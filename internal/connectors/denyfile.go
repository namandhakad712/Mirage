package connectors

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// denyFileHeader marks the file as managed so an operator eyeballing it
// knows to keep hands off; any manual edit is clobbered by the next
// rewrite.
const denyFileHeader = "# managed by mirage — do not edit\n"

// DenyFile is the local, zero-dependency enforcement connector: it
// maintains an nginx/Apache-compatible deny map that the web server
// includes in its configuration. The file is the provider — whatever is
// listed in it is blocked.
//
// Every rewrite is atomic: content goes to a temp file in the same
// directory, gets fsynced, then is renamed over the target. A crash
// mid-rewrite leaves the previous deny map intact instead of a
// truncated file the web server would refuse to load — a broken include
// would take the site down, which is the one thing Mirage must never
// cause (I1).
//
// The deny map has no native TTL: an entry blocks until removed, so the
// "expires" timestamp lives in a comment and Reconcile owns expiry.
// Apply does not check that timestamp (it has no clock by design); the
// service layer only queues unexpired bans and Reconcile prunes the
// rest.
type DenyFile struct {
	mu       sync.Mutex
	path     string
	snapshot map[string]Ban // desired state, keyed by normalized IP
}

// NewDenyFile manages the deny map at path. The file appears on the
// first Apply; nothing is written before that.
func NewDenyFile(path string) *DenyFile {
	return &DenyFile{path: path, snapshot: make(map[string]Ban)}
}

// Name identifies the connector in logs and dashboards.
func (d *DenyFile) Name() string { return "denyfile" }

// Apply records the ban and rewrites the file. Idempotent: applying the
// same address again replaces its entry — one line per address, always.
func (d *DenyFile) Apply(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("denyfile: apply: %w", err)
	}
	if err := checkCommentSafe(b.Reason); err != nil {
		return fmt.Errorf("denyfile: apply: %w", err)
	}
	b.IP = addr.String()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.snapshot[b.IP] = b
	if err := d.rewriteLocked(ctx); err != nil {
		return fmt.Errorf("denyfile: apply: %w", err)
	}
	return nil
}

// Revoke removes the ban from the file. Revoking a ban that is not in
// the snapshot is success and rewrites nothing.
func (d *DenyFile) Revoke(ctx context.Context, b Ban) error {
	addr, err := parseBanIP(b)
	if err != nil {
		return fmt.Errorf("denyfile: revoke: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.snapshot[addr.String()]; !ok {
		return nil
	}
	delete(d.snapshot, addr.String())
	if err := d.rewriteLocked(ctx); err != nil {
		return fmt.Errorf("denyfile: revoke: %w", err)
	}
	return nil
}

// Reconcile syncs the file with the desired state: entries that are
// expired or no longer wanted by the service are dropped (a missed or
// crashed Revoke heals here), and an entry whose ban was renewed adopts
// the fresher version so the deny line never lapses. It counts only
// removals as corrections.
func (d *DenyFile) Reconcile(ctx context.Context, active []Ban, nowMs int64) (int, error) {
	desired := make(map[string]Ban, len(active))
	for _, b := range active {
		if b.ExpiresAtMs <= nowMs {
			continue // expired: not enforceable
		}
		addr, err := parseBanIP(b)
		if err != nil {
			continue // not enforceable; the service layer logs it
		}
		desired[addr.String()] = b
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	changed := false
	for ip, cur := range d.snapshot {
		want, ok := desired[ip]
		switch {
		case !ok:
			// Missed revoke or expired TTL: stop enforcing.
			delete(d.snapshot, ip)
			removed++
			changed = true
		case want.ExpiresAtMs != cur.ExpiresAtMs || want.Reason != cur.Reason:
			// Renewed or re-reasoned ban: adopt the service's version
			// in place, without ever dropping the deny line.
			d.snapshot[ip] = want
			changed = true
		}
	}
	if !changed {
		return removed, nil
	}
	if err := d.rewriteLocked(ctx); err != nil {
		return 0, fmt.Errorf("denyfile: reconcile: %w", err)
	}
	return removed, nil
}

// HealthCheck proves the directory is writable by creating and removing
// a probe file — the exact operation Apply depends on.
func (d *DenyFile) HealthCheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(d.path), ".mirage-health-*")
	if err != nil {
		return fmt.Errorf("denyfile: health check: directory %s not writable: %w", filepath.Dir(d.path), err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// rewriteLocked serializes the snapshot into the deny map. Lines are
// sorted by address so the same state always produces a byte-identical
// file: operators can diff it, and idempotent rewrites do not churn.
func (d *DenyFile) rewriteLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ips := make([]string, 0, len(d.snapshot))
	for ip := range d.snapshot {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	var buf bytes.Buffer
	buf.WriteString(denyFileHeader)
	for _, ip := range ips {
		b := d.snapshot[ip]
		fmt.Fprintf(&buf, "deny %s;  # %s expires %s\n",
			ip, b.Reason, time.UnixMilli(b.ExpiresAtMs).UTC().Format(time.RFC3339))
	}
	if err := writeFileAtomic(d.path, buf.Bytes()); err != nil {
		return fmt.Errorf("write deny map: %w", err)
	}
	return nil
}

// checkCommentSafe rejects control characters in text that is written
// into the file as a comment: a newline would let crafted input forge
// additional directives (I7). Reason codes are plain printable ASCII,
// so this rejects nothing legitimate.
func checkCommentSafe(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("reason %q contains control characters", s)
		}
	}
	return nil
}

// writeFileAtomic replaces path's contents atomically: temp file in the
// same directory (same filesystem, so the rename cannot fall back to a
// copy), fsync, rename. Fsync-before-rename is what makes the swap
// crash-safe: after a crash the OS has either the old or the new file,
// never a half-written one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mirage-denyfile-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	abort := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		abort()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	// 0644 so the web server's workers can read the map, not just the
	// master that includes it.
	if err := tmp.Chmod(0o644); err != nil {
		abort()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		abort()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
