package connectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustApply(t *testing.T, d *DenyFile, b Ban) {
	t.Helper()
	if err := d.Apply(context.Background(), b); err != nil {
		t.Fatalf("apply %s: %v", b.IP, err)
	}
}

func iso(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func readDenyFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read deny file: %v", err)
	}
	return string(b)
}

func TestDenyFileApplyWritesExpectedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirage-deny.map")
	d := NewDenyFile(path)

	mustApply(t, d, Ban{IP: "203.0.113.7", Reason: "SIG-104", CreatedAtMs: 1_000, ExpiresAtMs: 61_000})
	mustApply(t, d, Ban{IP: "198.51.100.9", Reason: "SIG-099", CreatedAtMs: 2_000, ExpiresAtMs: 62_000})
	mustApply(t, d, Ban{IP: "2001:db8::42", Reason: "SIG-201", CreatedAtMs: 3_000, ExpiresAtMs: 63_000})

	// Sorted by address, header first, RFC3339 expiry in the comment.
	want := denyFileHeader +
		"deny 198.51.100.9;  # SIG-099 expires " + iso(62_000) + "\n" +
		"deny 2001:db8::42;  # SIG-201 expires " + iso(63_000) + "\n" +
		"deny 203.0.113.7;  # SIG-104 expires " + iso(61_000) + "\n"
	if got := readDenyFile(t, path); got != want {
		t.Fatalf("content =\n%s\nwant\n%s", got, want)
	}
	wantNoTempLeftovers(t, dir)
}

func TestDenyFileApplyIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirage-deny.map")
	d := NewDenyFile(path)

	// Same address applied twice — the second time with a fresh reason
	// and the long-form v6 spelling — leaves exactly one line, in the
	// latest state, with the normalized address.
	mustApply(t, d, Ban{IP: "2001:db8:0:0:0:0:0:1", Reason: "SIG-104", ExpiresAtMs: 61_000})
	mustApply(t, d, Ban{IP: "2001:db8::1", Reason: "SIG-201", ExpiresAtMs: 62_000})

	want := denyFileHeader + "deny 2001:db8::1;  # SIG-201 expires " + iso(62_000) + "\n"
	if got := readDenyFile(t, path); got != want {
		t.Fatalf("content =\n%s\nwant\n%s", got, want)
	}
	wantNoTempLeftovers(t, dir)
}

func TestDenyFileRevokeRemovesAndToleratesMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirage-deny.map")
	d := NewDenyFile(path)
	mustApply(t, d, Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 61_000})
	mustApply(t, d, Ban{IP: "198.51.100.9", Reason: "SIG-099", ExpiresAtMs: 61_000})

	if err := d.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	want := denyFileHeader + "deny 198.51.100.9;  # SIG-099 expires " + iso(61_000) + "\n"
	if got := readDenyFile(t, path); got != want {
		t.Fatalf("after revoke content =\n%s\nwant\n%s", got, want)
	}

	// Revoking a ban that is not in the file is success and must not
	// rewrite anything.
	before := readDenyFile(t, path)
	if err := d.Revoke(context.Background(), Ban{IP: "203.0.113.7"}); err != nil {
		t.Fatalf("revoke missing: %v", err)
	}
	if after := readDenyFile(t, path); after != before {
		t.Fatal("revoking a missing ban rewrote the file")
	}
	wantNoTempLeftovers(t, dir)
}

func TestDenyFileReconcileDropsExpiredAndAdoptsRenewals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirage-deny.map")
	d := NewDenyFile(path)
	mustApply(t, d, Ban{IP: "203.0.113.7", Reason: "SIG-104", ExpiresAtMs: 5_000})   // expired
	mustApply(t, d, Ban{IP: "198.51.100.9", Reason: "SIG-099", ExpiresAtMs: 61_000}) // kept
	mustApply(t, d, Ban{IP: "192.0.2.5", Reason: "SIG-101", ExpiresAtMs: 61_000})    // revoked

	// 198.51.100.9 is renewed to 90_000 by the service; the reconcile
	// must adopt that in place without ever dropping the deny line.
	active := []Ban{{IP: "198.51.100.9", Reason: "SIG-099", ExpiresAtMs: 90_000}}
	removed, err := d.Reconcile(context.Background(), active, 10_000)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (expired + revoked)", removed)
	}
	want := denyFileHeader + "deny 198.51.100.9;  # SIG-099 expires " + iso(90_000) + "\n"
	if got := readDenyFile(t, path); got != want {
		t.Fatalf("content =\n%s\nwant\n%s", got, want)
	}

	// Idempotent: nothing left to correct.
	if removed, err := d.Reconcile(context.Background(), active, 10_000); err != nil || removed != 0 {
		t.Fatalf("second reconcile = (%d, %v), want (0, nil)", removed, err)
	}
	wantNoTempLeftovers(t, dir)
}

func TestDenyFileHealthCheck(t *testing.T) {
	dir := t.TempDir()
	d := NewDenyFile(filepath.Join(dir, "deny.map"))
	if err := d.HealthCheck(context.Background()); err != nil {
		t.Fatalf("writable dir: %v", err)
	}

	bad := NewDenyFile(filepath.Join(dir, "no-such-subdir", "deny.map"))
	err := bad.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "denyfile: health check") {
		t.Fatalf("err = %v, want a denyfile health check failure", err)
	}
}

func TestDenyFileRejectsInjection(t *testing.T) {
	// I7: attacker-influenced fields must not be able to forge file
	// content. A newline in the IP or reason could inject directives.
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.map")
	d := NewDenyFile(path)

	injected := []Ban{
		{IP: "1.2.3.4\nallow all;", Reason: "SIG-104", ExpiresAtMs: 61_000},
		{IP: "203.0.113.7", Reason: "SIG-104\n# forged directive", ExpiresAtMs: 61_000},
		{IP: "203.0.113.7", Reason: "SIG-104\x00", ExpiresAtMs: 61_000},
		{IP: "10.0.0.0/8", Reason: "SIG-104", ExpiresAtMs: 61_000}, // CIDR is not a bare address
	}
	for i, b := range injected {
		if err := d.Apply(context.Background(), b); err == nil {
			t.Fatalf("case %d: apply accepted IP %q reason %q", i, b.IP, b.Reason)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deny file created despite rejected bans: %v", err)
	}
	wantNoTempLeftovers(t, dir)
}
