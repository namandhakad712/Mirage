package enforce

import "sync"

// KillSwitch is the global enforcement off-switch (I9). While it is
// engaged, the service layer drops every enforcement decision to
// observe: no connector call is made at all. It is deliberately dumb —
// a boolean, a reason and a timestamp — so it keeps working when the
// store, the connector queue and the dashboard are all on fire, and so
// exercising it needs no mocks.
//
// The zero value is a disengaged switch, ready to embed.
type KillSwitch struct {
	mu          sync.Mutex
	engaged     bool
	reason      string
	engagedAtMs int64
}

// Engage trips the switch. The first engagement wins for engagedAtMs:
// that timestamp answers "when did enforcement stop", which must not
// move on re-engagement. The reason is refreshed on every call so it
// always carries the latest diagnosis.
func (k *KillSwitch) Engage(reason string, atMs int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.engaged {
		k.reason = reason
		return
	}
	k.engaged = true
	k.reason = reason
	k.engagedAtMs = atMs
}

// Disengage releases the switch and forgets the reason — a stale reason
// on a live switch would be a lie on the dashboard.
func (k *KillSwitch) Disengage() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.engaged = false
	k.reason = ""
	k.engagedAtMs = 0
}

// Engaged reports whether enforcement is off, why, and since when
// (unix milliseconds; 0 when disengaged).
func (k *KillSwitch) Engaged() (active bool, reason string, engagedAtMs int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.engaged, k.reason, k.engagedAtMs
}
