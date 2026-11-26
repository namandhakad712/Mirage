package enforce

import "testing"

func TestKillSwitchZeroValueIsDisengaged(t *testing.T) {
	// The zero value must be usable without a constructor: it is
	// embedded in larger structs all over the service layer.
	var k KillSwitch
	if active, reason, at := k.Engaged(); active || reason != "" || at != 0 {
		t.Fatalf("zero value = (%v, %q, %d), want disengaged", active, reason, at)
	}
}

func TestKillSwitchEngageDisengage(t *testing.T) {
	var k KillSwitch
	k.Engage("false-positive storm", 42_000)
	active, reason, at := k.Engaged()
	if !active || reason != "false-positive storm" || at != 42_000 {
		t.Fatalf("after engage = (%v, %q, %d), want (true, %q, %d)", active, reason, at, "false-positive storm", int64(42_000))
	}
	k.Disengage()
	if active, reason, at := k.Engaged(); active || reason != "" || at != 0 {
		t.Fatalf("after disengage = (%v, %q, %d), want cleared", active, reason, at)
	}
}

func TestKillSwitchReEngageKeepsTripTime(t *testing.T) {
	// engagedAtMs records when enforcement actually stopped; it must
	// not move on re-engagement. The reason is refreshed so the
	// dashboard always shows the latest diagnosis.
	var k KillSwitch
	k.Engage("budget exceeded", 1_000)
	k.Engage("owner request", 5_000)
	active, reason, at := k.Engaged()
	if !active || reason != "owner request" || at != 1_000 {
		t.Fatalf("re-engage = (%v, %q, %d), want (true, latest reason, original trip time)", active, reason, at)
	}
}
