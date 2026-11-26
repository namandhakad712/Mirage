package enforce

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/mirage-shield/mirage/internal/model"
)

func mustPrefixes(t *testing.T, items ...string) []netip.Prefix {
	t.Helper()
	ps, err := model.ParsePrefixes(items)
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	return ps
}

func TestEvaluateNeverBannedDenies(t *testing.T) {
	// I15: private, CGNAT, loopback and owner ranges are never banned.
	// The owner range is 203.0.113.0/24; everything else public allows.
	owner := mustPrefixes(t, "203.0.113.0/24")
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 100}, owner)
	cases := []struct {
		name string
		ip   string
		want Outcome
	}{
		{"private v4", "10.1.2.3", OutcomeDeny},
		{"private v6 ula", "fd00::1", OutcomeDeny},
		{"cgnat", "100.64.0.7", OutcomeDeny},
		{"cgnat upper edge", "100.127.255.9", OutcomeDeny},
		{"loopback v4", "127.0.0.1", OutcomeDeny},
		{"loopback v6", "::1", OutcomeDeny},
		{"link-local", "169.254.1.1", OutcomeDeny},
		{"owner range", "203.0.113.99", OutcomeDeny},
		{"public v4 allows", "198.51.100.7", OutcomeAllow},
		{"public v6 allows", "2001:4860:4860::8888", OutcomeAllow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := g.Evaluate(c.ip, 1_000); got != c.want {
				t.Fatalf("Evaluate(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

func TestEvaluatePerMinuteBudgetBoundary(t *testing.T) {
	// Exactly MaxBansPerMinute bans are allowed; the next proposal in
	// the same window drops to observe (design section 5).
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 3, MaxConcurrentBans: 100}, nil)
	ttl := model.BanTTL
	for i := 1; i <= 3; i++ {
		at := int64(1_000 + i)
		ip := fmt.Sprintf("198.51.100.%d", 10+i)
		if got := g.Evaluate(ip, at); got != OutcomeAllow {
			t.Fatalf("evaluate #%d = %v, want allow", i, got)
		}
		g.RecordBan(ip, at, at+ttl)
	}
	if got := g.Evaluate("198.51.100.99", 2_000); got != OutcomeObserve {
		t.Fatalf("fourth ban in window = %v, want observe", got)
	}
}

func TestEvaluateWindowSlides(t *testing.T) {
	// A ban recorded exactly 60_000 ms ago is outside the trailing
	// window; one millisecond earlier it still counts.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 1, MaxConcurrentBans: 100}, nil)
	// Long TTL so only the window, not expiry, frees the budget.
	g.RecordBan("198.51.100.7", 0, 3_600_000)
	if got := g.Evaluate("198.51.100.8", 59_999); got != OutcomeObserve {
		t.Fatalf("inside window = %v, want observe", got)
	}
	if got := g.Evaluate("198.51.100.8", 60_000); got != OutcomeAllow {
		t.Fatalf("window edge = %v, want allow (ban exactly 60s old stopped counting)", got)
	}
}

func TestEvaluateConcurrentCap(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 100, MaxConcurrentBans: 2}, nil)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	g.RecordBan("198.51.100.8", 1_001, 61_000)
	if got := g.Evaluate("198.51.100.9", 1_002); got != OutcomeObserve {
		t.Fatalf("cap reached = %v, want observe", got)
	}
	// Expired bans free the cap even mid-window: only unexpired bans
	// are concurrent.
	if got := g.Evaluate("198.51.100.9", 61_000); got != OutcomeAllow {
		t.Fatalf("after expiry = %v, want allow", got)
	}
}

func TestEvaluateNeverBanBeatsBudgets(t *testing.T) {
	// Rule order matters: with every budget exhausted, a never-ban
	// address still answers Deny, not Observe.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 1, MaxConcurrentBans: 1}, nil)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	if got := g.Evaluate("10.0.0.1", 1_001); got != OutcomeDeny {
		t.Fatalf("never-ban with exhausted budgets = %v, want deny", got)
	}
	if got := g.Evaluate("198.51.100.8", 1_001); got != OutcomeObserve {
		t.Fatalf("public with exhausted budgets = %v, want observe", got)
	}
}

func TestEvaluateZeroBudgetFailsSafeToObserve(t *testing.T) {
	// A zero budget is a zero cap, not an unlimited one: nothing may be
	// banned until the owner configures real budgets (I9).
	g := NewGatekeeper(Budgets{}, nil)
	if got := g.Evaluate("198.51.100.7", 1_000); got != OutcomeObserve {
		t.Fatalf("zero budgets = %v, want observe", got)
	}
}

func TestEvaluateUnparseableIPFallsThroughToBudgets(t *testing.T) {
	// model.IsNeverBanned cannot match garbage, so evaluation proceeds
	// to the budgets instead of panicking or inventing a verdict.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 5, MaxConcurrentBans: 5}, nil)
	if got := g.Evaluate("not-an-ip", 1_000); got != OutcomeAllow {
		t.Fatalf("garbage ip = %v, want allow (budgets have headroom)", got)
	}
}

func TestRecordBanRedeliveryDoesNotDoubleCount(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 2, MaxConcurrentBans: 10}, nil)
	// The queue may redeliver RecordBan after an Apply retry; the same
	// applied ban (same address, same expiry) must count once.
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	if got := g.Evaluate("198.51.100.8", 1_500); got != OutcomeAllow {
		t.Fatalf("after redelivery = %v, want allow (redelivery not double-counted)", got)
	}
	// A renewal (same address, new expiry) is a new ban event.
	g.RecordBan("198.51.100.7", 1_600, 61_600)
	if got := g.Evaluate("198.51.100.9", 1_700); got != OutcomeObserve {
		t.Fatalf("after renewal = %v, want observe (two events, budget 2)", got)
	}
}

func TestRecordBanAlwaysCountsWhenCalled(t *testing.T) {
	// RecordBan is honest accounting: a ban applied at a connector is
	// recorded even if Evaluate would have said no. Over-counting fails
	// safe; the counters must never lag reality.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 1, MaxConcurrentBans: 1}, nil)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	// Never evaluated, still recorded: the next proposal observes.
	g.RecordBan("198.51.100.8", 1_100, 61_000)
	if got := g.Evaluate("198.51.100.9", 1_200); got != OutcomeObserve {
		t.Fatalf("after un-evaluated record = %v, want observe", got)
	}
}

func TestMaxSharePctExposesBudget(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxSharePct: 15}, nil)
	if got := g.MaxSharePct(); got != 15 {
		t.Fatalf("MaxSharePct() = %d, want 15", got)
	}
}

func TestIsBanned(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 10}, nil)
	// No record yet: never banned.
	if _, ok := g.IsBanned("198.51.100.7", 1_000); ok {
		t.Fatalf("unrecorded address reports banned")
	}
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	// Active ban: banned until its expiry.
	exp, ok := g.IsBanned("198.51.100.7", 60_999)
	if !ok || exp != 61_000 {
		t.Fatalf("active ban = (%d, %v), want (61000, true)", exp, ok)
	}
	// Expired exactly at nowMs: already inactive, like store.BanRecords.
	if _, ok := g.IsBanned("198.51.100.7", 61_000); ok {
		t.Fatalf("ban expired exactly at nowMs still reports banned")
	}
	// Another address is untouched.
	if _, ok := g.IsBanned("198.51.100.8", 1_000); ok {
		t.Fatalf("different address reports banned")
	}
}

func TestIsBannedLongestExpiryWins(t *testing.T) {
	// A re-ban inside the first TTL leaves two active records; the address
	// stays banned until the LONGER one lapses.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 10}, nil)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	g.RecordBan("198.51.100.7", 2_000, 121_000)
	exp, ok := g.IsBanned("198.51.100.7", 100_000)
	if !ok || exp != 121_000 {
		t.Fatalf("two active bans = (%d, %v), want (121000, true)", exp, ok)
	}
	// Only the longer one remains active.
	exp, ok = g.IsBanned("198.51.100.7", 121_000)
	if ok || exp != 0 {
		t.Fatalf("after both expire = (%d, %v), want (0, false)", exp, ok)
	}
}

func TestRevokeBanExpiresActiveOnly(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 10}, nil)
	g.RecordBan("198.51.100.7", 1_000, 61_000)
	g.RecordBan("198.51.100.8", 1_000, 61_000)
	// Revoking a never-banned address is a no-op, not an error (I5).
	g.RevokeBan("198.51.100.9", 5_000)
	if _, ok := g.IsBanned("198.51.100.9", 5_000); ok {
		t.Fatalf("revoked never-banned address reports banned")
	}
	// One address revoked, the other untouched.
	g.RevokeBan("198.51.100.7", 5_000)
	if _, ok := g.IsBanned("198.51.100.7", 5_000); ok {
		t.Fatalf("revoked address still banned")
	}
	if _, ok := g.IsBanned("198.51.100.8", 5_000); !ok {
		t.Fatalf("untouched address lost its ban")
	}
}

func TestRevokeBanIdempotentNeverExtends(t *testing.T) {
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 10}, nil)
	g.RecordBan("198.51.100.7", 1_000, 10_000)
	g.RevokeBan("198.51.100.7", 5_000)
	// A second revoke at a LATER time must not push the expiry forward:
	// the record stays expired at 5_000.
	g.RevokeBan("198.51.100.7", 7_000)
	if exp, ok := g.IsBanned("198.51.100.7", 6_000); ok {
		t.Fatalf("double revoke extended the ban to %d", exp)
	}
	// The freed concurrency cap proves the ban is truly gone: with
	// MaxConcurrentBans 1 a new proposal now allows.
	tight := NewGatekeeper(Budgets{MaxBansPerMinute: 10, MaxConcurrentBans: 1}, nil)
	tight.RecordBan("198.51.100.7", 1_000, 61_000)
	tight.RevokeBan("198.51.100.7", 2_000)
	if got := tight.Evaluate("198.51.100.8", 2_001); got != OutcomeAllow {
		t.Fatalf("after revoke, cap still occupied = %v, want allow", got)
	}
}

func TestGatekeeperConcurrentEvaluateAndRecord(t *testing.T) {
	// The gatekeeper sits on the hot enforcement path; Evaluate and
	// RecordBan arrive from multiple goroutines. Run under -race.
	g := NewGatekeeper(Budgets{MaxBansPerMinute: 10_000, MaxConcurrentBans: 10_000}, nil)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				g.Evaluate("198.51.100.7", int64(i))
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				g.RecordBan("198.51.100.8", int64(i), int64(i)+model.BanTTL)
			}
		}()
	}
	wg.Wait()
	// All recorded bans are long expired at t=10_000_000, so the storm
	// must leave a healthy gatekeeper behind.
	if got := g.Evaluate("198.51.100.9", 10_000_000); got != OutcomeAllow {
		t.Fatalf("post-race evaluate = %v, want allow", got)
	}
}
