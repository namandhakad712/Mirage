package service

import "time"

// DefaultDecideBudgetMs is the per-request decision budget every adapter is
// recommended to grant (spec/ADAPTER-PROTOCOL.md section 2: "Recommended:
// 5 ms. On overrun the engine returns the fail-open decision"). The service
// measures itself against it twice per Decide and returns the fail-open
// decision on overrun (I1).
const DefaultDecideBudgetMs = 5

// Options tunes Service construction. The zero value is production-shaped:
// the real wall clock and the recommended decision budget.
type Options struct {
	// Clock returns the wall clock in Unix milliseconds. Decide calls it a
	// bounded number of times (the decision start and the two deadline
	// checks), the background loops call it for timestamps, and nil means
	// time.Now().UnixMilli. Tests inject a deterministic clock — never a
	// sleeping real one — so every deadline behaviour is reproducible.
	Clock func() int64

	// DecideBudgetMs is the per-request decision budget Decide measures
	// its elapsed time against, twice: after the engine call and after
	// enforcement wiring. 0 means DefaultDecideBudgetMs; a negative value
	// is clamped to the default too — an unset option must not become a
	// zero deadline that fails every request open.
	DecideBudgetMs int64
}

// clockOrDefault resolves the Clock option.
func (o Options) clockOrDefault() func() int64 {
	if o.Clock == nil {
		return func() int64 { return time.Now().UnixMilli() }
	}
	return o.Clock
}

// budgetOrDefault resolves the DecideBudgetMs option.
func (o Options) budgetOrDefault() int64 {
	if o.DecideBudgetMs <= 0 {
		return DefaultDecideBudgetMs
	}
	return o.DecideBudgetMs
}
