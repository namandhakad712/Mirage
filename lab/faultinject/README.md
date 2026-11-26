# Mirage fault-injection lab (`lab/faultinject`)

This lab proves Mirage's fail-open invariants (`docs/invariants.md`) hold
when everything around the decision path is broken. Each scenario builds a
real Mirage stack — real detection rules loaded from `data/` and the canon
decoy catalog at `spec/decoy-catalog/catalog.yaml`, the real engine, the
real event queue, a real gatekeeper, the real dashboard, and a protect-mode
site config loaded through the real `config.Load` from a YAML fixture — and
then injects exactly one fault family. The assertions are about system
behavior (exact verdicts, actions, records, bounded timings), never just
"it did not crash".

The same scenario registry runs two ways: under `go test`
(`scenarios_test.go`) and as a terminal program (`main.go`), through the
narrow `TestingT` interface so no test machinery ships in the CLI build.

## The fault matrix

| Name | Fault injected | Invariants asserted | Expected outcome |
| --- | --- | --- | --- |
| store-down | Every `store.Store` method fails | I1, I3, I10 | `Decide` still answers the exact engine ladder for the canon `203.0.113.7` session; `ServeDecoy` still renders; `/api/events` answers a well-formed JSON 500; `/healthz` stays 200; `Stop` returns nil within the bound. |
| queue-flood | Queue at minimum capacity (100) with the drainer never started; more decisions than capacity | I3, I10 | Every decision completes within the bound; overflow is counted in `Queue.Dropped()`; the decision made over a full queue is still exactly right. |
| connector-dead | A connector whose `Apply` always errors | I1, I5, I10 | The ban-grade ladder still ends in action `ban`; the gatekeeper and the store hold the local ban; `Apply` attempted exactly once; `Decide` returned promptly. |
| connector-hang | A connector whose `Apply` blocks until the scenario's cleanup releases it | I1, I3, I5 | The ban rung returns promptly while the provider is provably still wedged; the ban is enforced locally; the wedge is released and waited on, no goroutine leaks. |
| budget-exhausted | Gatekeeper budgets `MaxBansPerMinute: 1` with two different ban-grade attackers | I5, I9, I10 | The first attacker's ban lands; the second's ban degrades to `pass` (OutcomeObserve through the service) while all six verdicts are still recorded as events. |
| never-ban | A ban-grade replay from `10.0.0.5`, inside `owner_ips: 10.0.0.0/8` | I6, I15 | Owner ranges are never scored: every rung answers observe/pass; no gatekeeper ban and no ban record exist. |
| deadline-overrun | A scripted decision clock that jumps past `DefaultDecideBudgetMs` between the start and the deadline check | I1, I3 | Even a fully armed ban-grade request answers with exactly `model.FailOpen()` (reason `SIG-000`, action `pass`); no event, no ban, no record is minted. |
| kill-switch | The site fixture boots with `enforcement.kill_switch: true`; then a live flip on an armed service | I9, I10 | Under the switch, verdicts record (I10) but every enforcement action passes and nothing is minted; flipping the switch live stops an existing ban's renewal within one decision. |
| dashboard-storm | 50 concurrent workers mixing valid/invalid tokens across all endpoints over the broken store of store-down | I1, I7, I11 | Every response is well-formed JSON with the JSON content type; everything answers within the bound; no handler panic; the dashboard token never appears in any response body. |

## Running

From the repository root:

```sh
go run ./lab/faultinject          # run the whole matrix, print the table
go run ./lab/faultinject -list    # print the matrix (names, invariants, descriptions)
go run ./lab/faultinject -only store-down,queue-flood -v
go test ./lab/faultinject/        # the same scenarios as subtests
go test -race ./lab/faultinject/  # the lab is a concurrency suite; always race it too
```

The program exits 0 only when every selected scenario passed; on failure it
names the failing scenarios on stderr. `-only` accepts a comma-separated
list and repeats; an unknown name is a usage error that lists the valid
names.

The lab runs from a source checkout: it loads the repo's real `data/` files
and the canon catalog, resolved relative to its own source location.

## Adding a scenario

1. Write `runXyz(t TestingT)` in `scenarios.go`: build your own stack with
   `newStack` (pick or add a YAML site fixture — configs must go through
   the real `config.Load`), inject ONE fault family, and assert the
   system's behavior, not survival. Cite the invariants you prove in the
   comments, the way the rest of the repo does.
2. Register it in `registry` with a kebab-case name, a one-line
   description and its invariant citations.
3. Add the row to the matrix table above — `TestRegistry` fails CI if the
   README does not mention every registered scenario name, or a citation
   has no heading in `docs/invariants.md`.
4. Synchronization rules: bounded waits via channels plus `time.After`
   (the bound is the assertion — document why it is generous); no sleeps
   for coordination; clean up every goroutine you spawn (WaitGroup), even
   on the `Fatalf` bail-out path — deferred cleanups run as the sentinel
   panic unwinds.

## Scope — what this lab does not cover

- **Network partitions to the origin.** The lab exercises Mirage Core
  in-process; the adapter's own forwarding path (origin unreachable) is the
  adapter conformance suite's territory, not the lab's.
- **Kernel-level faults** (disk I/O errors beneath SQLite, OOM kills,
  CPU starvation, SIGKILL mid-decision). The broken store simulates the
  observable contract of a wedged disk, not the disk itself.
- **Real provider outages.** Connector faults are in-process fakes
  (dead, hung); a real CrowdSec/Cloudflare outage adds DNS failures,
  TLS timeouts and 429 storms, which the connector retry tests cover
  separately.
- **Process kills / restarts.** Crash-restart behavior (queue loss,
  gatekeeper budget re-arming, SQLite WAL recovery) belongs to the store
  and service suites, not this lab.

What the lab does cover is the fail-open contract of
`spec/ADAPTER-PROTOCOL.md` section 5: with everything around the decision
path broken, decisions stay correct or degrade to the reserved fail-open
decision — and traffic always passes.
