<!--
Short checklist mirroring the CONTRIBUTING gates. The deterministic gates
decide; this list is a reminder, not a substitute for `make check`.
Read docs/charter.md and docs/invariants.md first: contributions that add
hack-back, web poisoning or overclaiming are declined by charter.
-->

- [ ] Spec first: engine-observable changes include the spec change AND the
      regenerated golden vectors (`make vectors`, both files committed) — or
      N/A with a one-line justification.
- [ ] `make fmt-check vet build test vectors slop` — all green locally;
      CI runs exactly these gates.
- [ ] Worker touched: `make worker-build` and `make worker-test` green
      (they need network for `npm ci`) — or N/A.
- [ ] Renderer change: both render-parity suites pass on
      `spec/golden-vectors/renders.json` (Go `internal/decoy` and worker
      `render.ts`), and `spec/DECOY-CATALOG.md` §4 is updated to match.
- [ ] No secrets, tokens or credentials in the diff — connector secrets
      belong in environment variables named by `*_env` config keys (I11).
- [ ] Claims follow docs/claims-policy.md: every performance or detection
      claim links to a reproducible test.
- [ ] Invariants respected (I1–I15); an ADR in docs/adr/ accompanies any
      change that touches one.
- [ ] Commit subjects use feat:/fix:/spec:/docs:/build:; this PR is ready
      for squash-merge.
