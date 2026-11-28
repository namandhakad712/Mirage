# @mirage-shield/mirage-worker

The Cloudflare Worker port of the Mirage decision engine: the SIGNALS
v1.1.0 scoring, the verdict ladder and the decoy catalog, in-process at
the edge with zero runtime dependencies. The Go core and this worker
produce identical verdicts on the shared golden vectors — CI fails on
any divergence.

- Guide + deploy walkthrough: <https://namandhakad712.github.io/Mirage/deploy/cloudflare-worker.html>
- Signal spec: <https://namandhakad712.github.io/Mirage/spec/SIGNALS.html>
- Repository: <https://github.com/namandhakad712/Mirage>

License: Apache-2.0 (the Go core is AGPL-3.0 — see the repository
`LICENSE` files; this port is a separate, permissively licensed
implementation of the same spec).

## Work on it

```sh
npm ci
npm test      # vitest
npm run build # typecheck + emits dist/
```

Publishing is manual and gated: `npm publish` runs `prepublishOnly`
(test + build) first, and parity with the Go core is enforced in CI,
not by trust.
