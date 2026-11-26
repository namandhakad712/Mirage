#!/usr/bin/env node
// Build the Mirage Cloudflare Worker.
//
// 1. gen-data.mjs — refresh src/generated/data.ts from the shared repo data
//    files, so the snapshot in the bundle is always current.
// 2. tsc --project tsconfig.json — type-check src + test (noEmit).
// 3. tsc --project tsconfig.build.json — emit dist/ as multi-file ES2022.
//
// No bundler step is invented here: Cloudflare Workers accept multi-file ESM
// uploads and `wrangler deploy` bundles the emitted graph itself, so the
// honest build is plain tsc. Everything runs with zero runtime dependencies.
import { spawnSync } from "node:child_process";

const steps = [
  { cmd: process.execPath, args: ["scripts/gen-data.mjs"], label: "gen-data" },
  { cmd: "npx", args: ["tsc", "--project", "tsconfig.json"], label: "type-check (src + test)" },
  { cmd: "npx", args: ["tsc", "--project", "tsconfig.build.json"], label: "emit dist/" },
];

for (const step of steps) {
  console.log(`[build] ${step.label}`);
  const result = spawnSync(step.cmd, step.args, { stdio: "inherit", shell: process.platform === "win32" });
  if (result.status !== 0) {
    console.error(`[build] FAILED at: ${step.label}`);
    process.exit(result.status ?? 1);
  }
}
console.log("[build] done: dist/ ready for `wrangler deploy`");
