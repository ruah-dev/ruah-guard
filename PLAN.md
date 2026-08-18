# ruah-guard — Deep Build Plan

> **Question it answers.** Can I trust the agent not to do damage — in *any*
> harness, with proof?
>
> Read first: `../GROK_BUILD_PLAN.md` §T1 + §0.7, `../ENGINEERING_STANDARDS.md`.
> Package: `@ruah-dev/guard` · CLI: `ruah guard …` · Build slot: **T1 (first)**

## 1. Where the code is today (verified 2026-08-18)

123/123 tests pass; CLI runs after `npm run build`. Modules:
`policy.ts` (rule engine), `scanner.ts` (secrets), `audit.ts`, `approvals.ts`,
`cli.ts`, `errors.ts`, `index.ts`. README claims "not started" — false; rewrite it.

**Audit first (M0):** map every exported function of the four core modules against
this plan. The engine likely already covers much of §2 — the deliverable of M0 is a
gap table (exists / partial / missing per work item below), committed as
`docs/gap-analysis.md`, before any code is written.

## 2. Product shape

Deterministic policy engine between an agent and the world. Three consumption modes,
one core:

1. **Library** — `evaluate(policy, action) → Verdict` (pure, no I/O).
2. **CLI** — `ruah guard check|scan|audit|init|hook`.
3. **Hook adapters** — the wedge. Claude Code PreToolUse reads JSON on stdin,
   answers allow/deny JSON on stdout. One process spawn per decision → cold start
   matters (< 50ms; no schema peer import on the hot path if it costs startup time).

### Verdict contract (JSON, stable, versioned)

```json
{ "schemaVersion": "1", "decision": "deny" | "allow" | "ask",
  "ruleId": "no-recursive-force-rm", "reason": "human sentence",
  "matched": "rm -rf /", "severity": "critical" | "high" | "warn" }
```

Policy file: `.ruah/guard.json`, shape aligned with `Policy` from `@ruah-dev/schema`
(if the schema's `Policy` can't express something needed, change schema FIRST as a
separate release — big-plan rule). Built-in default policy ships in the package and
applies with zero config; user policy extends/overrides it by rule id.

## 3. Work plan

### M1 — Core hardening
- Command verdicts: normalize before matching — the same denial must fire for
  `rm -rf /`, `rm -fr /`, `command rm -rf /`, `bash -c "rm -rf /"`, `sudo rm -rf /`,
  newline/semicolon-chained forms, and `$HOME`-style env indirection of the target.
  Document (README + tests) what is out of scope: full shell interpretation is a
  non-goal; guard is best-effort pattern defense, and says so honestly.
- Default ruleset (each rule: id, pattern(s), severity, reason):
  recursive force rm of `/`, `~`, `.` at repo root; `dd` to block devices; `mkfs`;
  `DROP TABLE`/`TRUNCATE` without WHERE-guard; `git push --force` to
  main/master; `curl|bash` and `wget|sh`; `chmod -R 777`; `> /dev/sd*`;
  `git reset --hard` + `clean -fd` combo; writing to `.env` history.
- Secret scanner: AWS (`AKIA…`), `sk_live`/`sk-ant`/`ghp_`/`gho_`, private key
  blocks, JWTs, high-entropy strings ≥ threshold with allowlist escape hatch
  (`.ruah/guard.json → secrets.allow: [pattern]`). Output redacts values
  (standards §5): rule id + file:line + `sk_live_••••`.
- Every rule has hostile tests (standards §4.2): bypass attempts asserted as
  *caught* or *documented-as-uncatchable* — nothing in between.

### M2 — Hook adapters
- `ruah guard hook claude-code`: prints ready-to-paste `settings.json` hook config.
- `ruah guard hook --stdin`: reads one PreToolUse JSON event, writes the
  allow/deny JSON Claude Code expects, exit 0 always (a hook crash must fail-open
  or fail-closed **by configured choice**, default fail-closed for deny-severity
  rules; test both).
- Generic mode: `{"tool":"...","command":"..."}` in → Verdict out, for any harness.
- Latency test: 100 sequential stdin decisions complete < 5s wall.

### M3 — Audit + release
- Append-only `.ruah/guard-audit.jsonl` (one Verdict + timestamp per line;
  injected clock). `ruah guard audit --last N [--json]`, `--stats` (counts by
  rule/decision). Torn-final-line tolerance (standards §4.2).
- `ruah guard init`: writes starter policy with commented examples; refuses to
  overwrite without `--force`.
- README full rewrite (standards §7) + CHANGELOG + version bump + git tag.

## 4. Testing plan (beyond the existing 123)

- Contract tests on Verdict JSON (field presence, ordering, schemaVersion).
- Table-driven bypass suite per rule (the table IS the security documentation).
- Hook e2e: spawn built CLI, pipe a real Claude Code PreToolUse event fixture,
  assert response shape + exit code; malformed stdin JSON → configured
  fail-open/closed behavior, never a stack trace on stdout.
- Determinism: same event → byte-identical verdict.
- Negative space: scanner output contains no full secret value (grep the output
  for the fixture's actual secret; must be absent).

## 5. Acceptance criteria

- `echo '{"tool":"Bash","command":"rm -rf /"}' | ruah guard hook --stdin` → deny,
  correct ruleId, < 50ms after warm cache.
- `ruah guard check --cmd 'bash -c "rm -rf ~"'` → deny (indirection caught).
- Fixture diff with an AWS key + `sk_live` + PEM block → all three flagged,
  values redacted; allowlisted pattern not flagged.
- Works via `ruah guard …` (needs ruah-cli W2) and standalone `ruah-guard`.
- Zero runtime deps; `npm run verify` green; README honest.

## 6. Demo asset (required for done — save to `files/demos/guard/`)

Terminal GIF, ≤ 30s: agent session where `rm -rf` gets denied with rule id, then a
commit with an API key gets blocked with the redacted preview. Closing frame:
`npx @ruah-dev/guard init`.

## 6.5 Language note — hook latency trigger

The whole ecosystem is TypeScript/Node by decision (distribution via npx, zero-dep
stdlib, audience) — do not revisit per package. The ONE sanctioned exception path:
the guard **hook binary** is spawned per agent tool call, so cold start is product
surface. Budget: < 50ms per decision (M2 latency test). If dogfooding (big plan
§2.6) shows the Node hook measurably slowing sessions — measure with ruah-opt,
don't guess — the approved remedy is porting ONLY the hook binary to Rust (small
static binary, same stdin/stdout JSON contract, policy file parsed identically,
verified by running the existing hook e2e suite against both implementations).
The library, CLI, scanner, and audit stay TypeScript. Do not start this port
speculatively; it requires a recorded measurement first.

## 7. Don'ts

- No LLM/intent detection, no network, no container sandboxing (parked concerns).
- Don't claim shell-grammar-complete parsing — honest scope beats false safety.
- Don't log secret values anywhere, including debug output.
