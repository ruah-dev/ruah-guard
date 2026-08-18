# AGENTS.md

## Project: @ruah-dev/guard

Policy engine for agent safety. Three faces: **guard** (allow/deny/approve decisions for commands and path boundaries), **scan** (secrets scanner with masked excerpts), **approve** (human-in-the-loop inbox) — plus an append-only audit log.

## Quality Gates

All changes must pass these checks before commit:

### Lint & format
1. `npm run format` (biome check --write)
2. `npm run lint` (biome check)

### Types & tests
1. `npm run build`
2. `npm run typecheck`
3. `npm test` (compiles TS tests via tsconfig.test.json, runs node:test)

## Coding Standards

- **Zero runtime dependencies.** Node built-ins only. Dev deps are fine.
- TypeScript `strict: true`; code must pass `tsc --noEmit`.
- Tests use the built-in `node:test` runner — no test frameworks.
- Tests must use temp dirs (`fs.mkdtemp`) — never write into the package folder or a real `.ruah/`.
- Conventional commits (feat:, fix:, docs:, etc.).
- No hardcoded secrets — and never write complete secret-shaped literals even in fixtures; assemble fake values at runtime (see test/scanner.test.ts).

## Guard-Specific Rules

- **Schema types are canonical.** `Policy`, `PolicyRule`, `PolicyAction`, `RiskLevel`, `LockMode` come from `@ruah-dev/schema` (type-only imports). Never redefine them locally.
- **Never emit raw secrets.** Every finding excerpt must go through `maskSecret`. The audit log stores commands and rule ids, never scanned secret values.
- **Config root is `.ruah/` under the consumer's CWD.** Never read or write state anywhere else, and never inside this package folder.
- **Fail safe, not silent.** Audit-log write failures warn on stderr but never block the command; malformed audit lines are skipped on read.
- **The CLI contract is fixed.** `--help`/`-h`/`--version` exit 0; every command supports `--json` (pure JSON on stdout, logs on stderr); exit codes 0 success/allow, 1 user error/blocked/findings, 2 internal error.
- **Standalone first.** Composing with siblings (e.g. git for `--staged`) must degrade gracefully into a `UserError`, never a crash.
