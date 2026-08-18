# ruah-guard M0 gap analysis (2026-08-18)

Audited against `PLAN.md` and `GROK_BUILD_PLAN.md` T1 after reading
`policy.ts`, `scanner.ts`, `audit.ts`, `approvals.ts`, `cli.ts`, and the
existing 123-test suite. **Extend, do not rewrite.**

## Module map

| Module | Role | Verdict |
|---|---|---|
| `policy.ts` | load / checkCommand / checkPath / DEFAULT_POLICY / init | **partial** — engine works; wrappers and a few default rules missing |
| `scanner.ts` | secrets + entropy + gitignore + staged | **exists** — allowlist hatch missing |
| `audit.ts` | append-only jsonl | **partial** — no `--stats`, no injected clock, filename is `audit.jsonl` |
| `approvals.ts` | request / grant / deny | **exists** — keep |
| `cli.ts` | thin shell | **partial** — no `hook`, no `--cmd`/`--file`/`--last` aliases |
| `errors.ts` / `index.ts` | standard | **exists** |

## Work item status

| Item | Status | Notes |
|---|---|---|
| Policy load, first-match, defaultAction | exists | |
| Default deny: `rm -rf /` `~`, `dd`, `mkfs`, DROP TABLE, force-push main, curl\|bash, chmod 777 | exists | Covered by table tests |
| `sudo` / `command` / `bash -c` / `$HOME` / `;` chains | **partial** | `sudo rm -rf /` already denied (no `^` on regex). `bash -c`, `$HOME`, `;` chains, `rm -rf .` are **missing** |
| `> /dev/sd*`, `git reset --hard` + `clean -fd` | **missing** | |
| TRUNCATE as deny | **partial** | currently `approve` via `approve-destructive-sql` |
| Secret detectors (AWS, sk_live, sk-ant, ghp/gho, PEM, JWT, entropy) | exists | |
| `secrets.allow` escape hatch | **missing** | extra field on policy — not promoted to schema |
| Redacted excerpts | exists | will switch preview to `sk_live_••••` per standards |
| Hook `claude-code` print | **missing** | |
| Hook `--stdin` (generic + PreToolUse) | **missing** | |
| Fail-open / fail-closed on bad stdin | **missing** | default fail-closed |
| `init` | exists | writes `policy.json`; plan wants `guard.json` — **prefer plan**, keep `policy.json` as fallback load |
| Audit log | exists | `audit.jsonl`; plan wants `guard-audit.jsonl` — **prefer plan**, read both |
| `audit --last` / `--stats` | **partial** | `--tail` exists; add `--last` alias + `--stats` |
| Torn last line | exists | malformed lines skipped |
| README | **stale** | claims "empty scaffold" — P1 |
| Verdict `schemaVersion` | **missing** | add without removing `rule` / `riskLevel` |
| `ask` synonym of `approve` | **missing** | schema 0.1.0 now allows `ask` |
| `check --cmd` / `check --file` | **missing** | aliases |

## Don'ts honored

- No LLM intent detection, no network sandbox, no container isolation.
- Full shell interpretation is out of scope; documented uncatchable bypasses
  go in README + a test that records them as such (base64-decode-to-shell
  without a pipe heuristic is the main one we **do** catch via a new rule).
