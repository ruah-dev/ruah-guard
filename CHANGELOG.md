# Changelog

All notable changes to `@ruah-dev/guard` are documented here.

## 0.1.0 — 2026-06-12

Initial release.

- Policy engine over the canonical `Policy` type from `@ruah-dev/schema`: ordered rules (`command` / `path` / `secret`), first match wins, `defaultAction` fallback
- Built-in default policy: denies `rm -rf` on `/` or `~`, `dd`, `mkfs`, `DROP TABLE`, force-push to main/master, `curl | bash`, `chmod 777`; requires approval for `git push`, `npm publish`, `docker push`, `terraform apply|destroy`, destructive SQL, and anything matching `deploy`
- `ruah-guard check --command '<cmd>'` and `--path <p> --mode read|write` → `{ decision, rule, riskLevel, reason }`
- Secrets scanner `ruah-guard scan [dir]`: Stripe / Anthropic / AWS / GitHub keys, private key blocks, password assignments, bearer tokens, JWTs, `.env` files with real values, Shannon-entropy fallback — masked excerpts, `file:line:column`, `.gitignore`-aware, `--staged`, `--fail-on <level>` (exit 1 on findings at or above it)
- Approval inbox: `request`, `approve list|grant|deny`, persisted at `.ruah/approvals.json`; granted commands flip `approve` decisions to `allow` on exact match
- Append-only audit log at `.ruah/audit.jsonl` (`ruah-guard audit --tail n`); actor from `RUAH_ACTOR` or the OS user
- `ruah-guard init` writes a starter `.ruah/policy.json`
- Library API: `checkCommand`, `checkPath`, `scanText`, `scanDir`, `scanFiles`, `requestApproval`, `grantApproval`, `denyApproval`, `appendAudit`, `readAudit`
- Zero runtime dependencies; every command supports `--json`
