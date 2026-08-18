# @ruah-dev/guard

> **Can I trust the agent not to do damage — in *any* harness, with proof?**

One deterministic policy file. The same verdict in Claude Code, Codex, Cursor,
CI, and a local `check`. Backed by a bypass-attempt suite (quoting, `bash -c`,
`$HOME`, `;` / `&&` chains, `base64 | sh`) that a hand-rolled hook never has.

That is the edge over built-in permission modes: **portable and testable**, not
"it blocks `rm -rf`".

```bash
npm i -g @ruah-dev/guard          # also installs `ruah`
ruah guard hook claude-code       # paste into ~/.claude/settings.json
echo '{"tool":"Bash","command":"bash -c \"rm -rf ~\""}' \
  | ruah guard hook --stdin --json
```

Same policy, no harness:

```bash
ruah guard check --cmd 'bash -c "rm -rf ~"' --json
```

Requires Node.js >= 18. **Zero runtime dependencies** for the engine. Peer:
`@ruah-dev/schema`. `@ruah-dev/cli` is a *front-door* install dep so `ruah guard`
exists after `npm i -g @ruah-dev/guard`; the library does not import it.

## JSON output

```bash
$ ruah guard check --cmd 'bash -c "rm -rf ~"' --json
{
  "schemaVersion": "1",
  "decision": "deny",
  "ruleId": "deny-rm-root",
  "reason": "Recursive delete targeting filesystem root or home",
  "matched": "rm -rf ~",
  "severity": "critical"
}
```

Exit codes: `0` allow / clean scan, `1` deny / pending approval / findings /
user error, `2` internal error. `--json` keeps machines on stdout and humans
on stderr.

## Same file, every harness

`.ruah/guard.json` is a `Policy` from `@ruah-dev/schema`. `ruah guard init`
writes a starter. No file → built-in defaults.

| Harness | How |
|---------|-----|
| Claude Code | `ruah guard hook claude-code` → PreToolUse command |
| Codex / Cursor / anything | `ruah guard hook --stdin` (generic `{tool,command}` or PreToolUse JSON) |
| CI / scripts | `ruah guard check --cmd "$CMD" --json` |
| Pre-commit secrets | `ruah guard check --file staged.diff --json` |

```bash
ruah guard check --cmd "$CMD" --json | jq -e '.decision == "allow"'
ruah guard scan --json | jq '.findings[] | {file, detector, excerpt}'
```

## What the suite actually covers

- **Commands** — first matching `Policy` rule wins. Defaults deny recursive
  delete of `/` `~` `.`, `dd`, `mkfs`, DROP/TRUNCATE, force-push to main,
  `curl|bash`, `chmod 777`, `> /dev/sd*`, `git reset --hard` + `clean -fd`,
  `base64 -d | sh`. Wrappers are expanded before matching.
- **Secrets** — Stripe / Anthropic / AWS / GitHub / PEM / JWT / high-entropy.
  Excerpts are `sk_live_••••`. Allowlist: `{ "secrets": { "allow": ["EXAMPLE_KEY"] } }`.
- **Paths** — glob rules; `.git/**` writes and `*.pem` / `id_rsa*` denied.
- **Approvals** — `ask` / `approve` queue at `.ruah/approvals.json`.
- **Audit** — `.ruah/guard-audit.jsonl`. `ruah guard audit --last 50 --json`.

## Honest limits

- **Not a shell interpreter.** `x=$(printf rm); $x -rf /` and
  `python -c 'os.system("rm -rf /")'` are documented-as-uncatchable.
- No network sandbox, no containers, no LLM "intent detection".
- Full list of caught vs documented-uncatchable bypasses is the test suite
  (`test/normalize.test.ts`, `test/policy.test.ts`).

## License

[MIT](LICENSE)
