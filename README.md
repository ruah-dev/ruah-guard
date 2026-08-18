# @ruah-dev/guard

A policy engine that sits between an agent and the world: block destructive
commands, catch secrets before they land in git, bound the blast radius.

Ships as a library, a CLI, and a drop-in Claude Code / generic hook.

## 30-second quickstart

```bash
npx @ruah-dev/guard init
npx @ruah-dev/guard check --cmd 'rm -rf /' --json
echo '{"tool":"Bash","command":"rm -rf /"}' | npx @ruah-dev/guard hook --stdin
```

Requires Node.js >= 18. **Zero runtime dependencies.** Peer: `@ruah-dev/schema`.

## JSON output

```bash
$ ruah-guard check --cmd 'rm -rf /' --json
{
  "schemaVersion": "1",
  "decision": "deny",
  "ruleId": "deny-rm-root",
  "reason": "Recursive delete targeting filesystem root or home",
  "matched": "rm -rf /",
  "severity": "critical"
}
```

Exit codes: `0` allow / clean scan, `1` deny / pending approval / findings /
user error, `2` internal error. `--json` keeps machines on stdout and humans
on stderr.

## Composition

```bash
ruah-guard check --cmd "$CMD" --json | jq -e '.decision == "allow"'
ruah-guard scan --json | jq '.findings[] | {file, detector, excerpt}'
```

Install the Claude Code hook:

```bash
ruah-guard hook claude-code
# paste the printed block into ~/.claude/settings.json
```

## What it does

- **Commands** — ordered `Policy` rules from `@ruah-dev/schema`. First match
  wins. Built-in defaults deny `rm -rf /` `~` `.`, `dd`, `mkfs`, DROP/TRUNCATE,
  force-push to main, `curl|bash`, `chmod 777`, `> /dev/sd*`, `git reset --hard`
  + `clean -fd`, `base64 -d | sh`. Wrappers (`sudo`, `command`, `bash -c`,
  `$HOME`, `;` / `&&` chains) are expanded before matching.
- **Secrets** — Stripe / Anthropic / AWS / GitHub / PEM / JWT / high-entropy.
  Excerpts are `sk_live_••••`, never the value. Allowlist:
  `{ "secrets": { "allow": ["EXAMPLE_KEY"] } }` in `.ruah/guard.json`.
- **Paths** — glob rules; `.git/**` writes and `*.pem` / `id_rsa*` denied.
- **Approvals** — `ask` / `approve` queues at `.ruah/approvals.json`.
- **Audit** — append-only `.ruah/guard-audit.jsonl`. `ruah-guard audit --last 50 --json`
  and `--stats`. Torn last lines are skipped.

Policy file: `.ruah/guard.json` (legacy `.ruah/policy.json` still loads).
`ruah-guard init` writes a starter copy of the default policy.

## Honest limits (not yet / not ever)

- **Not a shell interpreter.** `x=$(printf rm); $x -rf /` and
  `python -c 'os.system("rm -rf /")'` are documented-as-uncatchable. Guard is
  best-effort pattern defense and says so.
- No network sandbox, no containers, no LLM "intent detection".
- `ruah guard …` via the top-level CLI needs the ruah-cli router (W2). The
  standalone `ruah-guard` binary works today.

## License

[MIT](LICENSE)
