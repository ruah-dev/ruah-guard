# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in `@ruah-dev/guard`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **peter.whzm@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fix (optional)

You will receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Security Considerations

`@ruah-dev/guard` is itself a safety tool, so its own behavior is deliberately conservative:

### Decisions, Not Execution

`ruah-guard check` evaluates commands — it never executes them. A policy is data; nothing in a policy file can cause this package to run a command.

### File System

The package writes only under `.ruah/` in the consumer's current working directory (`policy.json`, `approvals.json`, `audit.jsonl`). The scanner reads files in the directory you point it at, skipping binaries and honoring excludes; it never modifies scanned files.

### Secrets Are Always Masked

Scan findings carry masked excerpts (`sk_l****90`), never raw secret values. The audit log records commands, rule ids, and counts — never scanned secret content. If you find a code path that emits a raw secret, treat it as a vulnerability and report it.

### Process Execution

Exactly one optional subprocess exists: `git diff --cached --name-only` for `scan --staged`, invoked with `execFileSync` and a fixed argument list (no shell interpolation). It degrades into a user error when git is absent.

### No Network Access

No network requests are made, ever.

### Regex Input Hardening

Policy patterns are compiled defensively: invalid regular expressions fall back to literal substring matching instead of throwing. Malformed JSON in `.ruah/` files produces exit code 1 with a clear message, not a crash.

### Dependencies

`@ruah-dev/guard` has **zero runtime dependencies**. `@ruah-dev/schema` is a type-only peer. The supply-chain surface is limited to dev dependencies (TypeScript, Biome, @types/node) which are not shipped in the published package.
