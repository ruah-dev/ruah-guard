# Contributing to @ruah-dev/guard

Thanks for your interest in contributing! `@ruah-dev/guard` is the trust layer of the ruah ecosystem — agents and CI pipelines rely on its decisions, so changes are held to a high bar.

## Getting Started

```bash
# Clone the repo (plus the schema sibling for types)
git clone https://github.com/ruah-dev/ruah-guard.git
git clone https://github.com/ruah-dev/ruah-schema.git
cd ruah-schema && npm install && npm run build && cd ../ruah-guard

# Install dev dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Typecheck
npm run typecheck

# Lint
npm run lint
```

## Project Structure

```
src/
  index.ts        Public API surface
  policy.ts       Policy load/validate + checkCommand/checkPath + DEFAULT_POLICY
  scanner.ts      Secrets scanner (detectors, entropy, dir walking, masking)
  approvals.ts    Approval queue (.ruah/approvals.json)
  audit.ts        Append-only audit log (.ruah/audit.jsonl)
  errors.ts       UserError (exit code 1)
  version.ts      Package version lookup
  cli.ts          CLI (init / check / scan / request / approve / audit)
bin/
  ruah-guard.js   Thin ESM wrapper importing dist/cli.js
test/
  *.test.ts       Tests (node:test, compiled via tsconfig.test.json)
```

## Development Guidelines

### Safety Rules (most important)

- **Never emit raw secrets.** All excerpts go through `maskSecret`.
- **Never execute checked commands.** `check` is evaluation only.
- **Never write outside `.ruah/`** in the consumer's CWD.
- New default-policy rules need tests proving both the deny/approve match **and** that everyday commands stay allowed (false-positive guard).

### Canonical Types

`Policy`, `PolicyRule`, `PolicyAction`, `RiskLevel`, and `LockMode` are imported (type-only) from `@ruah-dev/schema`. Do not redefine them.

### Zero Runtime Dependencies

This is a hard constraint. The package ships with zero `dependencies` in package.json. If you need functionality that typically comes from a package, implement it with Node.js built-ins (see the glob matcher in `src/policy.ts`).

### TypeScript Strict Mode

The codebase uses `strict: true`. All code must pass `tsc --noEmit` with no errors.

### Testing

Tests use the Node.js built-in test runner (`node:test`). No test frameworks.

```bash
# Run all tests
npm test

# Run a single test file
npx tsc -p tsconfig.test.json && node --test dist-test/test/policy.test.js
```

Rules for tests:

- Use temp directories (`fs.mkdtemp`) — never a real `.ruah/` or the package folder.
- Secret fixtures must be **obviously fake** and assembled at runtime (string joins) so no complete secret-shaped literal lands in the repo.

### Linting & Formatting

We use [Biome](https://biomejs.dev/):

```bash
npm run lint     # check
npm run format   # auto-fix
```

### Commit Convention

```
type(scope): description
```

Types: `feat`, `fix`, `docs`, `refactor`, `style`, `test`, `chore`

Examples:
- `feat(scanner): detect slack webhook urls`
- `fix(policy): anchor force-push rule to the same shell segment`

### Branch Strategy

Trunk-based development on `main`:

1. Fork the repo
2. Create a feature branch from `main`
3. Make your changes
4. Ensure all checks pass: `npm run build && npm run typecheck && npm run lint && npm test`
5. Open a PR against `main`

## Bug Reports

Open an issue with:
- package version (`ruah-guard --version`)
- Node.js version (`node --version`)
- OS
- Steps to reproduce
- Expected vs actual behavior

For false positives/negatives in the scanner or default policy, include the (sanitized!) input that misbehaved.

## Running the CLI Locally

```bash
npm run build
node bin/ruah-guard.js --help
node bin/ruah-guard.js check --command 'rm -rf /' --json
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
