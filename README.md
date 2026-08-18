# Ruah Guard

> **Status:** empty scaffold — not started
> **Phase:** 2 — Trust Layer
> **Priority:** High — required for enterprise adoption
> **Package (planned):** `@ruah-dev/guard`
> **CLI (planned):** `ruah-guard`

## What it is

Policy engine for agent safety. Answers the enterprise question: "Can I trust agents in my codebase?"

## Core capabilities

- Permissioning and command safety
- Prompt/tool risk scoring
- Data boundary enforcement
- Approval workflows (human-in-the-loop)
- File-system boundaries beyond claims
- Secrets detection
- Audit logs of every agent action
- Rollback support

## Example policies

- Agent can read repo but cannot merge to main
- Billing tool is read-only
- Shell execution only in sandbox
- Human approval required for: destructive DB actions, infra changes, external sends

## Integrations

- **`ruah-exec`** — enforces sandbox / permission boundaries on every typed call
- **`ruah-orch`** — merge gates, claim enforcement
- **`ruah-obs`** — audit trail export
- **`ruah-gate`** — runtime policy for exposed tool surfaces

## Next step for agents

Read `/SCAFFOLDING_PLAN.md` at the repo root before writing any code here.
