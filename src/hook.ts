/**
 * Hook adapters: generic stdin/stdout and Claude Code PreToolUse.
 *
 * A hook process must not crash the agent session. `evaluateHookEvent`
 * never throws on bad input — it returns a fail-closed (deny) or
 * fail-open (allow) verdict depending on `failOpen`.
 */

import type { Policy } from "@ruah-dev/schema";
import type { CheckResult } from "./policy.js";
import { checkCommand, checkPath, DEFAULT_POLICY } from "./policy.js";

export const VERDICT_SCHEMA_VERSION = "1";

export type VerdictDecision = "deny" | "allow" | "ask";
export type VerdictSeverity = "critical" | "high" | "warn";

/** Stable, versioned verdict — the JSON contract for check + hook. */
export interface Verdict {
	schemaVersion: typeof VERDICT_SCHEMA_VERSION;
	decision: VerdictDecision;
	ruleId: string | null;
	reason: string;
	matched: string;
	severity: VerdictSeverity;
}

export interface HookEvent {
	tool: string;
	command?: string;
	path?: string;
	mode?: "read" | "write";
}

export interface HookResult {
	verdict: Verdict;
	/** Claude Code PreToolUse payload (nested, extra — harmless for generic consumers). */
	hookSpecificOutput: {
		hookEventName: "PreToolUse";
		permissionDecision: "deny" | "allow" | "ask";
		permissionDecisionReason: string;
	};
}

function toDecision(action: CheckResult["decision"]): VerdictDecision {
	if (action === "deny") return "deny";
	if (action === "approve" || action === "ask") return "ask";
	return "allow";
}

function toSeverity(level: CheckResult["riskLevel"]): VerdictSeverity {
	if (level === "critical") return "critical";
	if (level === "high") return "high";
	return "warn";
}

/** Project a CheckResult onto the versioned Verdict contract. */
export function toVerdict(result: CheckResult, matched: string): Verdict {
	return {
		schemaVersion: VERDICT_SCHEMA_VERSION,
		decision: toDecision(result.decision),
		ruleId: result.rule,
		reason: result.reason,
		matched,
		severity: toSeverity(result.riskLevel),
	};
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Accept both the generic `{tool, command}` shape and a Claude Code
 * PreToolUse event (`tool_name` + `tool_input`).
 */
export function parseHookEvent(value: unknown): HookEvent | null {
	if (!isRecord(value)) return null;
	const tool =
		(typeof value.tool === "string" && value.tool) ||
		(typeof value.tool_name === "string" && value.tool_name) ||
		"";
	if (tool === "") return null;

	const input = isRecord(value.tool_input) ? value.tool_input : value;
	const command =
		(typeof input.command === "string" && input.command) ||
		(typeof value.command === "string" && value.command) ||
		undefined;
	const path =
		(typeof input.file_path === "string" && input.file_path) ||
		(typeof input.path === "string" && input.path) ||
		(typeof value.path === "string" && value.path) ||
		undefined;

	return { tool, command, path, mode: "write" };
}

export function evaluateHookEvent(
	event: HookEvent,
	policy: Policy = DEFAULT_POLICY,
	granted: string[] = [],
): CheckResult {
	const name = event.tool.toLowerCase();
	if ((name === "bash" || name === "shell" || event.command) && event.command) {
		return checkCommand(event.command, policy, { grantedCommands: granted });
	}
	if (event.path) {
		const mode = event.mode === "read" ? "read" : "write";
		return checkPath(event.path, mode, policy);
	}
	return {
		decision: "allow",
		rule: null,
		pattern: null,
		riskLevel: "low",
		reason: `tool "${event.tool}" has no command or path to evaluate`,
	};
}

export function hookResult(result: CheckResult, matched: string): HookResult {
	const verdict = toVerdict(result, matched);
	return {
		verdict,
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: verdict.decision,
			permissionDecisionReason: verdict.reason,
		},
	};
}

export function failClosedVerdict(reason: string): HookResult {
	const result: CheckResult = {
		decision: "deny",
		rule: "hook-fail-closed",
		pattern: null,
		riskLevel: "high",
		reason,
	};
	return hookResult(result, "");
}

export function failOpenVerdict(reason: string): HookResult {
	const result: CheckResult = {
		decision: "allow",
		rule: "hook-fail-open",
		pattern: null,
		riskLevel: "low",
		reason,
	};
	return hookResult(result, "");
}

/** Ready-to-paste Claude Code settings.json hook block. */
export function claudeCodeHookConfig(
	command = "ruah guard hook --stdin",
): string {
	return `${JSON.stringify(
		{
			hooks: {
				PreToolUse: [
					{
						matcher: "*",
						hooks: [{ type: "command", command }],
					},
				],
			},
		},
		null,
		2,
	)}\n`;
}
