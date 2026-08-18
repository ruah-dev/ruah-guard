/**
 * Append-only audit log at `.ruah/audit.jsonl` (one JSON object per line).
 * Every check / scan / approval action is recorded with timestamp and actor.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { RUAH_DIR } from "./policy.js";

/** Audit log file name inside the config root (6-pool name). */
export const AUDIT_FILE = "guard-audit.jsonl";

/** Legacy filename still read as a fallback. */
export const LEGACY_AUDIT_FILE = "audit.jsonl";

/** One audit log entry. */
export interface AuditEntry {
	/** ISO-8601 timestamp. */
	ts: string;
	/** Who acted — RUAH_ACTOR env var or the OS username. */
	actor: string;
	/** What happened, e.g. "check.command", "scan", "approve.grant". */
	action: string;
	/** Outcome, e.g. "allow", "deny", "pass", "fail", "granted". */
	decision?: string;
	/** Free-form structured context. */
	details?: Record<string, unknown>;
}

/** Resolve the acting identity: RUAH_ACTOR env var, else OS username. */
export function resolveActor(): string {
	const fromEnv = process.env.RUAH_ACTOR;
	if (fromEnv && fromEnv.trim() !== "") return fromEnv.trim();
	try {
		return userInfo().username;
	} catch {
		return "unknown";
	}
}

export interface AppendAuditOptions {
	/** Injected clock (ms since epoch). Tests freeze time with this. */
	now?: () => number;
}

/** Append one entry to `.ruah/guard-audit.jsonl` under `root`. Returns the full entry. */
export function appendAudit(
	root: string,
	entry: {
		action: string;
		decision?: string;
		actor?: string;
		details?: Record<string, unknown>;
	},
	options: AppendAuditOptions = {},
): AuditEntry {
	const dir = join(root, RUAH_DIR);
	mkdirSync(dir, { recursive: true });
	const ts = new Date(options.now ? options.now() : Date.now()).toISOString();
	const full: AuditEntry = {
		ts,
		actor: entry.actor ?? resolveActor(),
		action: entry.action,
		...(entry.decision !== undefined ? { decision: entry.decision } : {}),
		...(entry.details !== undefined ? { details: entry.details } : {}),
	};
	appendFileSync(join(dir, AUDIT_FILE), `${JSON.stringify(full)}\n`, "utf8");
	return full;
}

/**
 * Read the audit log under `root`. With `tail`, only the last n entries are
 * returned. Malformed lines are skipped, never thrown.
 */
function parseAuditFile(file: string): AuditEntry[] {
	if (!existsSync(file)) return [];
	const entries: AuditEntry[] = [];
	for (const line of readFileSync(file, "utf8").split("\n")) {
		if (line.trim() === "") continue;
		try {
			entries.push(JSON.parse(line) as AuditEntry);
		} catch {
			// Skip malformed / torn lines — the log must never block a command.
		}
	}
	return entries;
}

/**
 * Read the audit log under `root`. Prefers `guard-audit.jsonl`, falls back
 * to legacy `audit.jsonl`. With `tail`, only the last n entries are
 * returned. Malformed or torn last lines are skipped, never thrown.
 */
export function readAudit(root: string, tail?: number): AuditEntry[] {
	const preferred = join(root, RUAH_DIR, AUDIT_FILE);
	const legacy = join(root, RUAH_DIR, LEGACY_AUDIT_FILE);
	const entries = existsSync(preferred)
		? parseAuditFile(preferred)
		: parseAuditFile(legacy);
	if (tail !== undefined && tail >= 0 && entries.length > tail) {
		return entries.slice(entries.length - tail);
	}
	return entries;
}

/** Counts by decision and by rule id (from details.rule when present). */
export interface AuditStats {
	total: number;
	byDecision: Record<string, number>;
	byRule: Record<string, number>;
	byAction: Record<string, number>;
}

export function auditStats(entries: AuditEntry[]): AuditStats {
	const byDecision: Record<string, number> = {};
	const byRule: Record<string, number> = {};
	const byAction: Record<string, number> = {};
	for (const entry of entries) {
		byAction[entry.action] = (byAction[entry.action] ?? 0) + 1;
		if (entry.decision) {
			byDecision[entry.decision] = (byDecision[entry.decision] ?? 0) + 1;
		}
		const rule = entry.details?.rule;
		if (typeof rule === "string" && rule !== "") {
			byRule[rule] = (byRule[rule] ?? 0) + 1;
		}
	}
	return { total: entries.length, byDecision, byRule, byAction };
}
