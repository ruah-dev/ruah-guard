/**
 * Append-only audit log at `.ruah/audit.jsonl` (one JSON object per line).
 * Every check / scan / approval action is recorded with timestamp and actor.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { RUAH_DIR } from "./policy.js";

/** Audit log file name inside the config root. */
export const AUDIT_FILE = "audit.jsonl";

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

/** Append one entry to `.ruah/audit.jsonl` under `root`. Returns the full entry. */
export function appendAudit(
	root: string,
	entry: {
		action: string;
		decision?: string;
		actor?: string;
		details?: Record<string, unknown>;
	},
): AuditEntry {
	const dir = join(root, RUAH_DIR);
	mkdirSync(dir, { recursive: true });
	const full: AuditEntry = {
		ts: new Date().toISOString(),
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
export function readAudit(root: string, tail?: number): AuditEntry[] {
	const file = join(root, RUAH_DIR, AUDIT_FILE);
	if (!existsSync(file)) return [];
	const entries: AuditEntry[] = [];
	for (const line of readFileSync(file, "utf8").split("\n")) {
		if (line.trim() === "") continue;
		try {
			entries.push(JSON.parse(line) as AuditEntry);
		} catch {
			// Skip malformed lines — the log must never block a command.
		}
	}
	if (tail !== undefined && tail >= 0 && entries.length > tail) {
		return entries.slice(entries.length - tail);
	}
	return entries;
}
