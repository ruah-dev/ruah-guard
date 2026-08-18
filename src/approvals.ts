/**
 * Human-in-the-loop approval queue, persisted at `.ruah/approvals.json`.
 *
 * Lifecycle: `requestApproval` adds a pending entry → a human runs
 * `ruah-guard approve grant <id>` (or `deny`) → granted commands flip
 * "approve" decisions to "allow" on exact command match (see policy.ts).
 */

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolveActor } from "./audit.js";
import { UserError } from "./errors.js";
import { RUAH_DIR } from "./policy.js";

/** Approvals file name inside the config root. */
export const APPROVALS_FILE = "approvals.json";

/** State of an approval request. */
export type ApprovalStatus = "pending" | "granted" | "denied";

/** One queued approval request. */
export interface ApprovalRequest {
	/** Short hex id, e.g. "1a2b3c4d". */
	id: string;
	/** The exact command awaiting approval. */
	command: string;
	/** Why the command is needed. */
	reason: string;
	status: ApprovalStatus;
	/** ISO-8601 timestamp of the request. */
	requestedAt: string;
	requestedBy: string;
	/** ISO-8601 timestamp of the decision, null while pending. */
	decidedAt: string | null;
	decidedBy: string | null;
}

function approvalsPath(root: string): string {
	return join(root, RUAH_DIR, APPROVALS_FILE);
}

/** Load all approval requests under `root`. Missing file means empty queue. */
export function loadApprovals(root: string): ApprovalRequest[] {
	const file = approvalsPath(root);
	if (!existsSync(file)) return [];
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(file, "utf8"));
	} catch (err) {
		throw new UserError(
			`Invalid JSON in ${file}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!Array.isArray((parsed as { requests?: unknown }).requests)
	) {
		throw new UserError(
			`Malformed approvals file ${file} — expected { "requests": [...] }`,
		);
	}
	return (parsed as { requests: ApprovalRequest[] }).requests;
}

function saveApprovals(root: string, requests: ApprovalRequest[]): void {
	const dir = join(root, RUAH_DIR);
	mkdirSync(dir, { recursive: true });
	writeFileSync(
		approvalsPath(root),
		`${JSON.stringify({ requests }, null, "\t")}\n`,
		"utf8",
	);
}

/** Queue a new pending approval request and persist it. */
export function requestApproval(
	root: string,
	input: { command: string; reason?: string; actor?: string },
): ApprovalRequest {
	if (typeof input.command !== "string" || input.command.trim() === "") {
		throw new UserError("approval request needs a non-empty command");
	}
	const requests = loadApprovals(root);
	const request: ApprovalRequest = {
		id: randomBytes(4).toString("hex"),
		command: input.command,
		reason: input.reason ?? "",
		status: "pending",
		requestedAt: new Date().toISOString(),
		requestedBy: input.actor ?? resolveActor(),
		decidedAt: null,
		decidedBy: null,
	};
	requests.push(request);
	saveApprovals(root, requests);
	return request;
}

/** List approval requests, optionally filtered by status. */
export function listApprovals(
	root: string,
	status?: ApprovalStatus,
): ApprovalRequest[] {
	const all = loadApprovals(root);
	return status === undefined ? all : all.filter((r) => r.status === status);
}

function decide(
	root: string,
	id: string,
	status: "granted" | "denied",
	actor?: string,
): ApprovalRequest {
	const requests = loadApprovals(root);
	const request = requests.find((r) => r.id === id);
	if (!request) {
		throw new UserError(
			`No approval request with id "${id}" — see: ruah-guard approve list`,
		);
	}
	if (request.status !== "pending") {
		throw new UserError(`Approval ${id} was already ${request.status}`);
	}
	request.status = status;
	request.decidedAt = new Date().toISOString();
	request.decidedBy = actor ?? resolveActor();
	saveApprovals(root, requests);
	return request;
}

/** Grant a pending approval request. */
export function grantApproval(
	root: string,
	id: string,
	actor?: string,
): ApprovalRequest {
	return decide(root, id, "granted", actor);
}

/** Deny a pending approval request. */
export function denyApproval(
	root: string,
	id: string,
	actor?: string,
): ApprovalRequest {
	return decide(root, id, "denied", actor);
}

/** Exact command strings with a granted approval. */
export function grantedCommands(root: string): string[] {
	return listApprovals(root, "granted").map((r) => r.command);
}
