import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
	denyApproval,
	grantApproval,
	grantedCommands,
	listApprovals,
	loadApprovals,
	requestApproval,
	UserError,
} from "../src/index.js";

describe("approvals lifecycle", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "ruah-guard-approvals-"));
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	it("loadApprovals returns an empty queue when no file exists", () => {
		assert.deepEqual(loadApprovals(root), []);
	});

	it("requestApproval persists a pending entry with an 8-char hex id", () => {
		const request = requestApproval(root, {
			command: "git push origin main",
			reason: "release",
			actor: "test-actor",
		});
		assert.match(request.id, /^[0-9a-f]{8}$/);
		assert.equal(request.status, "pending");
		assert.equal(request.requestedBy, "test-actor");
		assert.ok(existsSync(join(root, ".ruah", "approvals.json")));
		const raw = JSON.parse(readFileSync(join(root, ".ruah", "approvals.json"), "utf8")) as {
			requests: unknown[];
		};
		assert.equal(raw.requests.length, 1);
	});

	it("listApprovals filters by status", () => {
		const a = requestApproval(root, { command: "npm publish", actor: "t" });
		requestApproval(root, { command: "git push", actor: "t" });
		grantApproval(root, a.id, "approver");
		assert.equal(listApprovals(root).length, 2);
		assert.equal(listApprovals(root, "pending").length, 1);
		assert.equal(listApprovals(root, "granted").length, 1);
	});

	it("grantApproval records decider and timestamp", () => {
		const request = requestApproval(root, { command: "npm publish", actor: "t" });
		const granted = grantApproval(root, request.id, "approver");
		assert.equal(granted.status, "granted");
		assert.equal(granted.decidedBy, "approver");
		assert.ok(granted.decidedAt !== null);
	});

	it("denyApproval records the denial", () => {
		const request = requestApproval(root, { command: "terraform apply", actor: "t" });
		const denied = denyApproval(root, request.id, "approver");
		assert.equal(denied.status, "denied");
		assert.deepEqual(grantedCommands(root), []);
	});

	it("grantedCommands lists exact granted command strings", () => {
		const request = requestApproval(root, { command: "git push", actor: "t" });
		grantApproval(root, request.id, "approver");
		assert.deepEqual(grantedCommands(root), ["git push"]);
	});

	it("throws UserError for an unknown id", () => {
		assert.throws(() => grantApproval(root, "deadbeef"), UserError);
	});

	it("throws UserError when deciding twice", () => {
		const request = requestApproval(root, { command: "npm publish", actor: "t" });
		grantApproval(root, request.id, "approver");
		assert.throws(() => denyApproval(root, request.id), /already granted/);
	});

	it("throws UserError on an empty command", () => {
		assert.throws(() => requestApproval(root, { command: "  " }), UserError);
	});
});
