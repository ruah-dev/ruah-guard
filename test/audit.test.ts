import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { appendAudit, readAudit, resolveActor } from "../src/index.js";

describe("audit log", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "ruah-guard-audit-"));
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	it("appendAudit creates .ruah/audit.jsonl and returns the full entry", () => {
		const entry = appendAudit(root, {
			action: "check.command",
			decision: "deny",
			actor: "test-actor",
			details: { command: "rm -rf /" },
		});
		assert.equal(entry.actor, "test-actor");
		assert.match(entry.ts, /^\d{4}-\d{2}-\d{2}T/);
		const file = join(root, ".ruah", "audit.jsonl");
		assert.ok(existsSync(file));
		const lines = readFileSync(file, "utf8").trim().split("\n");
		assert.equal(lines.length, 1);
		const parsed = JSON.parse(lines[0]) as { action: string; decision: string };
		assert.equal(parsed.action, "check.command");
		assert.equal(parsed.decision, "deny");
	});

	it("audit log is append-only across calls", () => {
		appendAudit(root, { action: "a", actor: "t" });
		appendAudit(root, { action: "b", actor: "t" });
		appendAudit(root, { action: "c", actor: "t" });
		const entries = readAudit(root);
		assert.deepEqual(
			entries.map((e) => e.action),
			["a", "b", "c"],
		);
	});

	it("readAudit tail returns only the last n entries", () => {
		for (const action of ["one", "two", "three", "four"]) {
			appendAudit(root, { action, actor: "t" });
		}
		const tail = readAudit(root, 2);
		assert.deepEqual(
			tail.map((e) => e.action),
			["three", "four"],
		);
	});

	it("readAudit skips malformed lines instead of throwing", () => {
		appendAudit(root, { action: "good", actor: "t" });
		appendFileSync(join(root, ".ruah", "audit.jsonl"), "this is not json\n");
		appendAudit(root, { action: "also-good", actor: "t" });
		const entries = readAudit(root);
		assert.deepEqual(
			entries.map((e) => e.action),
			["good", "also-good"],
		);
	});

	it("readAudit returns empty for a missing log", () => {
		assert.deepEqual(readAudit(root), []);
	});

	it("resolveActor honors RUAH_ACTOR and falls back to the OS user", () => {
		const original = process.env.RUAH_ACTOR;
		try {
			process.env.RUAH_ACTOR = "agent-007";
			assert.equal(resolveActor(), "agent-007");
			delete process.env.RUAH_ACTOR;
			assert.ok(resolveActor().length > 0);
		} finally {
			if (original === undefined) {
				delete process.env.RUAH_ACTOR;
			} else {
				process.env.RUAH_ACTOR = original;
			}
		}
	});
});
