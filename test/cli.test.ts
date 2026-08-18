import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// Compiled CLI inside dist-test (built by the pretest step).
const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));

// Assembled at runtime so secret hooks never see a complete literal.
const SK_LIVE = ["sk", "live", "FAKE1234567890abcdef"].join("_");

interface RunResult {
	status: number | null;
	stdout: string;
	stderr: string;
}

function run(args: string[], cwd: string, input?: string): RunResult {
	const result = spawnSync(process.execPath, [CLI, ...args], {
		cwd,
		encoding: "utf8",
		input,
		env: { ...process.env, RUAH_ACTOR: "test-actor" },
	});
	return {
		status: result.status,
		stdout: result.stdout,
		stderr: result.stderr,
	};
}

function runJson<T>(
	args: string[],
	cwd: string,
): { status: number | null; data: T } {
	const result = run(args, cwd);
	return { status: result.status, data: JSON.parse(result.stdout) as T };
}

describe("ruah-guard CLI", () => {
	let cwd: string;

	beforeEach(() => {
		cwd = mkdtempSync(join(tmpdir(), "ruah-guard-cli-"));
	});

	afterEach(() => {
		rmSync(cwd, { recursive: true, force: true });
	});

	it("--help exits 0 and prints usage", () => {
		const result = run(["--help"], cwd);
		assert.equal(result.status, 0);
		assert.match(result.stdout, /ruah-guard — policy engine/);
		assert.match(result.stdout, /Usage:/);
	});

	it("-h is an alias for --help", () => {
		const result = run(["-h"], cwd);
		assert.equal(result.status, 0);
		assert.match(result.stdout, /Usage:/);
	});

	it("--version exits 0 and prints a semver", () => {
		const result = run(["--version"], cwd);
		assert.equal(result.status, 0);
		assert.match(result.stdout, /ruah-guard \d+\.\d+\.\d+/);
	});

	it("unknown commands exit 1", () => {
		const result = run(["frobnicate"], cwd);
		assert.equal(result.status, 1);
		assert.match(result.stderr, /Unknown command/);
	});

	it("init writes .ruah/guard.json and emits JSON", () => {
		const { status, data } = runJson<{ written: string }>(
			["init", "--json"],
			cwd,
		);
		assert.equal(status, 0);
		assert.ok(data.written.endsWith(join(".ruah", "guard.json")));
		assert.ok(existsSync(join(cwd, ".ruah", "guard.json")));
	});

	it("init refuses to overwrite without --force", () => {
		assert.equal(run(["init"], cwd).status, 0);
		const second = run(["init", "--json"], cwd);
		assert.equal(second.status, 1);
		const error = JSON.parse(second.stdout) as { error: string };
		assert.match(error.error, /already exists/);
		assert.equal(run(["init", "--force"], cwd).status, 0);
	});

	it("check --command allows safe commands with valid JSON on stdout", () => {
		const { status, data } = runJson<{
			decision: string;
			rule: null;
			policySource: string;
		}>(["check", "--command", "ls -la", "--json"], cwd);
		assert.equal(status, 0);
		assert.equal(data.decision, "allow");
		assert.equal(data.rule, null);
		assert.equal(data.policySource, "default");
	});

	it("check --command denies destructive commands and exits 1", () => {
		const { status, data } = runJson<{
			decision: string;
			riskLevel: string;
			rule: string;
		}>(["check", "--command", "rm -rf /", "--json"], cwd);
		assert.equal(status, 1);
		assert.equal(data.decision, "deny");
		assert.equal(data.riskLevel, "critical");
		assert.equal(data.rule, "deny-rm-root");
	});

	it("check --path enforces write boundaries", () => {
		const denied = runJson<{ decision: string }>(
			["check", "--path", ".git/config", "--mode", "write", "--json"],
			cwd,
		);
		assert.equal(denied.status, 1);
		assert.equal(denied.data.decision, "deny");
		const allowed = runJson<{ decision: string }>(
			["check", "--path", "src/index.ts", "--mode", "write", "--json"],
			cwd,
		);
		assert.equal(allowed.status, 0);
		assert.equal(allowed.data.decision, "allow");
	});

	it("check without --command or --path exits 1", () => {
		assert.equal(run(["check", "--json"], cwd).status, 1);
	});

	it("check uses a custom .ruah/policy.json when present", () => {
		mkdirSync(join(cwd, ".ruah"), { recursive: true });
		writeFileSync(
			join(cwd, ".ruah", "policy.json"),
			JSON.stringify({
				name: "strict",
				defaultAction: "deny",
				rules: [{ kind: "command", pattern: "^ls\\b", action: "allow" }],
			}),
		);
		assert.equal(
			runJson<{ decision: string }>(["check", "--command", "ls", "--json"], cwd)
				.data.decision,
			"allow",
		);
		const denied = runJson<{ decision: string; policySource: string }>(
			["check", "--command", "cat x", "--json"],
			cwd,
		);
		assert.equal(denied.data.decision, "deny");
		assert.notEqual(denied.data.policySource, "default");
	});

	it("request → approve grant → check turns approve into allow", () => {
		const blocked = runJson<{ decision: string }>(
			["check", "--command", "git push origin main", "--json"],
			cwd,
		);
		assert.equal(blocked.status, 1);
		assert.equal(blocked.data.decision, "approve");

		const requested = runJson<{ id: string; status: string }>(
			[
				"request",
				"--command",
				"git push origin main",
				"--reason",
				"release v1.2.0",
				"--json",
			],
			cwd,
		);
		assert.equal(requested.status, 0);
		assert.equal(requested.data.status, "pending");

		const list = runJson<{
			requests: Array<{ id: string; status: string }>;
			count: number;
		}>(["approve", "list", "--json"], cwd);
		assert.equal(list.data.count, 1);
		assert.equal(list.data.requests[0].status, "pending");

		const granted = runJson<{ status: string; decidedBy: string }>(
			["approve", "grant", requested.data.id, "--json"],
			cwd,
		);
		assert.equal(granted.status, 0);
		assert.equal(granted.data.status, "granted");
		assert.equal(granted.data.decidedBy, "test-actor");

		const allowed = runJson<{ decision: string }>(
			["check", "--command", "git push origin main", "--json"],
			cwd,
		);
		assert.equal(allowed.status, 0);
		assert.equal(allowed.data.decision, "allow");
	});

	it("approve deny rejects a request; unknown ids exit 1", () => {
		const requested = runJson<{ id: string }>(
			["request", "--command", "npm publish", "--json"],
			cwd,
		);
		const denied = runJson<{ status: string }>(
			["approve", "deny", requested.data.id, "--json"],
			cwd,
		);
		assert.equal(denied.data.status, "denied");
		assert.equal(
			run(["approve", "grant", "deadbeef", "--json"], cwd).status,
			1,
		);
	});

	it("scan finds planted secrets, exits 1, and emits valid JSON", () => {
		mkdirSync(join(cwd, "src"), { recursive: true });
		writeFileSync(join(cwd, "src", "app.js"), `const key = "${SK_LIVE}";\n`);
		const result = run(["scan", ".", "--json"], cwd);
		assert.equal(result.status, 1);
		const data = JSON.parse(result.stdout) as {
			findings: Array<{
				detector: string;
				file: string;
				line: number;
				excerpt: string;
			}>;
			summary: { failed: boolean; failOn: string; total: number };
		};
		assert.equal(data.summary.failed, true);
		assert.equal(data.summary.failOn, "high");
		assert.equal(data.findings[0].detector, "stripe-live-key");
		assert.equal(data.findings[0].file, "src/app.js");
		assert.ok(!data.findings[0].excerpt.includes("FAKE1234567890abcdef"));
	});

	it("scan on a clean directory exits 0", () => {
		writeFileSync(join(cwd, "clean.js"), "const ok = true;\n");
		const { status, data } = runJson<{
			summary: { failed: boolean; total: number };
		}>(["scan", ".", "--json"], cwd);
		assert.equal(status, 0);
		assert.equal(data.summary.failed, false);
		assert.equal(data.summary.total, 0);
	});

	it("scan --fail-on critical tolerates high findings", () => {
		// AWS access key id is "high" — below the critical bar.
		writeFileSync(
			join(cwd, "aws.txt"),
			`${["AKIA", "IOSFODNN7", "EXAMPLE"].join("")}\n`,
		);
		const result = run(["scan", ".", "--fail-on", "critical", "--json"], cwd);
		assert.equal(result.status, 0);
		const data = JSON.parse(result.stdout) as {
			summary: { total: number; failed: boolean };
		};
		assert.equal(data.summary.total, 1);
		assert.equal(data.summary.failed, false);
	});

	it("scan --fail-on rejects invalid levels", () => {
		assert.equal(
			run(["scan", ".", "--fail-on", "nuclear", "--json"], cwd).status,
			1,
		);
	});

	it("scan --staged outside a git repo exits 1", () => {
		const result = run(["scan", "--staged", "--json"], cwd);
		assert.equal(result.status, 1);
	});

	it("scan --staged scans only staged files in a git repo", (t) => {
		try {
			execFileSync("git", ["--version"], { encoding: "utf8" });
		} catch {
			t.skip("git not available");
			return;
		}
		execFileSync("git", ["init", "-q"], { cwd });
		writeFileSync(join(cwd, "staged.js"), `const k = "${SK_LIVE}";\n`);
		writeFileSync(join(cwd, "unstaged.js"), `const k = "${SK_LIVE}";\n`);
		execFileSync("git", ["add", "staged.js"], { cwd });
		const result = run(["scan", "--staged", "--json"], cwd);
		assert.equal(result.status, 1);
		const data = JSON.parse(result.stdout) as {
			findings: Array<{ file: string }>;
		};
		assert.equal(data.findings.length, 1);
		assert.equal(data.findings[0].file, "staged.js");
	});

	it("audit records check/scan/approve actions and supports --tail", () => {
		run(["check", "--command", "ls", "--json"], cwd);
		run(["check", "--command", "rm -rf /", "--json"], cwd);
		const requested = runJson<{ id: string }>(
			["request", "--command", "git push", "--json"],
			cwd,
		);
		run(["approve", "grant", requested.data.id, "--json"], cwd);

		const { status, data } = runJson<{
			entries: Array<{
				ts: string;
				actor: string;
				action: string;
				decision?: string;
			}>;
			count: number;
		}>(["audit", "--json", "--tail", "10"], cwd);
		assert.equal(status, 0);
		assert.ok(data.count >= 4);
		const actions = data.entries.map((e) => e.action);
		assert.ok(actions.includes("check.command"));
		assert.ok(actions.includes("approve.request"));
		assert.ok(actions.includes("approve.grant"));
		assert.equal(data.entries[0].actor, "test-actor");

		const tailed = runJson<{ count: number }>(
			["audit", "--json", "--tail", "2"],
			cwd,
		);
		assert.equal(tailed.data.count, 2);
	});

	it("audit --tail rejects non-numeric values", () => {
		assert.equal(run(["audit", "--tail", "abc", "--json"], cwd).status, 1);
	});

	it("check --cmd is an alias of --command and stamps schemaVersion", () => {
		const { status, data } = runJson<{
			decision: string;
			schemaVersion: string;
			ruleId: string;
			severity: string;
		}>(["check", "--cmd", "rm -rf /", "--json"], cwd);
		assert.equal(status, 1);
		assert.equal(data.decision, "deny");
		assert.equal(data.schemaVersion, "1");
		assert.equal(data.ruleId, "deny-rm-root");
		assert.equal(data.severity, "critical");
	});

	it("hook claude-code prints pasteable settings", () => {
		const result = run(["hook", "claude-code"], cwd);
		assert.equal(result.status, 0);
		assert.match(result.stdout, /PreToolUse/);
		assert.match(result.stdout, /ruah-guard hook --stdin/);
	});

	it("hook --stdin denies rm -rf and always exits 0", () => {
		const result = run(
			["hook", "--stdin"],
			cwd,
			JSON.stringify({ tool: "Bash", command: "rm -rf /" }),
		);
		assert.equal(result.status, 0);
		const data = JSON.parse(result.stdout) as {
			decision: string;
			ruleId: string;
			schemaVersion: string;
			hookSpecificOutput: { permissionDecision: string };
		};
		assert.equal(data.schemaVersion, "1");
		assert.equal(data.decision, "deny");
		assert.equal(data.ruleId, "deny-rm-root");
		assert.equal(data.hookSpecificOutput.permissionDecision, "deny");
		assert.ok(!result.stdout.includes("rm -rf /") || data.decision === "deny");
	});

	it("hook --stdin fail-closed on malformed JSON; --fail-open allows", () => {
		const closed = run(["hook", "--stdin"], cwd, "{not json");
		assert.equal(closed.status, 0);
		assert.equal(JSON.parse(closed.stdout).decision, "deny");
		const opened = run(["hook", "--stdin", "--fail-open"], cwd, "{not json");
		assert.equal(opened.status, 0);
		assert.equal(JSON.parse(opened.stdout).decision, "allow");
	});

	it("check --file scans a diff and redacts secret values", () => {
		writeFileSync(join(cwd, "staged.diff"), `+const k = "${SK_LIVE}";\n`);
		const result = run(["check", "--file", "staged.diff", "--json"], cwd);
		assert.equal(result.status, 1);
		assert.ok(!result.stdout.includes("FAKE1234567890abcdef"));
		const data = JSON.parse(result.stdout) as {
			findings: Array<{ excerpt: string; detector: string }>;
		};
		assert.equal(data.findings[0].detector, "stripe-live-key");
		assert.equal(data.findings[0].excerpt, "sk_live_••••");
	});
});
