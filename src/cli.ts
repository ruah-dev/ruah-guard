#!/usr/bin/env node

/**
 * ruah-guard CLI — policy engine for agent safety.
 *
 * Exit codes: 0 success / allowed / clean scan, 1 user error or blocked
 * (deny / approval pending / findings at or above --fail-on), 2 internal
 * error. With --json, stdout carries pure machine-readable JSON; human
 * logs go to stderr.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { LockMode, Policy, RiskLevel } from "@ruah-dev/schema";
import type { ApprovalStatus } from "./approvals.js";
import {
	denyApproval,
	grantApproval,
	grantedCommands,
	listApprovals,
	requestApproval,
} from "./approvals.js";
import { AUDIT_FILE, appendAudit, auditStats, readAudit } from "./audit.js";
import { UserError } from "./errors.js";
import {
	claudeCodeHookConfig,
	evaluateHookEvent,
	failClosedVerdict,
	failOpenVerdict,
	hookResult,
	parseHookEvent,
	toVerdict,
} from "./hook.js";
import type { CheckResult } from "./policy.js";
import {
	checkCommand,
	checkPath,
	initPolicy,
	loadPolicy,
	RUAH_DIR,
	secretAllowlist,
} from "./policy.js";
import type { ScanResult } from "./scanner.js";
import {
	listStagedFiles,
	SEVERITY_ORDER,
	scanDir,
	scanFiles,
	severityAtLeast,
} from "./scanner.js";
import { VERSION } from "./version.js";

export interface ParsedArgs {
	_: string[];
	flags: Record<string, string | boolean>;
}

const BOOLEAN_FLAGS = new Set([
	"json",
	"force",
	"staged",
	"help",
	"h",
	"version",
	"v",
	"stdin",
	"stats",
	"fail-open",
	"quiet",
	"debug",
]);

export function parseArgs(argv: string[]): ParsedArgs {
	const args: ParsedArgs = { _: [], flags: {} };
	let i = 0;
	while (i < argv.length) {
		const arg = argv[i];
		if (arg.startsWith("--")) {
			const eq = arg.indexOf("=");
			if (eq !== -1) {
				args.flags[arg.slice(2, eq)] = arg.slice(eq + 1);
			} else {
				const key = arg.slice(2);
				const next = argv[i + 1];
				if (
					BOOLEAN_FLAGS.has(key) ||
					next === undefined ||
					next.startsWith("-")
				) {
					args.flags[key] = true;
				} else {
					args.flags[key] = next;
					i++;
				}
			}
		} else if (arg.startsWith("-") && arg.length === 2) {
			args.flags[arg.slice(1)] = true;
		} else {
			args._.push(arg);
		}
		i++;
	}
	return args;
}

function buildHelp(): string {
	return `
ruah-guard — policy engine for agent safety

Usage:
  ruah-guard init [--force] [--json]            Write a starter .ruah/guard.json
  ruah-guard check --cmd '<cmd>' [--json]       Evaluate a shell command against the policy
  ruah-guard check --command '<cmd>' [--json]   (alias of --cmd)
  ruah-guard check --path <p> [--mode read|write] [--json]
                                                Evaluate a file path boundary (default mode: write)
  ruah-guard check --file <path> [--json]       Scan one file / diff for secrets
  ruah-guard scan [dir] [--staged] [--fail-on low|medium|high|critical]
                  [--exclude <glob,glob>] [--json]
                                                Scan for committed secrets (default dir: .)
  ruah-guard hook claude-code                   Print ready-to-paste Claude Code hook config
  ruah-guard hook --stdin [--fail-open] [--json]
                                                Read one PreToolUse / generic event from stdin
  ruah-guard request --command '<cmd>' [--reason '<why>'] [--json]
                                                Queue a command for human approval
  ruah-guard approve list [--status pending|granted|denied] [--json]
  ruah-guard approve grant <id> [--json]
  ruah-guard approve deny <id> [--json]
  ruah-guard audit [--last <n>] [--stats] [--json]
                                                Show the append-only audit log

Decisions:
  allow    command/path is fine — exit 0
  approve  human approval required — exit 1 until granted (see request/approve)
  deny     blocked by policy — exit 1

Policy:
  Reads .ruah/guard.json (falls back to .ruah/policy.json). Canonical Policy
  type from @ruah-dev/schema. Without one, a built-in default applies:
  destructive commands (rm -rf /, ~, ., dd, mkfs, DROP/TRUNCATE, force-push
  to main, curl|bash, chmod 777, > /dev/sd*) are denied; git push, npm
  publish, docker push, terraform apply, DELETE FROM, and deploys require
  approval (action "ask" / "approve").

  Full shell interpretation is out of scope — guard is best-effort pattern
  defense. Documented uncatchable bypasses live in the README.

Options:
  --json         Machine-readable JSON on stdout (human logs go to stderr)
  --fail-open    Hook: allow on malformed stdin (default is fail-closed)
  --help, -h     Show this help
  --version, -v  Show version

Exit codes:
  0  success / allowed / no findings at or above --fail-on
  1  user error / denied / approval pending / findings
  2  internal error

Environment:
  RUAH_ACTOR     Actor recorded in approvals and the audit log (default: OS user)

Examples:
  ruah-guard check --cmd 'rm -rf /' --json
  echo '{"tool":"Bash","command":"rm -rf /"}' | ruah-guard hook --stdin
  ruah-guard scan . --json
  ruah-guard request --command 'git push origin main' --reason 'release v1.2.0'
  ruah-guard approve grant 1a2b3c4d
  ruah-guard audit --last 20 --json
`;
}

function out(text: string): void {
	console.log(text);
}

function emitJson(data: unknown): void {
	console.log(JSON.stringify(data, null, 2));
}

function safeAudit(
	root: string,
	entry: {
		action: string;
		decision?: string;
		details?: Record<string, unknown>;
	},
): void {
	try {
		appendAudit(root, entry);
	} catch (err) {
		console.error(
			`ruah-guard: warning — could not write audit log: ${
				err instanceof Error ? err.message : String(err)
			}`,
		);
	}
}

function stringFlag(args: ParsedArgs, name: string): string | undefined {
	const value = args.flags[name];
	return typeof value === "string" ? value : undefined;
}

function cmdInit(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const file = initPolicy(cwd, args.flags.force === true);
	safeAudit(cwd, { action: "init", details: { file } });
	if (json) {
		emitJson({ written: file });
	} else {
		out(`Wrote starter policy: ${file}`);
		out(
			"Edit the rules, then try: ruah-guard check --command 'git push' --json",
		);
	}
}

interface CheckPayload extends CheckResult {
	kind: "command" | "path";
	subject: string;
	mode?: LockMode;
	policySource: string;
}

function emitCheckResult(payload: CheckPayload, json: boolean): void {
	if (json) {
		const verdict = toVerdict(payload, payload.subject);
		emitJson({
			...payload,
			schemaVersion: verdict.schemaVersion,
			ruleId: verdict.ruleId,
			matched: verdict.matched,
			severity: verdict.severity,
		});
	} else {
		out(
			`${payload.decision.toUpperCase()} (${payload.riskLevel}) ${payload.subject}`,
		);
		out(`  rule:   ${payload.rule ?? "(policy default action)"}`);
		out(`  reason: ${payload.reason}`);
		if (payload.decision === "approve") {
			out(
				`  next:   ruah-guard request --command '${payload.subject}' --reason '<why>'`,
			);
		}
	}
	if (payload.decision !== "allow") {
		process.exitCode = 1;
	}
}

function cmdCheck(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const command = stringFlag(args, "cmd") ?? stringFlag(args, "command");
	const path = stringFlag(args, "path");
	const file = stringFlag(args, "file");
	const selected = [command, path, file].filter((v) => v !== undefined);
	if (selected.length > 1) {
		throw new UserError("check takes one of --cmd, --path, or --file");
	}
	const loaded = loadPolicy(cwd);

	if (command !== undefined) {
		const result = checkCommand(command, loaded.policy, {
			grantedCommands: grantedCommands(cwd),
		});
		safeAudit(cwd, {
			action: "check.command",
			decision: result.decision,
			details: { command, rule: result.rule },
		});
		emitCheckResult(
			{
				kind: "command",
				subject: command,
				...result,
				policySource: loaded.source,
			},
			json,
		);
		return;
	}

	if (path !== undefined) {
		const modeFlag = stringFlag(args, "mode") ?? "write";
		if (modeFlag !== "read" && modeFlag !== "write") {
			throw new UserError(
				`--mode must be "read" or "write", got "${modeFlag}"`,
			);
		}
		const result = checkPath(path, modeFlag, loaded.policy);
		safeAudit(cwd, {
			action: "check.path",
			decision: result.decision,
			details: { path, mode: modeFlag, rule: result.rule },
		});
		emitCheckResult(
			{
				kind: "path",
				subject: path,
				mode: modeFlag,
				...result,
				policySource: loaded.source,
			},
			json,
		);
		return;
	}

	if (file !== undefined) {
		cmdScanFile(cwd, file, loaded.policy, json);
		return;
	}

	throw new UserError(
		"check needs --cmd '<cmd>', --path <p>, or --file <path>",
	);
}

function cmdScanFile(
	cwd: string,
	file: string,
	policy: Policy,
	json: boolean,
): void {
	const result = scanFiles(cwd, [file], {
		customRules: policy.rules.filter((r) => r.kind === "secret"),
		allow: secretAllowlist(policy),
	});
	const failed = result.findings.length > 0;
	safeAudit(cwd, {
		action: "check.file",
		decision: failed ? "deny" : "allow",
		details: { file, findings: result.findings.length },
	});
	if (json) {
		emitJson({
			schemaVersion: "1",
			kind: "file",
			subject: file,
			findings: result.findings,
			summary: {
				filesScanned: result.filesScanned,
				total: result.findings.length,
				failed,
			},
		});
	} else {
		for (const f of result.findings) {
			out(
				`[${f.severity}] ${f.file}:${f.line}:${f.column} ${f.detector} — ${f.message} (${f.excerpt})`,
			);
		}
		out(
			`${result.findings.length} finding(s) in ${file}` +
				` — ${failed ? "FAIL" : "OK"}`,
		);
	}
	if (failed) process.exitCode = 1;
}

function cmdScan(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const dirArg = args._[1] ?? ".";
	const failOnFlag = stringFlag(args, "fail-on") ?? "high";
	if (!(failOnFlag in SEVERITY_ORDER)) {
		throw new UserError(
			`--fail-on must be one of: ${Object.keys(SEVERITY_ORDER).join(", ")} — got "${failOnFlag}"`,
		);
	}
	const failOn = failOnFlag as RiskLevel;
	const excludeFlag = stringFlag(args, "exclude");
	const exclude = excludeFlag
		? excludeFlag
				.split(",")
				.map((p) => p.trim())
				.filter((p) => p !== "")
		: [];
	const loaded = loadPolicy(cwd);
	const customRules = loaded.policy.rules.filter((r) => r.kind === "secret");
	const options = {
		exclude,
		customRules,
		allow: secretAllowlist(loaded.policy),
	};

	let result: ScanResult;
	let target: string;
	if (args.flags.staged === true) {
		target = "(staged files)";
		result = scanFiles(cwd, listStagedFiles(cwd), options);
	} else {
		target = dirArg;
		result = scanDir(resolve(cwd, dirArg), options);
	}

	const failed = result.findings.some((f) =>
		severityAtLeast(f.severity, failOn),
	);
	const bySeverity: Record<string, number> = {};
	for (const finding of result.findings) {
		bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
	}
	safeAudit(cwd, {
		action: "scan",
		decision: failed ? "fail" : "pass",
		details: { target, findings: result.findings.length, failOn },
	});

	if (json) {
		emitJson({
			findings: result.findings,
			summary: {
				filesScanned: result.filesScanned,
				filesSkipped: result.filesSkipped,
				total: result.findings.length,
				bySeverity,
				failOn,
				failed,
			},
		});
	} else {
		for (const f of result.findings) {
			out(
				`[${f.severity}] ${f.file}:${f.line}:${f.column} ${f.detector} — ${f.message} (${f.excerpt})`,
			);
		}
		out(
			`${result.findings.length} finding(s) in ${result.filesScanned} file(s)` +
				` — ${failed ? `FAIL (≥ ${failOn})` : "OK"}`,
		);
	}
	if (failed) {
		process.exitCode = 1;
	}
}

function cmdRequest(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const command = stringFlag(args, "command");
	if (command === undefined) {
		throw new UserError("request needs --command '<cmd>'");
	}
	const reason = stringFlag(args, "reason") ?? "";
	const request = requestApproval(cwd, { command, reason });
	safeAudit(cwd, {
		action: "approve.request",
		decision: "pending",
		details: { id: request.id, command },
	});
	if (json) {
		emitJson(request);
	} else {
		out(`Approval requested: ${request.id}`);
		out(`  command: ${request.command}`);
		out(`  reason:  ${request.reason || "(none)"}`);
		out(`Grant with: ruah-guard approve grant ${request.id}`);
	}
}

function cmdApprove(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const sub = args._[1];

	if (sub === "list") {
		const statusFlag = stringFlag(args, "status");
		if (
			statusFlag !== undefined &&
			statusFlag !== "pending" &&
			statusFlag !== "granted" &&
			statusFlag !== "denied"
		) {
			throw new UserError(
				`--status must be pending, granted, or denied — got "${statusFlag}"`,
			);
		}
		const requests = listApprovals(
			cwd,
			statusFlag as ApprovalStatus | undefined,
		);
		if (json) {
			emitJson({ requests, count: requests.length });
		} else if (requests.length === 0) {
			out(
				"No approval requests. Queue one with: ruah-guard request --command '<cmd>'",
			);
		} else {
			for (const r of requests) {
				out(
					`${r.id}  [${r.status}]  ${r.command}${r.reason ? `  — ${r.reason}` : ""}`,
				);
			}
		}
		return;
	}

	if (sub === "grant" || sub === "deny") {
		const id = args._[2];
		if (id === undefined) {
			throw new UserError(
				`approve ${sub} needs an id — see: ruah-guard approve list`,
			);
		}
		const request =
			sub === "grant" ? grantApproval(cwd, id) : denyApproval(cwd, id);
		safeAudit(cwd, {
			action: `approve.${sub}`,
			decision: request.status,
			details: { id: request.id, command: request.command },
		});
		if (json) {
			emitJson(request);
		} else {
			out(`${request.status}: ${request.id} (${request.command})`);
		}
		return;
	}

	throw new UserError(
		"approve needs a subcommand: list | grant <id> | deny <id>",
	);
}

function cmdAudit(args: ParsedArgs, json: boolean): void {
	const cwd = process.cwd();
	const tailFlag = stringFlag(args, "last") ?? stringFlag(args, "tail");
	let tail = 20;
	if (tailFlag !== undefined) {
		tail = Number.parseInt(tailFlag, 10);
		if (Number.isNaN(tail) || tail < 0) {
			throw new UserError(
				`--last must be a non-negative integer, got "${tailFlag}"`,
			);
		}
	}
	const entries = readAudit(cwd, tail);
	if (args.flags.stats === true) {
		const stats = auditStats(readAudit(cwd));
		if (json) {
			emitJson({ schemaVersion: "1", ...stats });
		} else {
			out(`total ${stats.total}`);
			for (const key of Object.keys(stats.byDecision).sort()) {
				out(`  decision ${key}: ${stats.byDecision[key]}`);
			}
			for (const key of Object.keys(stats.byRule).sort()) {
				out(`  rule ${key}: ${stats.byRule[key]}`);
			}
		}
		return;
	}
	if (json) {
		emitJson({
			entries,
			count: entries.length,
			file: join(cwd, RUAH_DIR, AUDIT_FILE),
		});
	} else if (entries.length === 0) {
		out("Audit log is empty.");
	} else {
		for (const e of entries) {
			out(
				`${e.ts}  ${e.actor}  ${e.action}${e.decision ? `  ${e.decision}` : ""}`,
			);
		}
	}
}

function cmdHook(args: ParsedArgs, json: boolean): void {
	const target = args._[1];
	if (target === "claude-code") {
		const config = claudeCodeHookConfig();
		if (json) {
			emitJson(JSON.parse(config));
		} else {
			out(config.trimEnd());
		}
		return;
	}
	if (args.flags.stdin !== true && target !== "--stdin") {
		throw new UserError(
			"hook needs `claude-code` or `--stdin` — run ruah-guard --help",
		);
	}

	const failOpen = args.flags["fail-open"] === true;
	const cwd = process.cwd();
	let raw = "";
	try {
		raw = readFileSync(0, "utf8");
	} catch {
		raw = "";
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		const failed = failOpen
			? failOpenVerdict("malformed hook stdin JSON — fail-open")
			: failClosedVerdict("malformed hook stdin JSON — fail-closed");
		writeHook(failed, json);
		return;
	}
	const event = parseHookEvent(parsed);
	if (!event) {
		const failed = failOpen
			? failOpenVerdict("hook event missing tool — fail-open")
			: failClosedVerdict("hook event missing tool — fail-closed");
		writeHook(failed, json);
		return;
	}
	const loaded = loadPolicy(cwd);
	const result = evaluateHookEvent(event, loaded.policy, grantedCommands(cwd));
	const matched = event.command ?? event.path ?? event.tool;
	const payload = hookResult(result, matched);
	safeAudit(cwd, {
		action: "hook",
		decision: payload.verdict.decision,
		details: { tool: event.tool, rule: result.rule, matched },
	});
	writeHook(payload, json);
}

function writeHook(
	payload: ReturnType<typeof hookResult>,
	json: boolean,
): void {
	// Hook always writes the verdict JSON (Claude Code reads stdout).
	// Exit 0 so a deny is a result, not a hook crash.
	emitJson({
		...payload.verdict,
		hookSpecificOutput: payload.hookSpecificOutput,
	});
	if (!json) {
		// Human hint on stderr only — stdout stays pipe-clean.
		console.error(
			`${payload.verdict.decision.toUpperCase()} ${payload.verdict.ruleId ?? ""}`.trim(),
		);
	}
	process.exitCode = 0;
}

function main(): void {
	const args = parseArgs(process.argv.slice(2));
	const json = args.flags.json === true;

	if (args.flags.help === true || args.flags.h === true) {
		out(buildHelp().trim());
		return;
	}
	if (args.flags.version === true || args.flags.v === true) {
		out(`ruah-guard ${VERSION}`);
		return;
	}

	const command = args._[0];
	if (command === undefined) {
		out(buildHelp().trim());
		return;
	}

	try {
		switch (command) {
			case "init":
				cmdInit(args, json);
				break;
			case "check":
				cmdCheck(args, json);
				break;
			case "scan":
				cmdScan(args, json);
				break;
			case "request":
				cmdRequest(args, json);
				break;
			case "approve":
				cmdApprove(args, json);
				break;
			case "audit":
				cmdAudit(args, json);
				break;
			case "hook":
				cmdHook(args, json);
				break;
			default:
				throw new UserError(
					`Unknown command: ${command} (run ruah-guard --help)`,
				);
		}
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		if (json) {
			emitJson({ error: message });
		}
		console.error(`ruah-guard: ${message}`);
		if (process.env.RUAH_DEBUG && err instanceof Error) {
			console.error(err.stack);
		}
		process.exitCode = err instanceof UserError ? 1 : 2;
	}
}

main();
