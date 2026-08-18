/**
 * Policy engine — loads `.ruah/policy.json` (canonical `Policy` type from
 * `@ruah-dev/schema`) and evaluates commands and path boundaries against it.
 *
 * Rule semantics: ordered list, first match wins, `defaultAction` applies
 * when nothing matches (defaults to "allow").
 *
 * - `command` rules: `pattern` is a case-insensitive regular expression
 *   source; if it does not compile, it falls back to a case-insensitive
 *   substring match.
 * - `path` rules: `pattern` is a glob (`**`, `*`, `?`). A rule may restrict
 *   itself to read or write via `metadata.modes: ["read"|"write"]`; without
 *   it the rule applies to both modes.
 * - `secret` rules: consumed by the scanner (see scanner.ts), ignored here.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
	LockMode,
	Policy,
	PolicyAction,
	PolicyRule,
	RiskLevel,
} from "@ruah-dev/schema";
import { UserError } from "./errors.js";
import { expandCommand } from "./normalize.js";

/** Config root directory name — always under the consumer's CWD. */
export const RUAH_DIR = ".ruah";

/**
 * Preferred policy file (6-pool name). `policy.json` is still loaded as a
 * fallback so existing repos keep working.
 */
export const POLICY_FILE = "guard.json";

/** Legacy filename kept as a fallback load path. */
export const LEGACY_POLICY_FILE = "policy.json";

const ACTIONS: readonly string[] = ["allow", "deny", "approve", "ask"];
const KINDS: readonly string[] = ["command", "path", "secret"];
const RISKS: readonly string[] = ["low", "medium", "high", "critical"];

/**
 * Built-in policy used when the consumer has no `.ruah/policy.json`.
 *
 * Denies the classic destructive commands; requires human approval for
 * pushes, publishes, infra changes, destructive SQL, and deploys.
 */
export const DEFAULT_POLICY: Policy = {
	name: "ruah-guard-default",
	version: "1",
	schemaVersion: "0.1.0",
	defaultAction: "allow",
	riskLevel: "medium",
	rules: [
		{
			kind: "command",
			id: "deny-rm-root",
			pattern:
				"rm\\s+(-[^\\s]*\\s+)*-[^\\s]*r[^\\s]*(\\s+-[^\\s]*)*\\s+[\"']?(/|~)/?[\"']?\\s*\\*?\\s*$",
			action: "deny",
			riskLevel: "critical",
			description: "Recursive delete targeting filesystem root or home",
		},
		{
			kind: "command",
			id: "deny-rm-no-preserve-root",
			pattern: "rm\\s+[^|;&]*--no-preserve-root",
			action: "deny",
			riskLevel: "critical",
			description: "rm with --no-preserve-root",
		},
		{
			kind: "command",
			id: "deny-dd",
			pattern: "(^|[\\s;|&])dd\\s+[^|;&]*\\b(if|of)=",
			action: "deny",
			riskLevel: "critical",
			description: "Raw disk read/write via dd",
		},
		{
			kind: "command",
			id: "deny-mkfs",
			pattern: "(^|[\\s;|&])mkfs(\\.[a-z0-9]+)?\\b",
			action: "deny",
			riskLevel: "critical",
			description: "Filesystem format via mkfs",
		},
		{
			kind: "command",
			id: "deny-drop-table",
			pattern: "\\bdrop\\s+table\\b",
			action: "deny",
			riskLevel: "critical",
			description: "SQL DROP TABLE",
		},
		{
			kind: "command",
			id: "deny-truncate",
			pattern: "\\btruncate\\s+(table|database|schema)\\b",
			action: "deny",
			riskLevel: "critical",
			description: "SQL TRUNCATE without a WHERE-guard (TRUNCATE has none)",
		},
		{
			kind: "command",
			id: "deny-rm-dot",
			pattern:
				"rm\\s+(-[^\\s]*\\s+)*-[^\\s]*r[^\\s]*(\\s+-[^\\s]*)*\\s+[\"']?\\.(/)?[\"']?\\s*$",
			action: "deny",
			riskLevel: "critical",
			description: "Recursive delete of the current directory (repo root)",
		},
		{
			kind: "command",
			id: "deny-dev-sd",
			pattern: ">\\s*/dev/sd[a-z]\\d*",
			action: "deny",
			riskLevel: "critical",
			description: "Redirect onto a block device",
		},
		{
			kind: "command",
			id: "deny-git-reset-hard-clean",
			pattern:
				"git\\s+reset\\s+--hard\\b[\\s\\S]*git\\s+clean\\s+-[a-zA-Z]*f[a-zA-Z]*d",
			action: "deny",
			riskLevel: "high",
			description: "git reset --hard combined with git clean -fd",
		},
		{
			kind: "command",
			id: "deny-base64-pipe-shell",
			pattern:
				"base64\\s+(-d|--decode)\\b[^|;&]*\\|\\s*(sudo\\s+)?(bash|sh|zsh)\\b",
			action: "deny",
			riskLevel: "high",
			description: "Decoded payload piped straight into a shell",
		},
		{
			kind: "command",
			id: "deny-force-push-protected",
			pattern:
				"git\\s+push\\b(?=[^|;&]*(\\s--force\\b|\\s-f\\b))[^|;&]*\\s(main|master)\\b",
			action: "deny",
			riskLevel: "critical",
			description: "Force-push to main/master",
		},
		{
			kind: "command",
			id: "deny-curl-pipe-shell",
			pattern: "(curl|wget)\\b[^|;&]*\\|\\s*(sudo\\s+)?(bash|sh|zsh)\\b",
			action: "deny",
			riskLevel: "high",
			description: "Remote script piped straight into a shell",
		},
		{
			kind: "command",
			id: "deny-chmod-777",
			pattern: "chmod\\s+(-[^\\s]+\\s+)*0?777\\b",
			action: "deny",
			riskLevel: "high",
			description: "World-writable permissions (chmod 777)",
		},
		{
			kind: "command",
			id: "approve-git-push",
			pattern: "\\bgit\\s+push\\b",
			action: "approve",
			riskLevel: "medium",
			description: "Pushing to a remote requires approval",
		},
		{
			kind: "command",
			id: "approve-npm-publish",
			pattern: "\\bnpm\\s+publish\\b",
			action: "approve",
			riskLevel: "high",
			description: "Publishing a package requires approval",
		},
		{
			kind: "command",
			id: "approve-docker-push",
			pattern: "\\bdocker\\s+push\\b",
			action: "approve",
			riskLevel: "medium",
			description: "Pushing a container image requires approval",
		},
		{
			kind: "command",
			id: "approve-terraform-apply",
			pattern: "\\bterraform\\s+(apply|destroy)\\b",
			action: "approve",
			riskLevel: "high",
			description: "Infrastructure changes require approval",
		},
		{
			kind: "command",
			id: "approve-destructive-sql",
			pattern:
				"\\b(drop|truncate)\\s+(table|database|schema|index)\\b|\\bdelete\\s+from\\b",
			action: "approve",
			riskLevel: "high",
			description: "Destructive SQL requires approval",
		},
		{
			kind: "command",
			id: "approve-deploy",
			pattern: "\\bdeploy\\b",
			action: "approve",
			riskLevel: "medium",
			description: "Deploy commands require approval",
		},
		{
			kind: "path",
			id: "deny-git-internals-write",
			pattern: ".git/**",
			action: "deny",
			riskLevel: "high",
			description: "Direct writes to .git internals",
			metadata: { modes: ["write"] },
		},
		{
			kind: "path",
			id: "deny-private-key-files",
			pattern: "**/id_rsa*",
			action: "deny",
			riskLevel: "critical",
			description: "SSH private key files are off limits",
		},
		{
			kind: "path",
			id: "deny-pem-files",
			pattern: "**/*.pem",
			action: "deny",
			riskLevel: "critical",
			description: "PEM key/cert files are off limits",
		},
		{
			kind: "path",
			id: "approve-env-files",
			pattern: "**/.env*",
			action: "approve",
			riskLevel: "high",
			description:
				"Env files may contain secrets — touching them requires approval",
		},
	],
	metadata: {
		source: "ruah-guard built-in default — run `ruah-guard init` to customize",
	},
};

/** Result of evaluating a command or path against a policy. */
export interface CheckResult {
	/** allow | deny | approve. */
	decision: PolicyAction;
	/** Matched rule id (or its pattern when the rule has no id); null when the default action applied. */
	rule: string | null;
	/** Raw pattern of the matched rule; null when the default action applied. */
	pattern: string | null;
	/** Risk classification of the decision. */
	riskLevel: RiskLevel;
	/** Human-readable explanation. */
	reason: string;
}

/** Options for {@link checkCommand}. */
export interface CheckCommandOptions {
	/**
	 * Exact command strings that already have a granted approval
	 * (see approvals.ts). An "approve" decision for one of these
	 * becomes "allow".
	 */
	grantedCommands?: string[];
}

function defaultRiskFor(action: PolicyAction): RiskLevel {
	if (action === "deny") return "high";
	if (action === "approve" || action === "ask") return "medium";
	return "low";
}

function isAsk(action: PolicyAction): boolean {
	return action === "approve" || action === "ask";
}

function rankDecision(action: PolicyAction): number {
	if (action === "deny") return 2;
	if (isAsk(action)) return 1;
	return 0;
}

function matchedResult(rule: PolicyRule): CheckResult {
	return {
		decision: rule.action,
		rule: rule.id ?? rule.pattern,
		pattern: rule.pattern,
		riskLevel: rule.riskLevel ?? defaultRiskFor(rule.action),
		reason:
			rule.description ??
			`matched ${rule.kind} rule "${rule.id ?? rule.pattern}"`,
	};
}

function defaultResult(policy: Policy): CheckResult {
	const action = policy.defaultAction ?? "allow";
	return {
		decision: action,
		rule: null,
		pattern: null,
		riskLevel: action === "allow" ? "low" : defaultRiskFor(action),
		reason: `no rule matched — policy default action is "${action}"`,
	};
}

function commandRuleMatches(rule: PolicyRule, command: string): boolean {
	let regex: RegExp | null = null;
	try {
		regex = new RegExp(rule.pattern, "i");
	} catch {
		regex = null;
	}
	if (regex) return regex.test(command);
	return command.toLowerCase().includes(rule.pattern.toLowerCase());
}

function checkCommandRaw(
	command: string,
	policy: Policy,
	options: CheckCommandOptions,
): CheckResult {
	for (const rule of policy.rules) {
		if (rule.kind !== "command") continue;
		if (!commandRuleMatches(rule, command)) continue;
		const result = matchedResult(rule);
		if (isAsk(result.decision) && options.grantedCommands?.includes(command)) {
			return {
				...result,
				decision: "allow",
				reason: `${result.reason} — approval granted for this exact command`,
			};
		}
		return result;
	}
	return defaultResult(policy);
}

/**
 * Evaluate a shell command against a policy. First matching `command` rule
 * wins; with no match the policy's `defaultAction` applies.
 *
 * The raw command plus unwrapped / `$HOME`-expanded / compound-split
 * variants are all scored; the most severe decision wins (deny > ask >
 * allow). This is best-effort pattern defense, not a shell interpreter.
 */
export function checkCommand(
	command: string,
	policy: Policy = DEFAULT_POLICY,
	options: CheckCommandOptions = {},
): CheckResult {
	if (typeof command !== "string" || command.trim() === "") {
		throw new UserError("checkCommand needs a non-empty command string");
	}
	let best = checkCommandRaw(command, policy, options);
	for (const variant of expandCommand(command)) {
		const result = checkCommandRaw(variant, policy, options);
		if (rankDecision(result.decision) > rankDecision(best.decision)) {
			best = result;
		}
		if (best.decision === "deny") return best;
	}
	return best;
}

/**
 * Convert a glob (`**`, `*`, `?`) to an anchored RegExp.
 * `**\/` matches zero or more path segments; `*` never crosses `/`.
 */
export function globToRegExp(glob: string): RegExp {
	let source = "";
	let i = 0;
	while (i < glob.length) {
		const ch = glob[i];
		if (ch === "*") {
			if (glob[i + 1] === "*") {
				if (glob[i + 2] === "/") {
					source += "(?:[^/]*/)*";
					i += 3;
				} else {
					source += ".*";
					i += 2;
				}
			} else {
				source += "[^/]*";
				i += 1;
			}
		} else if (ch === "?") {
			source += "[^/]";
			i += 1;
		} else {
			source += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
			i += 1;
		}
	}
	return new RegExp(`^${source}$`);
}

function normalizePath(path: string): string {
	let p = path.replace(/\\/g, "/");
	while (p.startsWith("./")) {
		p = p.slice(2);
	}
	if (p.length > 1 && p.endsWith("/")) {
		p = p.slice(0, -1);
	}
	return p;
}

function ruleModes(rule: PolicyRule): string[] | null {
	const modes = rule.metadata?.modes;
	if (!Array.isArray(modes)) return null;
	return modes.filter((m): m is string => typeof m === "string");
}

/**
 * Evaluate a file path boundary against a policy. `path` rules match via
 * globs; a rule with `metadata.modes` only applies to the listed modes.
 */
export function checkPath(
	path: string,
	mode: LockMode,
	policy: Policy = DEFAULT_POLICY,
): CheckResult {
	if (typeof path !== "string" || path.trim() === "") {
		throw new UserError("checkPath needs a non-empty path");
	}
	if (mode !== "read" && mode !== "write") {
		throw new UserError(
			`checkPath mode must be "read" or "write", got "${String(mode)}"`,
		);
	}
	const normalized = normalizePath(path);
	for (const rule of policy.rules) {
		if (rule.kind !== "path") continue;
		const modes = ruleModes(rule);
		if (modes !== null && !modes.includes(mode)) continue;
		let regex: RegExp;
		try {
			regex = globToRegExp(rule.pattern);
		} catch {
			continue;
		}
		if (!regex.test(normalized)) continue;
		return matchedResult(rule);
	}
	return defaultResult(policy);
}

/**
 * Structural validation of a parsed policy document.
 * Forward compatible: unknown extra fields are allowed.
 */
export function validatePolicyShape(value: unknown): string[] {
	const problems: string[] = [];
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return ["policy must be a JSON object"];
	}
	const policy = value as Record<string, unknown>;
	if (!Array.isArray(policy.rules)) {
		problems.push('"rules" must be an array');
		return problems;
	}
	if (
		policy.defaultAction !== undefined &&
		(typeof policy.defaultAction !== "string" ||
			!ACTIONS.includes(policy.defaultAction))
	) {
		problems.push(`"defaultAction" must be one of: ${ACTIONS.join(", ")}`);
	}
	policy.rules.forEach((rule: unknown, index: number) => {
		if (typeof rule !== "object" || rule === null) {
			problems.push(`rules[${index}] must be an object`);
			return;
		}
		const r = rule as Record<string, unknown>;
		if (typeof r.kind !== "string" || !KINDS.includes(r.kind)) {
			problems.push(`rules[${index}].kind must be one of: ${KINDS.join(", ")}`);
		}
		if (typeof r.pattern !== "string" || r.pattern === "") {
			problems.push(`rules[${index}].pattern must be a non-empty string`);
		}
		if (typeof r.action !== "string" || !ACTIONS.includes(r.action)) {
			problems.push(
				`rules[${index}].action must be one of: ${ACTIONS.join(", ")}`,
			);
		}
		if (
			r.riskLevel !== undefined &&
			(typeof r.riskLevel !== "string" || !RISKS.includes(r.riskLevel))
		) {
			problems.push(
				`rules[${index}].riskLevel must be one of: ${RISKS.join(", ")}`,
			);
		}
	});
	return problems;
}

/** A loaded policy plus where it came from. */
export interface LoadedPolicy {
	policy: Policy;
	/** "default" for the built-in policy, otherwise the file path. */
	source: string;
}

/**
 * Load `.ruah/policy.json` from `root` (defaults to CWD). Returns the
 * built-in {@link DEFAULT_POLICY} when no file exists. Throws {@link UserError}
 * on malformed JSON or an invalid policy shape.
 */
function resolvePolicyPath(root: string): string | null {
	const preferred = join(root, RUAH_DIR, POLICY_FILE);
	if (existsSync(preferred)) return preferred;
	const legacy = join(root, RUAH_DIR, LEGACY_POLICY_FILE);
	if (existsSync(legacy)) return legacy;
	return null;
}

/**
 * Secret-pattern allowlist from a policy document. Extra field
 * `secrets.allow` (not in the canonical Policy type — tool-local).
 */
export function secretAllowlist(policy: Policy): string[] {
	const extra = policy as Policy & {
		secrets?: { allow?: unknown };
	};
	const fromField = extra.secrets?.allow;
	const fromMeta = policy.metadata?.secretsAllow;
	const raw = Array.isArray(fromField)
		? fromField
		: Array.isArray(fromMeta)
			? fromMeta
			: [];
	return raw.filter(
		(item): item is string => typeof item === "string" && item !== "",
	);
}

export function loadPolicy(root: string = process.cwd()): LoadedPolicy {
	const file = resolvePolicyPath(root);
	if (file === null) {
		return { policy: DEFAULT_POLICY, source: "default" };
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(file, "utf8"));
	} catch (err) {
		throw new UserError(
			`Invalid JSON in ${file}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	const problems = validatePolicyShape(parsed);
	if (problems.length > 0) {
		throw new UserError(
			`Invalid policy file ${file}:\n  - ${problems.join("\n  - ")}`,
		);
	}
	return { policy: parsed as Policy, source: file };
}

/** Write a policy to `.ruah/policy.json` under `root`. */
export function savePolicy(root: string, policy: Policy): string {
	const dir = join(root, RUAH_DIR);
	mkdirSync(dir, { recursive: true });
	const file = join(dir, POLICY_FILE);
	writeFileSync(file, `${JSON.stringify(policy, null, "\t")}\n`, "utf8");
	return file;
}

/**
 * Write a starter `.ruah/policy.json` (a copy of the default policy the
 * user can edit). Refuses to overwrite an existing file unless `force`.
 */
export function initPolicy(
	root: string = process.cwd(),
	force = false,
): string {
	const file = join(root, RUAH_DIR, POLICY_FILE);
	if (existsSync(file) && !force) {
		throw new UserError(`${file} already exists — pass --force to overwrite`);
	}
	const starter: Policy = {
		...DEFAULT_POLICY,
		name: "project-policy",
		metadata: { generatedBy: "ruah-guard init" },
	};
	return savePolicy(root, starter);
}
