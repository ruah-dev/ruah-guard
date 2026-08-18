/**
 * @ruah-dev/guard — policy engine for agent safety.
 *
 * Library API (all functions are pure or touch only `.ruah/` under the
 * given root):
 * - `checkCommand(cmd, policy?)` / `checkPath(path, mode, policy?)` —
 *   evaluate against an ordered rule set (canonical `Policy` type from
 *   `@ruah-dev/schema`); returns `{ decision, rule, riskLevel, reason }`
 * - `scanText` / `scanDir` / `scanFiles` — secrets scanner with masked
 *   excerpts and Shannon-entropy fallback
 * - `requestApproval` / `grantApproval` / `denyApproval` / `listApprovals` —
 *   human-in-the-loop queue at `.ruah/approvals.json`
 * - `appendAudit` / `readAudit` — append-only log at `.ruah/audit.jsonl`
 */

export type { ApprovalRequest, ApprovalStatus } from "./approvals.js";
export {
	APPROVALS_FILE,
	denyApproval,
	grantApproval,
	grantedCommands,
	listApprovals,
	loadApprovals,
	requestApproval,
} from "./approvals.js";
export type { AuditEntry, AuditStats } from "./audit.js";
export {
	AUDIT_FILE,
	appendAudit,
	auditStats,
	LEGACY_AUDIT_FILE,
	readAudit,
	resolveActor,
} from "./audit.js";
export { UserError } from "./errors.js";
export type { HookEvent, HookResult, Verdict } from "./hook.js";
export {
	claudeCodeHookConfig,
	evaluateHookEvent,
	failClosedVerdict,
	failOpenVerdict,
	hookResult,
	parseHookEvent,
	toVerdict,
	VERDICT_SCHEMA_VERSION,
} from "./hook.js";
export {
	expandCommand,
	expandHome,
	extractShellDashC,
	splitCompounds,
	unwrapWrappers,
} from "./normalize.js";
export type {
	CheckCommandOptions,
	CheckResult,
	LoadedPolicy,
} from "./policy.js";
export {
	checkCommand,
	checkPath,
	DEFAULT_POLICY,
	globToRegExp,
	initPolicy,
	LEGACY_POLICY_FILE,
	loadPolicy,
	POLICY_FILE,
	RUAH_DIR,
	savePolicy,
	secretAllowlist,
	validatePolicyShape,
} from "./policy.js";
export type {
	Finding,
	ScanOptions,
	ScanResult,
	ScanTextOptions,
} from "./scanner.js";
export {
	listStagedFiles,
	maskSecret,
	SEVERITY_ORDER,
	scanDir,
	scanFiles,
	scanText,
	severityAtLeast,
	shannonEntropy,
} from "./scanner.js";
export { VERSION } from "./version.js";
