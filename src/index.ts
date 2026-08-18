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

export {
	APPROVALS_FILE,
	denyApproval,
	grantApproval,
	grantedCommands,
	listApprovals,
	loadApprovals,
	requestApproval,
} from "./approvals.js";
export type { ApprovalRequest, ApprovalStatus } from "./approvals.js";
export { appendAudit, AUDIT_FILE, readAudit, resolveActor } from "./audit.js";
export type { AuditEntry } from "./audit.js";
export { UserError } from "./errors.js";
export {
	checkCommand,
	checkPath,
	DEFAULT_POLICY,
	globToRegExp,
	initPolicy,
	loadPolicy,
	POLICY_FILE,
	RUAH_DIR,
	savePolicy,
	validatePolicyShape,
} from "./policy.js";
export type { CheckCommandOptions, CheckResult, LoadedPolicy } from "./policy.js";
export {
	listStagedFiles,
	maskSecret,
	scanDir,
	scanFiles,
	scanText,
	SEVERITY_ORDER,
	severityAtLeast,
	shannonEntropy,
} from "./scanner.js";
export type { Finding, ScanOptions, ScanResult, ScanTextOptions } from "./scanner.js";
export { VERSION } from "./version.js";
