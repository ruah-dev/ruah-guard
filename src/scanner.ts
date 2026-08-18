/**
 * Viral secrets scanner — pattern detectors plus a Shannon-entropy fallback.
 *
 * Detects: Stripe / Anthropic / AWS / GitHub keys, private key blocks,
 * password assignments, bearer tokens, JWTs, `.env` files with real values,
 * and generic high-entropy strings. Findings carry `file:line:column`, a
 * severity (`RiskLevel` from `@ruah-dev/schema`), and a masked excerpt —
 * raw secret values are never emitted.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import type { PolicyRule, RiskLevel } from "@ruah-dev/schema";
import { UserError } from "./errors.js";
import { globToRegExp } from "./policy.js";

/** One secret (or suspected secret) found by the scanner. */
export interface Finding {
	/** Detector id, e.g. "stripe-live-key" or "high-entropy". */
	detector: string;
	/** Severity of the finding. */
	severity: RiskLevel;
	/** File the finding was made in (relative to the scan root) or "<text>". */
	file: string;
	/** 1-based line number. */
	line: number;
	/** 1-based column of the match start. */
	column: number;
	/** Masked excerpt — never the raw secret. */
	excerpt: string;
	/** Human-readable description. */
	message: string;
}

/** Options for {@link scanText}. */
export interface ScanTextOptions {
	/** File label attached to findings (default "<text>"). */
	file?: string;
	/** Shannon entropy threshold for the high-entropy detector (default 4.5). */
	entropyThreshold?: number;
	/** Extra `secret` rules from a policy — each pattern becomes a detector. */
	customRules?: PolicyRule[];
	/**
	 * Allowlist of regex sources (or literal substrings). A finding whose
	 * raw match or excerpt matches any entry is dropped. False-positive hatch.
	 */
	allow?: string[];
}

/** Options for {@link scanDir} / {@link scanFiles}. */
export interface ScanOptions extends ScanTextOptions {
	/** Extra .gitignore-style exclude patterns. */
	exclude?: string[];
	/** Files larger than this many bytes are skipped (default 1 MB). */
	maxFileSize?: number;
}

/** Result of a directory or file-list scan. */
export interface ScanResult {
	findings: Finding[];
	filesScanned: number;
	filesSkipped: number;
}

/** Numeric ordering of risk levels, lowest first. */
export const SEVERITY_ORDER: Record<RiskLevel, number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

/** True when `severity` is at or above `min`. */
export function severityAtLeast(severity: RiskLevel, min: RiskLevel): boolean {
	return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min];
}

/** Shannon entropy (bits per character) of a string. */
export function shannonEntropy(value: string): number {
	if (value.length === 0) return 0;
	const counts = new Map<string, number>();
	for (const ch of value) {
		counts.set(ch, (counts.get(ch) ?? 0) + 1);
	}
	let entropy = 0;
	for (const count of counts.values()) {
		const p = count / value.length;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

const KNOWN_PREFIXES = [
	"sk_live_",
	"sk_test_",
	"sk-ant-",
	"ghp_",
	"gho_",
	"ghu_",
	"ghs_",
	"ghr_",
	"AKIA",
	"github_pat_",
] as const;

/** Mask a secret for safe display: known prefix + bullets, never the value. */
export function maskSecret(value: string): string {
	for (const prefix of KNOWN_PREFIXES) {
		if (value.startsWith(prefix)) return `${prefix}••••`;
	}
	if (value.length <= 8) return "•".repeat(value.length);
	return `${value.slice(0, 4)}••••`;
}

function isAllowed(raw: string, allow: string[] | undefined): boolean {
	if (!allow || allow.length === 0) return false;
	for (const pattern of allow) {
		try {
			if (new RegExp(pattern).test(raw)) return true;
		} catch {
			if (raw.includes(pattern)) return true;
		}
	}
	return false;
}

const DEFAULT_ENTROPY_THRESHOLD = 4.5;
const DEFAULT_MAX_FILE_SIZE = 1_000_000;

interface Detector {
	id: string;
	severity: RiskLevel;
	regex: RegExp;
	message: string;
	accept?: (match: string) => boolean;
}

const DETECTORS: Detector[] = [
	{
		id: "stripe-live-key",
		severity: "critical",
		regex: /sk_live_[A-Za-z0-9]{8,}/g,
		message: "Stripe live secret key",
	},
	{
		id: "stripe-test-key",
		severity: "medium",
		regex: /sk_test_[A-Za-z0-9]{8,}/g,
		message: "Stripe test secret key",
	},
	{
		id: "anthropic-key",
		severity: "critical",
		regex: /sk-ant-[A-Za-z0-9_-]{8,}/g,
		message: "Anthropic API key",
	},
	{
		id: "aws-access-key-id",
		severity: "high",
		regex: /\bAKIA[A-Z0-9]{16}\b/g,
		message: "AWS access key id",
	},
	{
		id: "aws-secret-key",
		severity: "critical",
		regex:
			/aws.{0,25}(secret|private).{0,25}[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
		message: "AWS secret access key",
	},
	{
		id: "github-token",
		severity: "critical",
		regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g,
		message: "GitHub token",
	},
	{
		id: "github-pat",
		severity: "critical",
		regex: /github_pat_[A-Za-z0-9_]{22,}/g,
		message: "GitHub fine-grained personal access token",
	},
	{
		id: "private-key",
		severity: "critical",
		regex:
			/-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/g,
		message: "Private key material",
	},
	{
		id: "jwt",
		severity: "high",
		regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g,
		message: "JSON Web Token",
	},
	{
		id: "bearer-token",
		severity: "high",
		regex: /\bbearer\s+[A-Za-z0-9._~+/=-]{20,}/gi,
		message: "Bearer token",
	},
	{
		id: "password-assignment",
		severity: "medium",
		regex: /\b(password|passwd|pwd)\b\s*[=:]\s*["']?[^\s"']{4,}/gi,
		message: "Hardcoded password",
		accept: (match) => !/[=:]\s*["']?[$<{%]/.test(match),
	},
];

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildDetectors(customRules: PolicyRule[] | undefined): Detector[] {
	const detectors = DETECTORS.map((d) => ({
		...d,
		regex: new RegExp(d.regex.source, d.regex.flags),
	}));
	for (const rule of customRules ?? []) {
		if (rule.kind !== "secret") continue;
		let regex: RegExp;
		try {
			regex = new RegExp(rule.pattern, "g");
		} catch {
			regex = new RegExp(escapeRegExp(rule.pattern), "g");
		}
		detectors.push({
			id: rule.id ?? `policy:${rule.pattern.slice(0, 40)}`,
			severity: rule.riskLevel ?? "high",
			regex,
			message: rule.description ?? "Matched custom policy secret pattern",
		});
	}
	return detectors;
}

function overlaps(
	taken: Array<[number, number]>,
	start: number,
	end: number,
): boolean {
	for (const [s, e] of taken) {
		if (start < e && end > s) return true;
	}
	return false;
}

/**
 * Scan a string for secrets. Pattern detectors run first, then a
 * Shannon-entropy pass over long tokens that no detector claimed.
 */
export function scanText(
	text: string,
	options: ScanTextOptions = {},
): Finding[] {
	const file = options.file ?? "<text>";
	const threshold = options.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
	const detectors = buildDetectors(options.customRules);
	const findings: Finding[] = [];
	const lines = text.split(/\r?\n/);

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const taken: Array<[number, number]> = [];

		for (const detector of detectors) {
			detector.regex.lastIndex = 0;
			for (
				let m = detector.regex.exec(line);
				m !== null;
				m = detector.regex.exec(line)
			) {
				if (m[0].length === 0) break;
				const start = m.index;
				const end = start + m[0].length;
				if (overlaps(taken, start, end)) continue;
				if (detector.accept && !detector.accept(m[0])) continue;
				if (isAllowed(m[0], options.allow)) continue;
				taken.push([start, end]);
				findings.push({
					detector: detector.id,
					severity: detector.severity,
					file,
					line: i + 1,
					column: start + 1,
					excerpt: maskSecret(m[0]),
					message: detector.message,
				});
			}
		}

		const tokenRegex = /[A-Za-z0-9+=_-]{21,}/g;
		for (let t = tokenRegex.exec(line); t !== null; t = tokenRegex.exec(line)) {
			const token = t[0];
			const start = t.index;
			const end = start + token.length;
			if (overlaps(taken, start, end)) continue;
			if (!/[0-9]/.test(token)) continue;
			if (/^[0-9a-f]+$/i.test(token)) continue;
			const entropy = shannonEntropy(token);
			if (entropy < threshold) continue;
			if (isAllowed(token, options.allow)) continue;
			taken.push([start, end]);
			findings.push({
				detector: "high-entropy",
				severity: "medium",
				file,
				line: i + 1,
				column: start + 1,
				excerpt: maskSecret(token),
				message: `High-entropy string (entropy ${entropy.toFixed(2)})`,
			});
		}
	}
	return findings;
}

const ENV_BASENAME = /^\.env(\..+)?$/;
const ENV_SKIP = /\.(example|sample|template|dist|defaults)$/i;

function isEnvFile(name: string): boolean {
	return ENV_BASENAME.test(name) && !ENV_SKIP.test(name);
}

function scanEnvLines(text: string, file: string): Finding[] {
	const findings: Finding[] = [];
	const lines = text.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (line.trimStart().startsWith("#")) continue;
		const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(
			line,
		);
		if (!m) continue;
		const value = m[2].trim().replace(/^["']|["']$/g, "");
		if (value === "") continue;
		findings.push({
			detector: "env-file-value",
			severity: "high",
			file,
			line: i + 1,
			column: 1,
			excerpt: `${m[1]}=${maskSecret(value)}`,
			message: "Real value committed in .env file",
		});
	}
	return findings;
}

const ALWAYS_SKIP_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"dist-test",
	".ruah",
	".hg",
	".svn",
	"coverage",
	"__pycache__",
	".venv",
	"venv",
]);

const DEFAULT_FILE_EXCLUDES = [
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"bun.lockb",
	"*.min.js",
	"*.map",
	"*.lock",
];

interface IgnoreRule {
	regex: RegExp;
	baseNameOnly: boolean;
	dirOnly: boolean;
}

function toIgnoreRule(pattern: string): IgnoreRule | null {
	let p = pattern;
	let dirOnly = false;
	if (p.endsWith("/")) {
		dirOnly = true;
		p = p.slice(0, -1);
	}
	if (p.startsWith("/")) {
		p = p.slice(1);
	}
	if (p === "") return null;
	const baseNameOnly = !p.includes("/");
	try {
		return { regex: globToRegExp(p), baseNameOnly, dirOnly };
	} catch {
		return null;
	}
}

function buildIgnoreRules(root: string, extra: string[]): IgnoreRule[] {
	const patterns: string[] = [...DEFAULT_FILE_EXCLUDES, ...extra];
	const gitignore = join(root, ".gitignore");
	if (existsSync(gitignore)) {
		for (const rawLine of readFileSync(gitignore, "utf8").split(/\r?\n/)) {
			const line = rawLine.trim();
			if (line === "" || line.startsWith("#") || line.startsWith("!")) continue;
			patterns.push(line);
		}
	}
	const rules: IgnoreRule[] = [];
	for (const pattern of patterns) {
		const rule = toIgnoreRule(pattern);
		if (rule) rules.push(rule);
	}
	return rules;
}

function isIgnored(
	rules: IgnoreRule[],
	relPath: string,
	isDir: boolean,
): boolean {
	const base = basename(relPath);
	for (const rule of rules) {
		if (rule.dirOnly && !isDir) continue;
		const subject = rule.baseNameOnly ? base : relPath;
		if (rule.regex.test(subject)) return true;
	}
	return false;
}

function scanFile(
	absPath: string,
	relPath: string,
	options: ScanOptions,
): Finding[] | null {
	const stat = statSync(absPath);
	if (stat.size > (options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE)) return null;
	const buffer = readFileSync(absPath);
	if (buffer.subarray(0, 8192).includes(0)) return null;
	const text = buffer.toString("utf8");
	const findings = scanText(text, { ...options, file: relPath });
	if (isEnvFile(basename(relPath))) {
		findings.push(...scanEnvLines(text, relPath));
	}
	return findings;
}

/**
 * Recursively scan a directory for secrets. Always skips `node_modules`,
 * `.git`, `dist`, `dist-test`, `.ruah`, and lockfiles; honors simple
 * `.gitignore` patterns from the scan root plus `options.exclude`.
 */
export function scanDir(dir: string, options: ScanOptions = {}): ScanResult {
	const root = resolve(dir);
	if (!existsSync(root)) {
		throw new UserError(`Directory not found: ${dir}`);
	}
	if (!statSync(root).isDirectory()) {
		throw new UserError(`Not a directory: ${dir}`);
	}
	const rules = buildIgnoreRules(root, options.exclude ?? []);
	const findings: Finding[] = [];
	let filesScanned = 0;
	let filesSkipped = 0;

	const walk = (current: string): void => {
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			const abs = join(current, entry.name);
			const rel = relative(root, abs).split("\\").join("/");
			if (entry.isSymbolicLink()) {
				filesSkipped++;
				continue;
			}
			if (entry.isDirectory()) {
				if (ALWAYS_SKIP_DIRS.has(entry.name) || isIgnored(rules, rel, true))
					continue;
				walk(abs);
				continue;
			}
			if (!entry.isFile()) continue;
			if (isIgnored(rules, rel, false)) {
				filesSkipped++;
				continue;
			}
			const result = scanFile(abs, rel, options);
			if (result === null) {
				filesSkipped++;
				continue;
			}
			filesScanned++;
			findings.push(...result);
		}
	};
	walk(root);
	return { findings, filesScanned, filesSkipped };
}

/** Scan an explicit list of files (paths relative to `root`). */
export function scanFiles(
	root: string,
	relPaths: string[],
	options: ScanOptions = {},
): ScanResult {
	const rootAbs = resolve(root);
	const findings: Finding[] = [];
	let filesScanned = 0;
	let filesSkipped = 0;
	for (const rel of relPaths) {
		const abs = join(rootAbs, rel);
		if (!existsSync(abs) || !statSync(abs).isFile()) {
			filesSkipped++;
			continue;
		}
		const result = scanFile(abs, rel.split("\\").join("/"), options);
		if (result === null) {
			filesSkipped++;
			continue;
		}
		filesScanned++;
		findings.push(...result);
	}
	return { findings, filesScanned, filesSkipped };
}

/**
 * List files staged in git (added/copied/modified/renamed). Used by
 * `ruah-guard scan --staged`. Throws {@link UserError} outside a git repo.
 */
export function listStagedFiles(cwd: string): string[] {
	try {
		const output = execFileSync(
			"git",
			["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
			{ cwd, encoding: "utf8" },
		);
		return output
			.split("\n")
			.map((l) => l.trim())
			.filter((l) => l !== "");
	} catch {
		throw new UserError(
			"--staged requires git and a git repository in the current directory",
		);
	}
}
