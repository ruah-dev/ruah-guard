import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
	maskSecret,
	scanDir,
	scanFiles,
	scanText,
	severityAtLeast,
	shannonEntropy,
	UserError,
} from "../src/index.js";

// Fixture builders. Every value is OBVIOUSLY FAKE and assembled at runtime
// so that repo-level secret hooks (and ruah-guard itself) never see a
// complete secret-shaped literal in this source file.
const SK_LIVE = ["sk", "live", "FAKE1234567890abcdef"].join("_");
const SK_LIVE_2 = ["sk", "live", "FAKE0987654321"].join("_");
const SK_TEST = ["sk", "test", "FAKE1234567890"].join("_");
const SK_ANT = ["sk", "ant", "api03-FAKEFAKEFAKE"].join("-");
const AKIA_KEY = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
const AWS_SECRET_LINE = `${["aws", "secret", "access_key"].join("_")} = ${"wJalrXUtnFEMI/K7MDENG/bPxRfiCY"}${"EXAMPLEKEY"}`;
const GHP_TOKEN = ["gh", `p_${"FAKE".repeat(9)}`].join("");
const GHO_TOKEN = ["gh", `o_${"FAKE".repeat(9)}`].join("");
const GH_PAT = ["github", "pat", "11AAAAAA0FAKEFAKEFAKEFAKEFAKE"].join("_");
const RSA_HEADER = ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" ");
const EC_HEADER = ["-----BEGIN EC", "PRIVATE KEY-----"].join(" ");
const OPENSSH_HEADER = ["-----BEGIN OPENSSH", "PRIVATE KEY-----"].join(" ");
const PASSWORD_LINE = ["pass", "word=hunter22secret"].join("");
const PASSWD_LINE = ["pass", "wd: 'changeme123'"].join("");
const PASSWORD_TEMPLATED = ["pass", "word=${DB_PASSWORD}"].join("");
const FAKE_JWT = [
	"eyJhbGciOiJIUzI1NiJ9",
	"eyJzdWIiOiIxMjM0NTY3ODkwIn0",
	"FAKESIGFAKESIGFAKE",
].join(".");
const HIGH_ENTROPY = "Zx9kQ2mW8vL5tR7nB4cF6hJ3pYqA1sD0eGuT";

function detectorsOf(text: string): string[] {
	return scanText(text).map((f) => f.detector);
}

describe("scanText — secret classes", () => {
	it("catches Stripe live keys at critical severity, masked", () => {
		const findings = scanText(`const k = "${SK_LIVE}";`);
		assert.equal(findings.length, 1);
		assert.equal(findings[0].detector, "stripe-live-key");
		assert.equal(findings[0].severity, "critical");
		assert.ok(findings[0].excerpt.startsWith("sk_live_"));
		assert.ok(findings[0].excerpt.includes("••••"));
		assert.ok(!findings[0].excerpt.includes("FAKE1234567890abcdef"));
	});

	it("catches Stripe test keys at medium severity", () => {
		const findings = scanText(SK_TEST);
		assert.equal(findings[0].detector, "stripe-test-key");
		assert.equal(findings[0].severity, "medium");
	});

	it("catches Anthropic keys", () => {
		assert.ok(detectorsOf(`key: ${SK_ANT}`).includes("anthropic-key"));
	});

	it("catches AWS access key ids", () => {
		assert.ok(detectorsOf(AKIA_KEY).includes("aws-access-key-id"));
	});

	it("catches AWS secret key assignments", () => {
		assert.ok(detectorsOf(AWS_SECRET_LINE).includes("aws-secret-key"));
	});

	it("catches GitHub tokens and fine-grained PATs", () => {
		assert.ok(detectorsOf(`token = "${GHP_TOKEN}"`).includes("github-token"));
		assert.ok(detectorsOf(`token = "${GHO_TOKEN}"`).includes("github-token"));
		assert.ok(detectorsOf(GH_PAT).includes("github-pat"));
	});

	it("catches private key blocks (RSA, EC, OPENSSH)", () => {
		const text = [RSA_HEADER, EC_HEADER, OPENSSH_HEADER].join("\n");
		const findings = scanText(text).filter((f) => f.detector === "private-key");
		assert.equal(findings.length, 3);
		assert.equal(findings[0].severity, "critical");
	});

	it("catches password assignments but skips templated values", () => {
		assert.ok(detectorsOf(PASSWORD_LINE).includes("password-assignment"));
		assert.ok(detectorsOf(PASSWD_LINE).includes("password-assignment"));
		assert.equal(detectorsOf(PASSWORD_TEMPLATED).length, 0);
	});

	it("catches bearer tokens", () => {
		const text = "Authorization: Bearer FAKETOKENFAKETOKENFAKETOKEN12";
		assert.ok(detectorsOf(text).includes("bearer-token"));
	});

	it("catches JWTs", () => {
		assert.ok(detectorsOf(`token=${FAKE_JWT}`).includes("jwt"));
	});

	it("reports correct line numbers", () => {
		const findings = scanText(`ok\nok\n${SK_LIVE}`);
		assert.equal(findings[0].line, 3);
	});

	it("allowlist drops matching findings (false-positive hatch)", () => {
		const findings = scanText(`const k = "${SK_LIVE}";`, {
			allow: ["sk_live_FAKE"],
		});
		assert.equal(findings.length, 0);
	});

	it("supports custom secret rules from a policy", () => {
		const findings = scanText("token INTERNAL_TOKEN_123456", {
			customRules: [
				{
					kind: "secret",
					pattern: "INTERNAL_TOKEN_[0-9]{6}",
					action: "deny",
					riskLevel: "critical",
					id: "internal-token",
				},
			],
		});
		assert.equal(findings.length, 1);
		assert.equal(findings[0].detector, "internal-token");
		assert.equal(findings[0].severity, "critical");
	});
});

describe("scanText — entropy detector", () => {
	it("flags high-entropy strings", () => {
		const findings = scanText(`secret = "${HIGH_ENTROPY}"`);
		assert.equal(findings.length, 1);
		assert.equal(findings[0].detector, "high-entropy");
	});

	it("ignores ordinary long identifiers", () => {
		assert.equal(
			scanText("export const LONG_CONSTANT_NAME_FOR_THINGS = 1").length,
			0,
		);
	});

	it("ignores hex digests like git SHAs", () => {
		assert.equal(
			scanText('sha = "3b18e512dba79e4c8300dd08aeb37f8e728b8dad"').length,
			0,
		);
	});

	it("honors a custom entropy threshold", () => {
		assert.equal(
			scanText(`secret = "${HIGH_ENTROPY}"`, { entropyThreshold: 99 }).length,
			0,
		);
	});
});

describe("entropy / masking / severity helpers", () => {
	it("shannonEntropy is 0 for uniform strings and 1 for a fair pair", () => {
		assert.equal(shannonEntropy("aaaa"), 0);
		assert.equal(shannonEntropy("ab"), 1);
	});

	it("maskSecret hides the middle", () => {
		assert.equal(maskSecret("short"), "•••••");
		const masked = maskSecret(SK_LIVE);
		assert.equal(masked, "sk_live_••••");
		assert.ok(!masked.includes("FAKE1234567890"));
	});

	it("severityAtLeast orders risk levels", () => {
		assert.equal(severityAtLeast("critical", "high"), true);
		assert.equal(severityAtLeast("high", "high"), true);
		assert.equal(severityAtLeast("medium", "high"), false);
	});
});

describe("scanDir", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "ruah-guard-scan-"));
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	function write(rel: string, content: string): void {
		const abs = join(root, rel);
		mkdirSync(dirname(abs), { recursive: true });
		writeFileSync(abs, content);
	}

	it("finds secrets with file and line", () => {
		write("src/app.js", `const a = 1;\nconst k = "${SK_LIVE}";\n`);
		const result = scanDir(root);
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].file, "src/app.js");
		assert.equal(result.findings[0].line, 2);
	});

	it("always skips node_modules, dist, and .git", () => {
		write("node_modules/evil.js", SK_LIVE);
		write("dist/out.js", SK_LIVE);
		write(".git/config", SK_LIVE);
		const result = scanDir(root);
		assert.equal(result.findings.length, 0);
	});

	it("honors .gitignore patterns from the scan root", () => {
		write(".gitignore", "secrets.txt\nvendor/\n");
		write("secrets.txt", SK_LIVE);
		write("vendor/lib.js", SK_LIVE);
		write("src/ok.js", "const fine = true;");
		const result = scanDir(root);
		assert.equal(result.findings.length, 0);
		assert.ok(result.filesSkipped >= 1);
	});

	it("flags real values in .env files but not .env.example", () => {
		write(".env", "API_KEY=realvalue123\n# comment\nEMPTY=\n");
		write(".env.example", "API_KEY=somevalue123\n");
		const result = scanDir(root);
		const envFindings = result.findings.filter(
			(f) => f.detector === "env-file-value",
		);
		assert.equal(envFindings.length, 1);
		assert.equal(envFindings[0].file, ".env");
		assert.ok(!envFindings[0].excerpt.includes("realvalue123"));
	});

	it("skips binary files", () => {
		const binary = Buffer.concat([
			Buffer.from([0, 1, 2, 0]),
			Buffer.from(SK_LIVE),
		]);
		writeFileSync(join(root, "blob.bin"), binary);
		const result = scanDir(root);
		assert.equal(result.findings.length, 0);
		assert.ok(result.filesSkipped >= 1);
	});

	it("throws UserError for a missing directory", () => {
		assert.throws(() => scanDir(join(root, "does-not-exist")), UserError);
	});

	it("scanFiles scans only the listed files", () => {
		write("a.js", SK_LIVE);
		write("b.js", SK_LIVE_2);
		const result = scanFiles(root, ["a.js"]);
		assert.equal(result.findings.length, 1);
		assert.equal(result.findings[0].file, "a.js");
	});
});
