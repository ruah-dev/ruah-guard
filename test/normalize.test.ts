import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	expandCommand,
	expandHome,
	extractShellDashC,
	splitCompounds,
	unwrapWrappers,
} from "../src/index.js";

describe("splitCompounds", () => {
	it("splits on ; && || and newlines, not inside quotes", () => {
		assert.deepEqual(splitCompounds("ls; rm -rf /"), ["ls", "rm -rf /"]);
		assert.deepEqual(splitCompounds("true && rm -rf /"), ["true", "rm -rf /"]);
		assert.deepEqual(splitCompounds("echo 'a; b'"), ["echo 'a; b'"]);
	});
});

describe("expandHome / unwrap / bash -c", () => {
	it("rewrites HOME env forms to ~", () => {
		assert.equal(expandHome("rm -rf $HOME"), "rm -rf ~");
		assert.equal(expandHome("rm -rf " + "$" + "{HOME}/x"), "rm -rf ~/x");
	});

	it("strips sudo / command / env wrappers", () => {
		assert.equal(unwrapWrappers("sudo rm -rf /"), "rm -rf /");
		assert.equal(unwrapWrappers("command rm -rf /"), "rm -rf /");
		assert.equal(unwrapWrappers("env FOO=1 rm -rf /"), "rm -rf /");
	});

	it("extracts bash -c payloads", () => {
		assert.equal(extractShellDashC('bash -c "rm -rf /"'), "rm -rf /");
		assert.equal(extractShellDashC("sh -c 'rm -rf ~'"), "rm -rf ~");
	});

	it("expandCommand is stable and includes the original", () => {
		const once = expandCommand('bash -c "rm -rf $HOME"');
		const twice = expandCommand('bash -c "rm -rf $HOME"');
		assert.deepEqual(once, twice);
		assert.ok(once.includes('bash -c "rm -rf $HOME"'));
		assert.ok(once.includes("rm -rf ~") || once.includes("rm -rf $HOME"));
	});
});
