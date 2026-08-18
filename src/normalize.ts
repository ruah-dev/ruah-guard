/**
 * Best-effort command expansion for policy matching.
 *
 * This is NOT a shell parser. It unwraps the wrappers agents actually use
 * (`sudo`, `command`, `bash -c`, `$HOME`, `;` / `&&` chains) so the same
 * denial fires. Full shell grammar, eval of variables other than HOME, and
 * encoding tricks beyond the `base64 -d | sh` heuristic are out of scope.
 */

/** Split on `;` `&&` `||` and newlines, ignoring those inside quotes. */
export function splitCompounds(command: string): string[] {
	const parts: string[] = [];
	let current = "";
	let quote: "'" | '"' | null = null;
	let i = 0;
	while (i < command.length) {
		const ch = command[i];
		if (quote) {
			if (ch === quote) quote = null;
			current += ch;
			i++;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			current += ch;
			i++;
			continue;
		}
		if (ch === "\n" || ch === "\r") {
			if (current.trim()) parts.push(current.trim());
			current = "";
			i++;
			continue;
		}
		if (ch === ";") {
			if (current.trim()) parts.push(current.trim());
			current = "";
			i++;
			continue;
		}
		if (ch === "&" && command[i + 1] === "&") {
			if (current.trim()) parts.push(current.trim());
			current = "";
			i += 2;
			continue;
		}
		if (ch === "|" && command[i + 1] === "|") {
			if (current.trim()) parts.push(current.trim());
			current = "";
			i += 2;
			continue;
		}
		current += ch;
		i++;
	}
	if (current.trim()) parts.push(current.trim());
	return parts.length > 0 ? parts : [command.trim()].filter(Boolean);
}

/** Replace `$HOME` / `${HOME}` / `~` user-home forms used as path targets. */
export function expandHome(command: string): string {
	return command
		.replace(/\$\{HOME\}/g, "~")
		.replace(/\$HOME\b/g, "~")
		.replace(/~[A-Za-z_][A-Za-z0-9_-]*/g, "~");
}

const WRAPPER =
	/^(?:sudo(?:\s+-[nEe]+)*|command(?:\s+-p)?|env(?:\s+[A-Za-z_][A-Za-z0-9_]*=\S+)*)\s+/;

/** Strip leading sudo / command / env VAR= wrappers. */
export function unwrapWrappers(command: string): string {
	let current = command.trim();
	for (let n = 0; n < 4; n++) {
		const next = current.replace(WRAPPER, "");
		if (next === current) break;
		current = next.trim();
	}
	return current;
}

/**
 * Extract the script passed to `bash -c` / `sh -c` / `zsh -c` / `eval`.
 * Returns null when the command is not that shape.
 */
export function extractShellDashC(command: string): string | null {
	const dashC =
		/(?:^|[\s;|&])(?:\S*\/)?(?:ba|z)?sh\s+(?:-[^\s]*\s+)*-c\s+(?:(['"])([\s\S]*?)\1|(\S+))/i.exec(
			command,
		);
	if (dashC) {
		return (dashC[2] ?? dashC[3] ?? "").trim() || null;
	}
	const evalMatch = /(?:^|[\s;|&])eval\s+(?:(['"])([\s\S]*?)\1|(\S+))/i.exec(
		command,
	);
	if (evalMatch) {
		return (evalMatch[2] ?? evalMatch[3] ?? "").trim() || null;
	}
	return null;
}

/**
 * Produce every surface form the policy engine should test. Always includes
 * the original command. Order is stable (insertion order).
 */
export function expandCommand(command: string): string[] {
	const seen = new Set<string>();
	const out: string[] = [];

	const add = (value: string): void => {
		const trimmed = value.trim();
		if (trimmed === "" || seen.has(trimmed)) return;
		seen.add(trimmed);
		out.push(trimmed);
	};

	add(command);
	add(expandHome(command));

	for (const segment of splitCompounds(command)) {
		add(segment);
		add(expandHome(segment));
		const unwrapped = unwrapWrappers(segment);
		add(unwrapped);
		add(expandHome(unwrapped));
		const inner = extractShellDashC(segment) ?? extractShellDashC(unwrapped);
		if (inner) {
			add(inner);
			add(expandHome(inner));
			add(unwrapWrappers(inner));
			add(expandHome(unwrapWrappers(inner)));
			for (const nested of splitCompounds(inner)) {
				add(nested);
				add(expandHome(nested));
				add(unwrapWrappers(nested));
			}
		}
	}

	return out;
}
