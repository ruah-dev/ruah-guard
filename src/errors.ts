/**
 * Error types for ruah-guard.
 *
 * `UserError` marks problems the user can fix (bad flags, malformed files,
 * unknown ids). The CLI maps it to exit code 1; anything else exits 2.
 */
export class UserError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "UserError";
	}
}
