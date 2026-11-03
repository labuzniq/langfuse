import { findInCauseChain } from "../errors";

export type OAuth2TokenErrorKind =
  | "config"
  | "credential"
  | "disabled"
  | "unavailable";

/**
 * A deterministic failure in the OAuth2 client-credentials token path:
 * resolving a provider profile, checking the token endpoint allowlist, or
 * requesting/parsing a token. `kind` drives how callers classify and react
 * to the failure (evaluator block reason, queue retry behavior, etc.).
 */
export class OAuth2TokenError extends Error {
  readonly kind: OAuth2TokenErrorKind;
  readonly status?: number;

  constructor(
    kind: OAuth2TokenErrorKind,
    message: string,
    opts?: { status?: number; cause?: unknown },
  ) {
    super(message, { cause: opts?.cause });
    this.name = "OAuth2TokenError";
    this.kind = kind;
    this.status = opts?.status;
  }
}

/**
 * Walks an error's `.cause` chain looking for an `OAuth2TokenError`, so
 * callers can classify a failure that provider SDKs or retry wrappers have
 * re-wrapped. Cycle-safe: a chain that loops back on itself returns
 * `undefined` instead of looping forever.
 */
export function findOAuth2TokenError(
  error: unknown,
): OAuth2TokenError | undefined {
  return findInCauseChain(
    error,
    (candidate): candidate is OAuth2TokenError =>
      candidate instanceof OAuth2TokenError,
  );
}
