import { createHash } from "node:crypto";
import { LRUCache } from "lru-cache";
import { env } from "../../../env";
import type { ResolvedOAuth2Profile } from "../../../interfaces/oauth2Providers";
import { logger } from "../../logger";
import type { PreparedOAuth2Credential } from "./credential";
import { OAuth2TokenError } from "./errors";
import { requestOAuth2Token } from "./tokenRequest";

const MAX_CACHED_TOKENS = 1_000;
const REFRESH_MARGIN_SECONDS = 60;
const FAIL_FAST_WINDOW_MS = 30_000;

type CachedToken = { accessToken: string; ttlMs: number };

type FetchContext = {
  profile: ResolvedOAuth2Profile;
  credential: PreparedOAuth2Credential;
  projectId?: string;
};

// Normalized token endpoint -> epoch ms until which fetches fail at once.
const unavailableUntil = new Map<string, number>();

const tokenCache = new LRUCache<string, CachedToken, FetchContext>({
  max: MAX_CACHED_TOKENS,
  // Token lifetimes are wall-clock time, like the fail-fast window.
  perf: { now: () => Date.now() },
  // Invalidating a key while its fetch is in flight drops the entry but still
  // hands the fetched token to the callers waiting on it.
  ignoreFetchAbort: true,
  fetchMethod: async (_key, _stale, { options, context }) => {
    const token = await fetchToken(context);
    options.ttl = token.ttlMs;
    return token;
  },
});

/**
 * SHA-256 over everything that shapes the token request plus the hash of the
 * secret, so two connections share a token only when they hold the same
 * credential. Contains no secret, client id or other raw value.
 */
export function getOAuth2CacheKey(
  profile: ResolvedOAuth2Profile,
  credential: PreparedOAuth2Credential,
): string {
  const formParams = Object.keys(profile.formParams)
    .sort()
    .map((name) => [name, profile.formParams[name]]);
  return createHash("sha256")
    .update(
      JSON.stringify([
        profile.tokenEndpoint,
        profile.authMethod,
        profile.clientId,
        formParams,
        profile.assertionAudience,
        profile.sendClientIdWithAssertion,
        profile.assertionAlgorithm ?? null,
        credential.algorithm ?? null,
        credential.fingerprint,
      ]),
    )
    .digest("hex");
}

/**
 * Returns an access token for the profile and credential, from the
 * in-process cache while it is valid (until `expires_in` minus 60 s).
 * Concurrent callers for the same key share one request. A token endpoint
 * that ended `unavailable` fails at once, without a request, for 30 s.
 *
 * @throws OAuth2TokenError from the token request, or `unavailable` while
 * the endpoint is in its fail-fast window.
 */
export async function getOAuth2AccessToken({
  profile,
  credential,
  projectId,
}: {
  profile: ResolvedOAuth2Profile;
  credential: PreparedOAuth2Credential;
  projectId?: string;
}): Promise<{ accessToken: string; cacheKey: string }> {
  const cacheKey = getOAuth2CacheKey(profile, credential);
  const token = await tokenCache.forceFetch(cacheKey, {
    context: { profile, credential, projectId },
  });
  // lru-cache treats a ttl of 0 as "never expires"; such a token is used once.
  if (token.ttlMs === 0 && tokenCache.peek(cacheKey) === token) {
    tokenCache.delete(cacheKey);
  }
  return { accessToken: token.accessToken, cacheKey };
}

/**
 * Drops the cached token after the gateway rejected it, e.g. with a 401. Only
 * the rejected token is dropped: a newer cached token or a fetch already in
 * flight for the key is kept, so callers rejected with the same token share
 * one refetch.
 */
export function invalidateOAuth2AccessToken(
  cacheKey: string,
  rejectedAccessToken: string,
): void {
  // peek() returns undefined while a fetch for the key is in flight.
  if (tokenCache.peek(cacheKey)?.accessToken === rejectedAccessToken) {
    tokenCache.delete(cacheKey);
  }
}

export function clearOAuth2TokenCache(): void {
  tokenCache.clear();
  unavailableUntil.clear();
}

async function fetchToken({
  profile,
  credential,
  projectId,
}: FetchContext): Promise<CachedToken> {
  const endpoint = new URL(profile.tokenEndpoint).href;
  const failFastUntil = unavailableUntil.get(endpoint);
  if (failFastUntil !== undefined) {
    if (Date.now() < failFastUntil) {
      throw new OAuth2TokenError(
        "unavailable",
        `OAuth2 token endpoint was unavailable recently; it will be retried after ${new Date(failFastUntil).toISOString()}`,
      );
    }
    unavailableUntil.delete(endpoint);
  }

  let result;
  try {
    result = await requestOAuth2Token({
      profile,
      credential,
      maxRetries: env.LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES,
    });
  } catch (error) {
    if (error instanceof OAuth2TokenError && error.kind === "unavailable") {
      unavailableUntil.set(endpoint, Date.now() + FAIL_FAST_WINDOW_MS);
    }
    throw error;
  }
  unavailableUntil.delete(endpoint);

  logger.info("OAuth2 access token fetched", {
    projectId,
    provider: profile.provider,
    host: new URL(profile.tokenEndpoint).host,
    authMethod: profile.authMethod,
    expiresIn: result.expiresInSeconds,
    attempts: result.attempts,
  });

  return {
    accessToken: result.accessToken,
    ttlMs: Math.max(result.expiresInSeconds - REFRESH_MARGIN_SECONDS, 0) * 1000,
  };
}
