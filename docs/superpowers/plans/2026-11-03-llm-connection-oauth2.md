# OAuth2 Client Credentials for LLM Connections — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** LLM connections of adapter `openai`/`anthropic` can authenticate with an OAuth2 client-credentials access token (provider presets + Custom; four client auth methods), minted, cached and refreshed inside Langfuse.

**Architecture:** A pure provider-profile module in `packages/shared/src/interfaces` turns a stored `config.oauth2` into one resolved request shape. A server module in `packages/shared/src/server/llm/oauth2/` validates the credential, signs assertions with `jose`, requests tokens through the existing SSRF-safe fetch with retries, and caches tokens per credential with single flight. `llmText.ts` swaps the decrypted secret for a token before building the AI SDK provider and wraps the provider fetch with a one-shot 401 refresh. Write-path validation, public API, Fern and UI are extended additively.

**Tech Stack:** TypeScript, zod v4, `jose` 6.2.3, `lru-cache` 11, AI SDK (`@ai-sdk/openai` 4.0.93, `@ai-sdk/anthropic` 4.0.79), vitest, Next.js/tRPC, react-hook-form, Docker Compose, Keycloak.

**Spec:** `docs/superpowers/specs/2026-11-03-llm-connection-oauth2-design.md` (approved). Background: `spec.md`. Executors read both; the design wins where they differ.

## Global Constraints

- No Prisma migration; no new `EvaluatorBlockReason`.
- Non-OAuth2 connections: behavior byte-for-byte unchanged; existing suites stay green.
- Never put a client secret, JWK, assertion, or access token in logs, errors, API responses, UI, or span attributes.
- `jose` version `6.2.3` (same as `web`), added to `packages/shared` only.
- Assertion lifetime 300 s; refresh margin 60 s; default `expires_in` 300; token HTTP timeout 10 s per attempt.
- Retry env `LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES`: int, default `3`, min `0`, max `10`. Backoff base 1 s, doubling, full jitter, each wait capped at 10 s; `Retry-After` honored up to 10 s. Fail-fast window 30 s per token endpoint.
- Allowlist env `LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS`: comma-separated exact URLs, compared as `new URL(x).href`. Unset ⇒ OAuth2 disabled.
- Error copy (exact): `OAuth2 client credentials are disabled: set LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS`; `OAuth2 token endpoint returned <status>: <first 300 chars of body>`; `token response missing access_token`; `OAuth2 token endpoint unavailable after <n> attempts: <last status or error kind>`.
- Cache bounded at 1 000 entries.
- Commits: conventional commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No ticket ids in code, commits or PR.
- Run node binaries via `pnpm`, quote paths in shell commands. No new ESLint disables.
- Design-system components first (`web/src/components/design-system`); `components/ui/textarea` only for the JWK field.

## Review Focus

1. **JWK pasted as a JWKS (`{"keys":[...]}`) or with surrounding whitespace/newlines** → whitespace is fine; a JWKS gets the config error `Paste a single private JWK, not a JWKS ({"keys": [...]})`. Test in Task 3.
2. **Identity provider echoes request parameters in its 400 body** (some do, including `client_secret`) → the error excerpt has the secret and the assertion replaced by `[redacted]` before truncation. Test in Task 4.
3. **`expires_in` sent as a numeric string (`"3600"`)** → treated as 3600, not 300. Test in Task 4.
4. **Operator lists the endpoint with a trailing slash or a different path than the preset resolves to** → the `disabled` error names the resolved endpoint (`... not in LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS: <url>`) so it can be copied. Test in Task 2.
5. **Playground streaming call hits a 401 from the gateway** → one refresh + retry, stream then works. Test in Task 6.

---

## File Structure

| File | Responsibility |
|---|---|
| `packages/shared/src/interfaces/oauth2Providers.ts` (new) | Provider list, method/algorithm enums, `OAuth2ConfigSchema`, UI profile metadata, `resolveOAuth2Profile` (pure, no server imports) |
| `packages/shared/src/interfaces/customLLMProviderConfigSchemas.ts` | `OpenAIConfigSchema.oauth2`, new `AnthropicConfigSchema`, widened `LLMConnectionConfigSchema` |
| `packages/shared/src/server/llm/oauth2/errors.ts` (new) | `OAuth2TokenError`, `findOAuth2TokenError` |
| `packages/shared/src/server/llm/oauth2/allowlist.ts` (new) | allowlist + scheme rule |
| `packages/shared/src/server/llm/oauth2/credential.ts` (new) | credential parsing/validation, alg + header resolution, display key |
| `packages/shared/src/server/llm/oauth2/tokenRequest.ts` (new) | assertion signing, token HTTP request, retries |
| `packages/shared/src/server/llm/oauth2/tokenCache.ts` (new) | LRU cache, single flight, fail-fast window |
| `packages/shared/src/server/llm/oauth2/connection.ts` (new) | `resolveOAuth2Connection`, 401 fetch wrapper, `assertNotOAuth2Connection` |
| `packages/shared/src/server/llm/llmText.ts`, `ai-sdk/providers/{index,anthropic}.ts`, `secureLlmFetch.ts` | call-path wiring |
| `packages/shared/src/server/evals/classifyEvaluatorLlmError.ts`, `worker/src/features/topics/provider-error.ts` | error mapping |
| `web/src/features/llm-api-key/{types.ts,server/llmConnectionService.ts}`, `web/src/features/public-api/types/llm-connections.ts` | write path |
| `web/src/features/public-api/components/OAuth2ConnectionFields.tsx` (new), `CreateLLMApiKeyForm.tsx`, `LLMApiKeySettingsTable/*` | UI |
| `fern/apis/server/definition/llm-connections.yml` + generated OpenAPI | public API docs |
| `scripts/e2e/llm-oauth2/**` (new) | docker-compose e2e harness |

---

### Task 0: Workspace bootstrap

- [ ] **Step 1:** From the worktree root run `bash scripts/agents/setup.sh` (installs deps, env files). Expected: exits 0.
- [ ] **Step 2:** Baseline: `pnpm --filter @langfuse/shared run test src/server/llm/llmText.test.ts` and `pnpm --filter worker run test src/__tests__/secureLlmFetch.test.ts`. Expected: both pass. If not, stop and report.
- [ ] **Step 3:** Add `.superpowers/` to `.git/info/exclude` of the common git dir (`git rev-parse --git-common-dir`) so mockups never get committed. No commit.

---

### Task 1: Provider profiles and config schemas

**Files:**
- Create: `packages/shared/src/interfaces/oauth2Providers.ts`
- Modify: `packages/shared/src/interfaces/customLLMProviderConfigSchemas.ts`, `packages/shared/src/server/llm/types.ts:516-538` (`LLMApiKeySchema.config`), the shared barrel that exports interfaces (follow how `OpenAIConfigSchema` is exported)
- Test: `packages/shared/src/interfaces/oauth2Providers.test.ts`

**Interfaces — Produces:**
```ts
export const OAUTH2_PROVIDERS = ["entra","okta","auth0","cognito","keycloak","onelogin","workos","authentik","custom"] as const;
export type OAuth2Provider = (typeof OAUTH2_PROVIDERS)[number];
export const OAUTH2_AUTH_METHODS = ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"] as const;
export type OAuth2AuthMethod = (typeof OAUTH2_AUTH_METHODS)[number];
export const CLIENT_SECRET_JWT_ALGORITHMS = ["HS256","HS384","HS512"] as const;
export const PRIVATE_KEY_JWT_ALGORITHMS = ["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512"] as const;
export const OAuth2ConfigSchema: z.ZodType<OAuth2Config>; // discriminatedUnion("provider") + superRefine
export type OAuth2Config;
export type OAuth2ProfileField = { key: string; label: string; required: boolean; placeholder?: string; defaultValue?: string };
export const OAUTH2_PROVIDER_PROFILES: Record<OAuth2Provider, { label: string; authMethods: readonly OAuth2AuthMethod[]; fields: readonly OAuth2ProfileField[] }>;
export type ResolvedOAuth2Profile = {
  provider: OAuth2Provider; tokenEndpoint: string; clientId: string; authMethod: OAuth2AuthMethod;
  assertionAudience: string; sendClientIdWithAssertion: boolean;
  formParams: Record<string, string>;            // scope / audience / resource, only keys that are set
  assertionAlgorithm?: string;                   // explicit config value only
  defaultRsaAlgorithm: "RS256" | "PS256";
  requireX5tS256: boolean;
};
export function resolveOAuth2Profile(config: OAuth2Config): ResolvedOAuth2Profile;
export function isOAuth2Config(config: unknown): config is { oauth2: OAuth2Config };
// customLLMProviderConfigSchemas.ts
export const AnthropicConfigSchema; // z.object({ oauth2: OAuth2ConfigSchema.optional() }).strict()
// OpenAIConfigSchema gains oauth2: OAuth2ConfigSchema.optional()
```

Per-provider fields and rules are exactly design §5.1. Field names: `entra {tenantId, scope}`, `okta {domain, authorizationServerId="default", scope}`, `auth0 {domain, audience}`, `cognito {domain, scope?}`, `keycloak {baseUrl, realm, scope?}`, `onelogin {subdomain, scope?, resource?}`, `workos {domain, scope?}`, `authentik {baseUrl, scope?}`, `custom {tokenEndpoint, scope?, audience?, resource?, assertionAudience?, sendClientIdWithAssertion?=false}`; all have `clientId`, `authMethod` (restricted per provider), and JWT-capable providers have optional `assertionAlgorithm`. Every member is `.strict()`.

- [ ] **Step 1: Write failing tests** `oauth2Providers.test.ts`:
  - `it.each` over providers: `resolveOAuth2Profile` yields — entra `tokenEndpoint "https://login.microsoftonline.com/t1/oauth2/v2.0/token"`, `sendClientIdWithAssertion true`, `requireX5tS256 true`, `defaultRsaAlgorithm "PS256"`, `formParams {scope}`; okta (`domain "acme.okta.com"`, default AS) `"https://acme.okta.com/oauth2/default/v1/token"`, aud = endpoint; auth0 `"https://t.eu.auth0.com/oauth/token"`, `assertionAudience "https://t.eu.auth0.com/"`, `formParams {audience}`; cognito `"https://p.auth.eu-west-1.amazoncognito.com/oauth2/token"`; keycloak (`baseUrl "http://kc:8080/"`, realm `"lf"`) `"http://kc:8080/realms/lf/protocol/openid-connect/token"`, aud `"http://kc:8080/realms/lf"`; onelogin `"https://acme.onelogin.com/oidc/2/token"`; workos `"https://auth.acme.com/oauth2/token"`; authentik `"https://ak.acme.com/application/o/token/"`; custom defaults: aud = tokenEndpoint, `sendClientIdWithAssertion false`.
  - Schema rejects: method not allowed for provider (`cognito` + `private_key_jwt`, `workos` + `client_secret_basic`, `entra` + `client_secret_jwt`); missing required (`entra` without `scope`, `auth0` without `audience`); `domain` containing `/` or `://`; `assertionAlgorithm` with a non-JWT method; `HS256` with `private_key_jwt`; unknown keys.
  - `OpenAIConfigSchema.parse({ useResponsesApi: true, oauth2: {...} })` ok; `AnthropicConfigSchema.parse({ useResponsesApi: true })` fails; `LLMConnectionConfigSchema.parse({ region: "eu" })` ok, `.parse({ oauth2: validCfg })` ok, `.parse({ foo: { a: 1 } })` fails; `LLMApiKeySchema` accepts an anthropic row with `config: { oauth2 }`.
- [ ] **Step 2:** `pnpm --filter @langfuse/shared run test src/interfaces/oauth2Providers.test.ts` → FAIL (module missing).
- [ ] **Step 3:** Implement. Hosts/subdomains: `z.string().regex(/^[a-z0-9.-]+$/i)`; path segments (`tenantId`, `realm`, `authorizationServerId`) are `encodeURIComponent`-ed; `baseUrl` trailing slashes stripped. Widen `LLMConnectionConfigSchema` to `z.object({ oauth2: OAuth2ConfigSchema.optional() }).catchall(LLMConnectionConfigValueSchema)` (or equivalent that passes the tests); fix type fallout in consumers. In `LLMApiKeySchema` and the tRPC union, place `AnthropicConfigSchema` so an OpenAI `{useResponsesApi}` row still parses as OpenAI.
- [ ] **Step 4:** Re-run the test → PASS. Then `pnpm --filter @langfuse/shared run typecheck` → no errors.
- [ ] **Step 5:** Commit `feat(shared): add OAuth2 provider profiles and connection config schemas`.

---

### Task 2: Env vars, errors and allowlist

**Files:**
- Modify: `packages/shared/src/env.ts` (next to `LANGFUSE_LLM_CONNECTION_WHITELISTED_HOST`, ~line 538), all `.env*.example` files at repo root, `docker-compose.yml` and `docker-compose.build.yml` env passthrough
- Create: `packages/shared/src/server/llm/oauth2/errors.ts`, `packages/shared/src/server/llm/oauth2/allowlist.ts`
- Test: `packages/shared/src/server/llm/oauth2/allowlist.test.ts`

**Interfaces — Produces:**
```ts
export type OAuth2TokenErrorKind = "config" | "credential" | "disabled" | "unavailable";
export class OAuth2TokenError extends Error { readonly kind: OAuth2TokenErrorKind; readonly status?: number; constructor(kind, message, opts?: { status?: number; cause?: unknown }) }
export function findOAuth2TokenError(error: unknown): OAuth2TokenError | undefined; // walks .cause chain, cycle-safe
export function assertOAuth2TokenEndpointAllowed(tokenEndpoint: string): void;  // throws OAuth2TokenError
// env: LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS: string[] (parsed, trimmed, empty entries dropped)
//      LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES: number (z.coerce.number().int().min(0).max(10).default(3))
```

- [ ] **Step 1: Failing tests** (mutate `env` like `secureLlmFetch.test.ts` does, restore in `afterEach`):
  - unset → `disabled`, message exactly `OAuth2 client credentials are disabled: set LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS`.
  - listed `https://idp.example.com/token`, called with `https://IDP.example.com:443/token` → ok; with `https://idp.example.com/token/` → `disabled`, message contains `not in LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS: https://idp.example.com/token/` (Review Focus 4).
  - `http://kc:8080/t` listed but `kc` not in `LANGFUSE_LLM_CONNECTION_WHITELISTED_HOST` → `config` ("must use https"); with `kc` whitelisted → ok; with `NEXT_PUBLIC_LANGFUSE_CLOUD_REGION` set → `config` even if whitelisted.
  - `findOAuth2TokenError(new Error("x", { cause: new Error("y", { cause: oauthErr }) }))` returns `oauthErr`.
- [ ] **Step 2:** Run `pnpm --filter @langfuse/shared run test src/server/llm/oauth2/allowlist.test.ts` → FAIL.
- [ ] **Step 3:** Implement; add both vars to every `.env*.example` (commented, with one-line explanation) and compose passthrough (`${VAR:-}`).
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `feat(shared): add OAuth2 token endpoint allowlist and env vars`.

---

### Task 3: Credential parsing and validation

**Files:**
- Modify: `packages/shared/package.json` (add `"jose": "6.2.3"`), lockfile via `pnpm install`
- Create: `packages/shared/src/server/llm/oauth2/credential.ts`
- Test: `packages/shared/src/server/llm/oauth2/credential.test.ts`

**Interfaces — Consumes:** `ResolvedOAuth2Profile` (Task 1), `OAuth2TokenError` (Task 2). **Produces:**
```ts
export type PreparedOAuth2Credential = {
  secret?: string;                          // client_secret_* methods
  signingKey?: CryptoKey | Uint8Array;      // JWT methods (Uint8Array = HMAC secret bytes)
  algorithm?: string;                       // resolved JWS alg for JWT methods
  protectedHeader?: { kid?: string; "x5t#S256"?: string; x5t?: string };
  fingerprint: string;                      // sha256 hex of the decrypted secret string
};
export async function prepareOAuth2Credential(profile: ResolvedOAuth2Profile, decryptedSecret: string): Promise<PreparedOAuth2Credential>; // throws OAuth2TokenError("config")
export function getOAuth2DisplaySecretKey(authMethod: OAuth2AuthMethod, secret: string): string; // "kid:<kid>" | "kid:none" | "...abcd"
```

- [ ] **Step 1: Failing tests** (generate keys with `jose.generateKeyPair(..., { extractable: true })` + `exportJWK`):
  - RSA JWK without `alg` → `RS256` (custom), `PS256` (entra default), config `assertionAlgorithm "RS512"` wins over JWK `alg "RS384"` wins over default.
  - EC P-256 → `ES256`; EC P-384 with `assertionAlgorithm "ES256"` → `config` error; RSA with `ES256` → `config`.
  - public-only JWK (no `d`) → `config` "private JWK required"; `kty "OKP"` → `config` "unsupported kty"; invalid JSON → `config`; `{"keys":[...]}` → `config` with Review Focus 1 copy; JWK with `\n` and spaces around → ok.
  - `kid` copied when present, absent otherwise; entra: `x5t#S256` from member, computed from `x5c[0]` (base64url SHA-256 of DER), neither → `config`.
  - `client_secret_jwt`: HS256 with 31-byte secret → `config`; 32 bytes ok; HS512 needs 64.
  - error messages never contain any JWK field value (assert `d`, `n` values absent).
  - `getOAuth2DisplaySecretKey("private_key_jwt", jwkWithKid)` → `kid:agent-x`; without kid → `kid:none`; `client_secret_post`, `"abcdefgh"` → `...efgh`.
- [ ] **Step 2:** Run `pnpm --filter @langfuse/shared run test src/server/llm/oauth2/credential.test.ts` → FAIL.
- [ ] **Step 3:** Implement with `jose.importJWK(jwk, alg)`. Confirm `jose` (ESM-only) loads under the shared/worker build: `pnpm --filter @langfuse/shared run build` must pass; if CJS interop fails, stop and report rather than vendoring crypto.
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `feat(shared): validate OAuth2 client credentials and private JWKs`.

---

### Task 4: Token request, assertion and retries

**Files:**
- Modify: `packages/shared/src/server/llm/secureLlmFetch.ts` (`fetchSecureLlmUrl` params gain `maxRedirects?: number`, default `MAX_LLM_REDIRECTS`)
- Create: `packages/shared/src/server/llm/oauth2/tokenRequest.ts`
- Test: `packages/shared/src/server/llm/oauth2/tokenRequest.test.ts`

**Interfaces — Consumes:** Tasks 1–3, `fetchSecureLlmUrl`. **Produces:**
```ts
export async function createClientAssertion(profile: ResolvedOAuth2Profile, credential: PreparedOAuth2Credential, nowMs?: number): Promise<string>;
export type OAuth2TokenResult = { accessToken: string; expiresInSeconds: number; attempts: number };
export async function requestOAuth2Token(params: {
  profile: ResolvedOAuth2Profile; credential: PreparedOAuth2Credential;
  maxRetries: number; sleep?: (ms: number) => Promise<void>;
}): Promise<OAuth2TokenResult>; // throws OAuth2TokenError("credential" | "unavailable")
```
Request uses `fetchSecureLlmUrl(url, init, { logContext: "OAuth2 token endpoint", maxRedirects: 0 })`, `AbortSignal.timeout(10_000)`; a `MaxRedirectsExceededError` (3xx) maps to `credential`.

- [ ] **Step 1: Failing tests** (mock `../secureLlmFetch` like `ai-sdk/requestShape.test.ts`; capture `url`, headers, body):
  - Custom + `private_key_jwt` (spec.md contract): body has exactly `grant_type`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion` (+`scope` only when set); no `client_id`; JWT header `{alg, typ:"JWT", kid?}`; claims `iss=sub=clientId`, `aud=tokenEndpoint`, `exp-iat=300`, `jti` UUID v4 and different across two calls; signature verifies with the public JWK (RSA and EC).
  - entra `private_key_jwt`: body has `client_id`; header has `x5t#S256`; alg `PS256`.
  - auth0 `private_key_jwt`: `aud="https://t.eu.auth0.com/"`, body has `audience`.
  - `client_secret_basic`: header `Basic base64("a%3Ab" + ":" + "p%20%2B%25")` for id `a:b`, secret `p +%`; body has no client fields.
  - `client_secret_post`: body `client_id`, `client_secret`. `client_secret_jwt`: HS256 verifies with secret.
  - 200 `{access_token:"t", expires_in:3600}` → `{accessToken:"t", expiresInSeconds:3600}`; `expires_in:"3600"` → 3600 (Review Focus 3); missing / `-5` / `"abc"` → 300; no `access_token` → `credential` `token response missing access_token`.
  - 400 with body echoing `client_secret=s3cr3t&client_assertion=<jwt>` → `credential`, message starts `OAuth2 token endpoint returned 400: `, contains `[redacted]`, contains neither the secret nor the assertion (Review Focus 2); body longer than 300 chars truncated.
  - 401/403 → `credential`, `fetch` called once. 302 (mock throws `MaxRedirectsExceededError`) → `credential`.
  - 503, 503, 200 with `maxRetries 3` → success, `attempts 3`, sleeps called with values ≤ 1000 then ≤ 2000 (stub `Math.random` → 1). 429 with `Retry-After: 4` → sleep 4000; `Retry-After: 60` → 10000. Network error ×4 with `maxRetries 3` → `unavailable` `OAuth2 token endpoint unavailable after 4 attempts: network error`. `maxRetries 0` + 500 → one call, `unavailable ... after 1 attempts: 500`. Each attempt signs a fresh assertion (different `jti`).
- [ ] **Step 2:** Run `pnpm --filter @langfuse/shared run test src/server/llm/oauth2/tokenRequest.test.ts` → FAIL.
- [ ] **Step 3:** Implement. Redaction: replace every occurrence of the raw secret, its form-encoded form, and the assertion with `[redacted]`, then slice to 300.
- [ ] **Step 4:** Re-run → PASS. Also `pnpm --filter worker run test src/__tests__/secureLlmFetch.test.ts` → still PASS.
- [ ] **Step 5:** Commit `feat(shared): request OAuth2 client credentials tokens with retries`.

---

### Task 5: Token cache, single flight and fail-fast

**Files:**
- Create: `packages/shared/src/server/llm/oauth2/tokenCache.ts`
- Test: `packages/shared/src/server/llm/oauth2/tokenCache.test.ts`

**Interfaces — Consumes:** `requestOAuth2Token` (Task 4). **Produces:**
```ts
export function getOAuth2CacheKey(profile: ResolvedOAuth2Profile, credential: PreparedOAuth2Credential): string; // sha256 hex
export async function getOAuth2AccessToken(params: {
  profile: ResolvedOAuth2Profile; credential: PreparedOAuth2Credential; projectId?: string;
}): Promise<{ accessToken: string; cacheKey: string }>;
export function invalidateOAuth2AccessToken(cacheKey: string): void;
export function clearOAuth2TokenCache(): void; // used by tests
```
`lru-cache` with `max: 1000`, per-entry `ttl = max(expiresIn - 60, 0) * 1000` (via `fetchMethod` options), `fetch()` for single flight. Fail-fast map keyed by normalized token endpoint, 30 s. Retries come from `env.LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES`. Info log per successful fetch: `projectId`, provider, endpoint host, authMethod, `expiresIn`, attempts. Warn per retry inside Task 4 code with host/attempt/status only.

- [ ] **Step 1: Failing tests** (mock `./tokenRequest`; `vi.useFakeTimers()`):
  - second call within validity → `requestOAuth2Token` called once; after advancing `expires_in - 60` s → called again; `expires_in` 30 → every call refetches.
  - 10 concurrent calls → one request.
  - first call rejects, second resolves → two requests, second returns the token.
  - same profile, different secret → different `cacheKey`, two requests; key string contains neither secret nor clientId.
  - `unavailable` → next call to same endpoint (other credential) rejects immediately with `unavailable`, no request; after 30 s it requests again; a success clears the window.
  - `credential` error does not open the fail-fast window.
  - `invalidateOAuth2AccessToken(key)` → next call refetches.
  - logs (spy `logger.info`) contain no token/secret.
- [ ] **Step 2:** Run `pnpm --filter @langfuse/shared run test src/server/llm/oauth2/tokenCache.test.ts` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `feat(shared): cache OAuth2 access tokens with single flight and fail-fast`.

---

### Task 6: Call path wiring and 401 refresh

**Files:**
- Create: `packages/shared/src/server/llm/oauth2/connection.ts`
- Modify: `packages/shared/src/server/llm/llmText.ts:319-416` (`openLLMConnection` becomes `async`, both callers `await` it), `packages/shared/src/server/llm/ai-sdk/providers/index.ts` (`buildAiSdkModel` param `bearerAuth?: boolean`), `providers/anthropic.ts` (`buildAnthropicModel` param `bearerAuth?: boolean` → `createAnthropic({ authToken })` and no `apiKey`)
- Test: `worker/src/__tests__/llmOAuth2Connection.test.ts` (local servers, pattern of `secureLlmFetch.test.ts` + `helpers/localLlmServer.ts`)

**Interfaces — Consumes:** Tasks 1–5. **Produces:**
```ts
export async function resolveOAuth2Connection(params: {
  config: { oauth2: OAuth2Config }; decryptedSecret: string; projectId?: string;
}): Promise<{ accessToken: string; wrapFetch: (fetchFn: typeof fetch) => typeof fetch }>;
// wrapFetch: on a 401 response, invalidate, get a fresh token, re-send once with Authorization: Bearer <new>
export function assertNotOAuth2Connection(config: unknown, context: string): void; // throws OAuth2TokenError("config", `OAuth2 connections are not supported for ${context}`)
```
`openLLMConnection` returns `{ apiKey, bearerAuth, extraHeaders, createFetch }`; for OAuth2 it checks the allowlist, sets `apiKey = accessToken`, `bearerAuth = true`, and `createFetch` returns `wrapFetch(createSecureLlmFetch(...))`. Non-OAuth2 path unchanged.

- [ ] **Step 1: Failing tests** (whitelist `127.0.0.1` and set the allowlist env to the fake token URL):
  - openai adapter, one case per auth method (Custom profile against the fake token server): `generateLLMText` hits `/v1/chat/completions` with `authorization: Bearer <token from fake endpoint>`.
  - anthropic adapter: `/v1/messages` has `authorization: Bearer <token>` and no `x-api-key`; `ANTHROPIC_API_KEY` env set to `leak` is not sent.
  - gateway 401 once then 200 → token endpoint called twice, gateway twice, call succeeds; 401 twice → error status 401, token endpoint called twice, gateway twice.
  - `streamLLMText` with 401 once → stream text completes (Review Focus 5).
  - `embedLLMText` (openai) with OAuth2 → embedding request carries bearer token.
  - allowlist unset → `generateLLMText` rejects with `OAuth2TokenError` kind `disabled`, gateway never called.
- [ ] **Step 2:** Run `pnpm --filter worker run test src/__tests__/llmOAuth2Connection.test.ts` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Re-run → PASS. Then `pnpm --filter @langfuse/shared run test src/server/llm` and `pnpm --filter worker run test src/__tests__/secureLlmFetch.test.ts` → PASS (non-OAuth2 unchanged).
- [ ] **Step 5:** Commit `feat(shared): send OAuth2 access tokens on LLM calls with 401 refresh`.

---

### Task 7: Block bypass paths

**Files:**
- Modify: `worker/src/features/evaluation/evalExecutionDeps.ts:~302`, `web/src/features/evals/v2/server/evaluators/testEvaluator.ts:~158`, plus every other hit of the search below
- Test: extend the closest existing test for decision-model evaluation in `worker/src/__tests__/` (search `evalExecutionDeps` / `decisionModel`)

- [ ] **Step 1:** List every site that decrypts a connection secret outside `llmText.ts`: `rg -n "decrypt\(" web/src worker/src packages/shared/src ee/src | rg -i "secretKey"`. Record the list in the commit body.
- [ ] **Step 2: Failing test:** a decision-model evaluation whose connection has `config.oauth2` rejects with message `OAuth2 connections are not supported for decision-model evaluators` and the decision-model client is never constructed (spy).
- [ ] **Step 3:** Run it → FAIL. Add `assertNotOAuth2Connection(config, "<context>")` before each decrypt that would send the secret to an LLM (Bedrock-only and Vertex-only paths need no guard; note them in the commit body).
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `fix(worker): reject OAuth2 connections on decision-model paths`.

---

### Task 8: Error classification (evaluators, experiments, topics)

**Files:**
- Modify: `packages/shared/src/server/evals/classifyEvaluatorLlmError.ts`, `worker/src/features/topics/provider-error.ts`
- Test: `packages/shared/src/server/evals/classifyEvaluatorLlmError.test.ts` (extend if it exists, else create next to it), the existing topics provider-error test (extend)

**Interfaces — Consumes:** `findOAuth2TokenError` (Task 2).

- [ ] **Step 1: Failing tests:**
  - `classifyEvaluatorLlmError(new OAuth2TokenError("credential", ...))` → `{ kind: "evaluator-policy", isRetryable: false, blockReason: LLM_CONNECTION_AUTH_INVALID }`; same for `config`; `disabled` and `unavailable` → `isRetryable: false, blockReason: null`, `message` = the error message; an `APICallError` whose `cause` is an `OAuth2TokenError("unavailable")` → `blockReason: null`, not retryable.
  - Topics: `credential`/`config` → reason `"authentication"` (pauses); `disabled`/`unavailable` → the non-pausing `"provider_error"` reason.
- [ ] **Step 2:** Run `pnpm --filter @langfuse/shared run test src/server/evals/classifyEvaluatorLlmError.test.ts` and the topics test → FAIL.
- [ ] **Step 3:** Implement: check `findOAuth2TokenError` first in both. With `isRetryable: false` + `blockReason: null`, `evalQueue.ts` already marks the job `ERROR` with the user-facing message and does not rethrow; confirm by reading `worker/src/queues/evalQueue.ts:247-270` and `worker/src/queues/experimentQueue.ts` — no queue changes expected; if the experiment queue differs, add the same handling there.
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `feat(shared): classify OAuth2 token errors for evaluators and topics`.

---

### Task 9: Write path (service, tRPC, public API types)

**Files:**
- Modify: `web/src/features/llm-api-key/server/llmConnectionService.ts` (`validateSecret` ~267, `getDisplaySecretKey` ~152, create ~526, upsert ~586, update ~676, test/testUpdate ~759), `web/src/features/llm-api-key/types.ts:19-21`, `web/src/features/public-api/types/llm-connections.ts:66-149`
- Test: extend `web/src/__tests__/server/llm-api-key.servertest.ts`, `organization-llm-api-key.servertest.ts`, `llm-connections-api.servertest.ts`, `organization-llm-connections-api.servertest.ts`

**Interfaces — Consumes:** `OAuth2ConfigSchema`, `resolveOAuth2Profile`, `assertOAuth2TokenEndpointAllowed`, `prepareOAuth2Credential`, `getOAuth2DisplaySecretKey`, `isOAuth2Config`. **Produces (module-private):**
```ts
async function validateOAuth2Connection(params: { adapter: LLMAdapter; config: unknown; secretKey: string; extraHeaders?: Record<string, string | null | undefined> }): Promise<void>; // InvalidRequestError, message from OAuth2TokenError
function requiresNewSecret(existing: LLMConnectionConfig | null, next: LLMConnectionConfig | null | undefined): boolean; // auth type, provider, authMethod, resolved tokenEndpoint, clientId
```
Also: `Authorization` (any case) in `extraHeaders` of an OAuth2 connection → `InvalidRequestError("Authorization header is not allowed for OAuth2 connections")`. `getDisplaySecretKey(secretKey, config)` branches to `getOAuth2DisplaySecretKey` first. Validation runs `validateBaseUrlForWrite`-style SSRF host check on the resolved token endpoint (reuse `validateLlmConnectionBaseURL`).

- [ ] **Step 1: Failing tests** (servertests mock `generateLLMText` as the existing suite does; set allowlist env in the test process — for public API tests, the web server under test must run with `.env.test` containing the allowlist and a test endpoint; add those vars to `.env.test.example`):
  - tRPC create openai + Custom `private_key_jwt` with a generated JWK (kid `t1`) → DB row `secretKey` decrypts to the JWK, `displaySecretKey "kid:t1"`, `config.oauth2` stored, list response has no `d`/`n`.
  - tRPC create anthropic + keycloak `client_secret_post` → ok; anthropic `{ useResponsesApi: true }` → rejected.
  - update with empty `secretKey` and changed `scope` → ok, secret unchanged; changed `clientId` / `tokenEndpoint` / `provider` / `authMethod` / API-key→OAuth2 without secret → rejected with `A new secret is required when ...`.
  - `extraHeaders: { authorization: "x" }` on OAuth2 → rejected; on API-key connection → still allowed.
  - allowlist unset → create rejected with the exact disabled copy; endpoint not listed → rejected.
  - public JWK → rejected, message has no key material.
  - PUT `/api/public/llm-connections` (project and org) with Custom + private JWK → 200, response has no `secretKey`, `config.oauth2` echoed, `displaySecretKey "kid:t1"`; GET returns `config.oauth2`.
  - testUpdate with empty secret uses stored JWK (mocked `generateLLMText` receives a connection whose decrypted secret is the stored JWK).
- [ ] **Step 2:** Run `pnpm --filter web run test src/__tests__/server/llm-api-key.servertest.ts` (and the three others) → new cases FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Re-run all four → PASS (old cases too).
- [ ] **Step 5:** Commit `feat(web): validate and store OAuth2 LLM connections`.

---

### Task 10: Fern and OpenAPI

**Files:**
- Modify: `fern/apis/server/definition/llm-connections.yml` (document `config.oauth2`: providers, fields, methods; `secretKey` = client secret or private JWK JSON for OAuth2; example from design §10 with placeholder values)
- Regenerate: `web/public/generated/**/openapi.yml`

- [ ] **Step 1:** Edit the Fern definition (docs + example only; `config` stays `optional<map<string, unknown>>`).
- [ ] **Step 2:** `pnpm run openapi:export` → exits 0.
- [ ] **Step 3:** `pnpm run openapi:check` after staging → exits 0.
- [ ] **Step 4:** Commit `docs(api): document OAuth2 config for LLM connections`.

---

### Task 11: UI

**Files:**
- Create: `web/src/features/public-api/components/OAuth2ConnectionFields.tsx`
- Modify: `web/src/features/public-api/components/CreateLLMApiKeyForm.tsx` (form schema ~112, submit ~640-805, default secret branch ~1368, advanced ~1440), `LLMApiKeySettingsTable/LLMApiKeySettingsTable.tsx:~85`
- Test: extend `web/src/features/public-api/components/CreateLLMApiKeyForm.clienttest.tsx`

**Interfaces — Consumes:** `OAUTH2_PROVIDERS`, `OAUTH2_PROVIDER_PROFILES`, `OAuth2ConfigSchema`, `resolveOAuth2Profile` (Task 1; pure, safe for the client bundle).
Form adds `authType: "api-key" | "oauth2"` (openai/anthropic only, `Tabs` like Bedrock), `oauth2` nested values. Fields render from `OAUTH2_PROVIDER_PROFILES[provider].fields`; Credential choice from `.authMethods` (preset labels "Client secret" / "Certificate (private key)" / "Signed JWT (client secret)"; Custom shows raw method names); read-only resolved token endpoint line; secret field `PasswordInput` or `components/ui/textarea` "Private JWK (JSON)" for `private_key_jwt`; in update mode placeholder = `displaySecretKey`. Submit builds `config = { ...(openai ? { useResponsesApi } : {}), oauth2 }`. Table shows `OAuth2 · <provider label>` next to `displaySecretKey` when `config.oauth2` exists.

- [ ] **Step 1: Failing client tests:** switching to OAuth2 + Entra shows Tenant ID/Client ID/Scope and token endpoint `https://login.microsoftonline.com/<typed tenant>/oauth2/v2.0/token`; Cognito offers no JWT credential option; Custom + `private_key_jwt` shows the JWK textarea and Assertion algorithm; submit sends the expected `config.oauth2` for Entra and for Custom; switching back to API key sends no `oauth2`.
- [ ] **Step 2:** `pnpm --filter web run test-client src/features/public-api/components/CreateLLMApiKeyForm.clienttest.tsx` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Re-run → PASS.
- [ ] **Step 5:** Commit `feat(web): OAuth2 provider presets in the LLM connection form`.

---

### Task 12: Docker Compose end-to-end harness

**Files (all new, under `scripts/e2e/llm-oauth2/`):** `README.md`, `docker-compose.oauth2.yml` (override for `docker-compose.build.yml`), `keycloak/realm.template.json`, `fake-llm/server.mjs` (Node built-ins only, no npm deps; verifies RS256 access tokens against Keycloak's JWKS with Node `crypto`), `setup.sh`, `run-scenarios.mjs`, `.gitignore` (`generated/`).

Services: `keycloak` (`quay.io/keycloak/keycloak:26.x start-dev --import-realm`, realm `lf-e2e`, access token lifespan 120 s, confidential clients `cs-basic`, `cs-post`, `cs-jwt` (Signed JWT with client secret), `pk-jwt` (Signed JWT, public key from `generated/`), service accounts on); `fault-proxy` endpoints inside `fake-llm` (`/fault/token` proxies to Keycloak's token endpoint, mode set via `POST /control {tokenMode: "ok"|"503"|"slow", gateway401Once: true}`); `fake-llm` routes `/v1/chat/completions`, `/v1/messages` returning a judge-shaped JSON answer, 401 on bad/expired token. Langfuse web + worker get `LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS` (Keycloak token URL and the fault URL), `LANGFUSE_LLM_CONNECTION_WHITELISTED_HOST=keycloak,fake-llm`, `LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES=2`, and `LANGFUSE_INIT_*` org/project/API keys.

- [ ] **Step 1:** `setup.sh` generates an RSA key pair (Node `crypto.generateKeyPairSync`, JWK export with `kid`) into `generated/`, renders the realm. No key material committed.
- [ ] **Step 2:** `docker compose -f docker-compose.build.yml -f scripts/e2e/llm-oauth2/docker-compose.oauth2.yml up -d --build` → web healthy at `http://localhost:3000`.
- [ ] **Step 3:** `node scripts/e2e/llm-oauth2/run-scenarios.mjs` runs and prints PASS/FAIL per scenario:
  1. PUT connection per method × adapter (Keycloak preset ×4 methods, Custom `private_key_jwt` with `assertionAudience` = token endpoint ×2 adapters) → 200.
  2. Create an LLM-as-a-Judge evaluator (public API, as the seeder's `evaluator-gallery` does) on the openai Keycloak `private_key_jwt` connection, ingest a trace, poll until a score exists.
  3. Wait > 120 s, ingest another trace → scored (refresh proven; fake-llm logs two distinct tokens).
  4. `gateway401Once` → next trace scored; fake-llm saw one 401.
  5. `tokenMode 503` on a connection using `/fault/token` → evaluation ERROR with `unavailable after 3 attempts`, evaluator still active.
  6. Disable `pk-jwt` client via Keycloak admin API → evaluation fails, evaluator blocked `LLM_CONNECTION_AUTH_INVALID`.
  7. PUT with a token endpoint not on the allowlist → 400 with the disabled/not-listed copy.
  8. `docker compose logs langfuse-web langfuse-worker` grepped for the generated JWK `d`, the client secrets, and any `eyJ` access token → no hits.
- [ ] **Step 4:** Save the scenario output to `scripts/e2e/llm-oauth2/generated/last-run.txt` (git-ignored) for the PR body. `docker compose ... down -v`.
- [ ] **Step 5:** Commit `test(e2e): docker-compose harness for OAuth2 LLM connections`.

---

### Task 13: Verification, review, PR

- [ ] **Step 1:** `pnpm exec turbo run lint --force` → quote `Tasks:` and `Cached:` lines (must be 0 cached). `pnpm run typecheck` → pass. `pnpm exec knip` → pass. `pnpm run openapi:check` → pass.
- [ ] **Step 2:** Targeted suites from Tasks 1–11 all green; quote each vitest summary line.
- [ ] **Step 3:** Run `/security-review`, then superpowers:requesting-code-review (whole branch), then `/simplify`. Fix confirmed findings with `fix:`/`refactor:` commits; re-run Step 1–2 afterwards.
- [ ] **Step 4:** Push the branch and open a reviewable PR to `main` of `labuzniq/langfuse` with `gh pr create`: business summary, design §11 differences, the spec.md VERIFY table (design §15), test evidence, e2e output, deployment note (env vars for web + worker; add the token endpoint host to `LANGFUSE_LLM_CONNECTION_ALLOWED_HOSTS` if that env is used). End with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
