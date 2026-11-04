# Design: OAuth2 client credentials for LLM connections

Date: 2026-11-03. Branch: `feat/llm-connection-oauth2-client-credentials`.
Source requirements: `spec.md` at the repo root (the original spec). This document
**replaces** it where they differ; every difference is listed in section 11.

## 1. Intent

Langfuse LLM connections only support static secrets today (API key + extra headers,
Bedrock keys, Vertex service account). Many companies put their LLMs behind a gateway
that only accepts short-lived OAuth2 access tokens, minted with the machine-to-machine
(M2M) **client credentials** grant. Langfuse features that call an LLM on the user's
behalf (LLM-as-a-Judge, playground, prompt experiments, connection test) cannot be used
against such gateways.

An example is a self-hosted deployment where each agent project has its own
identity-provider client (for example a PingFederate client using `private_key_jwt`). The feature is
meant to be offered upstream and used world-wide, so it supports the standard client
authentication methods and ships **presets for well-known identity providers**, the same
way Langfuse SSO login offers `AUTH_AZURE_AD_*`, `AUTH_KEYCLOAK_*`, ... next to
`AUTH_CUSTOM_*`. A preset asks only for the few values that provider needs and knows how
that provider wants the token request shaped. Anything else (PingFederate included) uses
**Custom**, which exposes every setting.

## 2. Goals, non-goals, anti-goals

**Goals**
- A new auth type for LLM connections of adapter `openai` and `anthropic`:
  "OAuth2 (machine-to-machine)", with an identity provider chosen from presets or Custom.
- Client authentication methods: `client_secret_basic`, `client_secret_post`,
  `client_secret_jwt`, `private_key_jwt` (each preset allows the subset its provider supports).
- Every LLM call through such a connection uses a cached (or freshly minted) access
  token as `Authorization: Bearer <token>`. Refresh is automatic.
- Works for project-owned and organization-owned connections (same code path).
- Configurable through the UI, tRPC and the public API (`PUT /api/public/llm-connections`
  and the organization variant).
- Token-endpoint outages are retried with backoff a configurable number of times.

**Non-goals**
- mTLS client auth (`tls_client_auth`, `self_signed_tls_client_auth`). Needs a client
  certificate in the secure fetch dispatcher; a separate change if anyone asks.
- Other grants (authorization code, refresh token, token exchange, JWT-bearer grant).
- Non-standard provider flows (Authentik username + app password, Authentik federated JWTs).
- Other adapters (Azure, Bedrock, Google, TypeSafe/decision models).
- Reading keys from external secret stores. OIDC discovery (`.well-known`) lookups.
- Changes to ingestion auth, SSO, or public API auth.
- Self-service on Langfuse Cloud. The operator-managed allowlist means only the
  operator can enable a token endpoint. Cloud self-service would need a per-organization
  allowlist with storage; a separate design if upstream asks for it.

**Anti-goals (failure even if it "works")**
- Any secret material (client secret, JWK, assertion, access token) in logs, error
  messages, API responses, UI, or telemetry.
- Any behavior change for existing API-key connections.
- One project ever using a token minted with another project's credentials.
- Langfuse becoming a way to POST to arbitrary URLs (SSRF, Server-Side Request Forgery).
- A raw client secret or JWK being sent to the LLM gateway on any code path.
- A preset offered in the UI that can never work against that provider.

## 3. Decisions made with the user

| Topic | Decision |
|---|---|
| Client auth methods | `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`. mTLS out. |
| Provider presets | Same idea and same provider list as Langfuse SSO, limited to providers that support client credentials (section 5.1). PingFederate is **not** a preset; it uses Custom. |
| `private_key_jwt` contract for PingFederate | `spec.md` §4.3/§4.4, reached through Custom with its defaults. |
| Token-endpoint outage | Retry `LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES` times (env var on web + worker) with exponential backoff, then abort. |
| Meaning of "abort" | The one LLM call fails with a clear error. For evaluators: that evaluation is marked failed, the queue does **not** retry it, the evaluator is **not** blocked; the next trace tries again. |
| Credential rejected | Token endpoint 400/401 (`invalid_client`, bad key, ...) is never retried and blocks the evaluator with `LLM_CONNECTION_AUTH_INVALID`. |
| End-to-end test | Langfuse via docker-compose + a Keycloak container + a small fake OpenAI/Anthropic server that checks the bearer token. |
| Quality bar | Upstream quality: docs, Fern, UI; full security + code review before the PR. |

## 4. Data model

No Prisma migration. Existing `llm_api_keys` columns:

| Column | OAuth2 connection value |
|---|---|
| `adapter` | `openai` or `anthropic` |
| `baseURL` | gateway URL |
| `secretKey` | encrypted (existing `encrypt()`): the **client secret** for `client_secret_*`, the **private JWK JSON string** for `private_key_jwt` |
| `displaySecretKey` | `private_key_jwt`: `kid:<kid>` or `kid:none`. Secret methods: the existing masked form (`...abcd`). |
| `config` | `{ "oauth2": { ... } }` (section 5) |
| `extraHeaders` | Allowed, except `Authorization` (case-insensitive) |

## 5. Providers and config schema

### 5.1 Provider profiles

One table in shared code (single source of truth, used by the server and by the UI to
render fields) defines each provider. Sources: official docs, checked 2026-11-03.

| `provider` | Inputs (besides Client ID + secret) | Token endpoint | Methods allowed (UI default first) | Required params | Assertion `aud` | `client_id` in body with assertion | Other |
|---|---|---|---|---|---|---|---|
| `entra` | `tenantId`, `scope` | `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token` | post, basic, private_key_jwt ("certificate") | `scope` (e.g. `api://x/.default`) | token endpoint | yes | `x5t#S256` header required: from JWK `x5t#S256`, else computed from JWK `x5c[0]`; JWK without either is rejected. Default alg PS256 for RSA. |
| `okta` | `domain`, `authorizationServerId` (default `default`), `scope` | `https://{domain}/oauth2/{authorizationServerId}/v1/token` | basic, post, client_secret_jwt, private_key_jwt | `scope` | token endpoint | no | client_secret_jwt secret ≥ 32 chars. Org authorization server not supported (only issues `okta.*` scopes). |
| `auth0` | `domain`, `audience` | `https://{domain}/oauth/token` | post, basic, private_key_jwt | `audience` | `https://{domain}/` (issuer, trailing slash) | no | — |
| `cognito` | `domain` (hosted or custom domain), `scope` optional | `https://{domain}/oauth2/token` | basic, post | — | — | — | No JWT methods (Cognito does not support them). |
| `keycloak` | `baseUrl`, `realm`, `scope` optional | `{baseUrl}/realms/{realm}/protocol/openid-connect/token` | basic, post, client_secret_jwt, private_key_jwt | — | issuer `{baseUrl}/realms/{realm}` | no | Keycloak ≥ 26 wants a single-string `aud`; issuer is its recommended value. |
| `onelogin` | `subdomain`, `scope` optional, `resource` optional | `https://{subdomain}.onelogin.com/oidc/2/token` | basic, post | — | — | — | — |
| `workos` | `domain` (AuthKit domain), `scope` optional | `https://{domain}/oauth2/token` | post | — | — | — | — |
| `authentik` | `baseUrl`, `scope` optional | `{baseUrl}/application/o/token/` | post | — | — | — | Standard provider secret only (token is issued for the provider's service account). |
| `custom` | `tokenEndpoint`, plus all optional knobs below | as entered | all four (default `client_secret_basic`) | none | `assertionAudience` if set, else token endpoint | `sendClientIdWithAssertion` (default **false**) | `scope`, `audience`, `resource` optional; `assertionAlgorithm` optional. |

Not offered (no client credentials grant for customer APIs): Google, GitHub, GitHub
Enterprise, GitLab, WordPress.com, JumpCloud (OIDC apps lack the grant), ClickHouse Cloud.

PingFederate through Custom with defaults gives exactly the `spec.md` contract: `aud` =
token endpoint, no `client_id` in the body, `kid` only if in the JWK, alg from config >
JWK > RS256/ES256.

Inputs that are hosts (`domain`, `subdomain`) are entered without a scheme and always
built as `https://`. `baseUrl` and `tokenEndpoint` are full URLs (scheme rule: section 7).

### 5.2 Schema

In `packages/shared/src/interfaces/customLLMProviderConfigSchemas.ts`, a
`z.discriminatedUnion("provider", [...])` with one `.strict()` object per row above,
each with `clientId`, `authMethod` limited to that provider's allowed methods, the
provider's inputs, and `assertionAlgorithm` (optional; only valid with a JWT method;
HS256/384/512 for `client_secret_jwt`, RS*/PS*/ES* for `private_key_jwt`).

- `OpenAIConfigSchema` gains `oauth2: OAuth2ConfigSchema.optional()` (keeps `useResponsesApi`).
- New `AnthropicConfigSchema = z.object({ oauth2: OAuth2ConfigSchema.optional() }).strict()`.
- A pure function `resolveOAuth2Profile(config)` returns the concrete request shape:
  `{ tokenEndpoint, authMethod, assertionAudience, sendClientIdWithAssertion,
  formParams (scope/audience/resource), defaultAlgorithm, headerRules }`. The token
  client only ever sees this resolved shape, so presets cannot drift from Custom.
- Every place that accepts a connection config must accept the new shape, and other
  adapters must stay exactly as strict as today. Known places (from code reading):
  - `LLMConnectionConfigSchema` (flat `record<string, string|boolean>` today; must also
    allow the nested `oauth2` object). Used by the public API types and
    `llmConnectionService.ts`.
  - `LLMApiKeySchema.config` union in `packages/shared/src/server/llm/types.ts` (add
    Anthropic schema; OpenAI schema already grows). Its consumers
    (`LlmApiKeyService`, `DefaultEvalModelService`, `worker/.../experiments/utils.ts`,
    `testModelCall.ts`, MCP `listLlmConnections.ts`) must parse OAuth2 connections.
  - tRPC input union in `web/src/features/llm-api-key/types.ts`.
  - Public API `superRefine` in `web/src/features/public-api/types/llm-connections.ts`
    (today rejects any Anthropic config; must accept `{ oauth2 }` for Anthropic).
  - Runtime readers: `resolveAiSdkModelConfig.ts` etc.
- The OAuth2 config holds no secrets, so it is returned as-is in GET responses and tRPC lists.

## 6. Token client (new module `packages/shared/src/server/llm/oauth2ClientCredentials.ts`)

### 6.1 Token request

Built from the resolved profile (5.2):

```
POST {tokenEndpoint}
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=client_credentials
[&scope=...][&audience=...][&resource=...]   only when set
+ client authentication, by method:
```

| Method | Client authentication |
|---|---|
| `client_secret_basic` | Header `Authorization: Basic base64(urlenc(clientId) ":" urlenc(secret))` (RFC 6749 §2.3.1 form-encoding). No client fields in body. |
| `client_secret_post` | Body `client_id=<id>&client_secret=<secret>` |
| `client_secret_jwt` | Body `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<JWT, HMAC with the secret>` [+ `client_id` if the profile says so] |
| `private_key_jwt` | Body `client_assertion_type=...jwt-bearer&client_assertion=<JWT signed with the private JWK>` [+ `client_id` if the profile says so] |

Assertion (both JWT methods), built with `jose` (`SignJWT`; `importJWK` for the JWK,
raw secret bytes for HMAC):

| Part | Value |
|---|---|
| Header `alg` | `private_key_jwt`: config `assertionAlgorithm` > JWK `alg` > profile default > `RS256` (RSA) / `ES256` (EC). `client_secret_jwt`: config > `HS256`. |
| Header `kid` | JWK `kid` only if present (`private_key_jwt`) |
| Header `x5t#S256` | Entra: required (from JWK `x5t#S256` or computed from `x5c[0]`). Other providers: copied from the JWK only if present. |
| Header `typ` | `JWT` |
| `iss`, `sub` | `clientId` |
| `aud` | profile `assertionAudience` (exact string) |
| `iat` / `exp` | now / now + 300 s (Keycloak's default max age is 60 s from `iat`, which a fresh assertion meets) |
| `jti` | new random UUID v4 per assertion (also per retry attempt) |

`jose` is not a dependency of `packages/shared` today; add it at the version `web`
already uses (6.2.3). It is ESM-only; the builder must confirm it loads in the shared/worker
build (web already uses it).

Response handling:
- 200 with string `access_token` → success. `expires_in` missing or not a positive
  integer → 300.
- 200 without string `access_token` → error `token response missing access_token`
  (credential class, no retry).
- 3xx → error, never followed (a redirect would re-send `client_secret_post` /
  assertions to another URL). The secure fetch currently follows redirects manually
  (`fetchWithSecureRedirects`), so it needs an option to not follow them.
- 400 / 401 / 403 → credential error (no retry). Message:
  `OAuth2 token endpoint returned <status>: <first 300 chars of body>`. The body of an
  error response is an OAuth error JSON (`invalid_client`, ...), safe to show; never
  include the request, assertion, secret, or any token.
- 429, 5xx, network error, timeout (10 s per attempt) → transient; retried (6.2).
- All outbound calls go through the existing SSRF-safe fetch
  (`createSecureLlmFetch` / `fetchSecureLlmUrl`) **and** the allowlist (section 7).

### 6.2 Retries for transient failures

- `LANGFUSE_LLM_OAUTH2_TOKEN_MAX_RETRIES`: integer ≥ 0, default `3`, max `10`
  (0 = no retries). Total attempts = retries + 1.
- Exponential backoff with full jitter: base 1 s, doubling, each wait capped at 10 s.
  A 429 `Retry-After` (seconds) is used instead when present, capped at 10 s.
- After the last attempt: throw an "unavailable" error
  `OAuth2 token endpoint unavailable after <n> attempts: <last status or error kind>`.
- **Fail-fast window (my call):** when a fetch ends `unavailable`, remember that
  token endpoint (by normalized URL, not by credential) as down for 30 s. Any fetch to
  it during that window fails at once with the same `unavailable` error and no HTTP
  request. Reason: hundreds of projects use different credentials against one
  endpoint, so per-credential single flight does not stop each eval job from waiting
  the full retry budget (~70 s with defaults) and filling the worker slots during an
  outage. A successful fetch to that endpoint clears the mark.

### 6.3 Cache and single flight

- In-process, per container. Bounded to 1 000 entries, least-recently-used eviction.
  `lru-cache` is already a dependency of shared; its `fetch()` gives single flight.
  (`LocalCache` in `server/cache/localCache.ts` has no single flight and a fixed TTL,
  so it does not fit.)
- **Cache key:** SHA-256 over the resolved profile (token endpoint, method, client id,
  form params, assertion audience) plus SHA-256(secret material). Including the secret
  hash means two connections only share a token when they hold the same credential — a
  project with a wrong or stale key can never be served another project's cached token.
  The key never contains raw secrets.
- Valid while `now < fetchedAt + max(expires_in - 60, 0)` seconds.
- Concurrent callers for the same key share one in-flight request (including its
  retries). A failed fetch is not cached; the next call starts fresh.
- `invalidate(key)` drops an entry (used by the 401 retry, 8.3).

### 6.4 Errors

New error class (e.g. `OAuth2TokenError`) with a `kind`:

| kind | When | Evaluator effect | Topics effect |
|---|---|---|---|
| `config` | project-side: bad JWK / unsupported `kty` / public-only JWK / `alg` mismatch / Entra JWK without thumbprint | Block: `LLM_CONNECTION_AUTH_INVALID` | Pause (auth) |
| `credential` | token endpoint 400/401/403, missing `access_token`, 3xx | Block: `LLM_CONNECTION_AUTH_INVALID` | Pause (auth) |
| `disabled` | operator-side: allowlist unset / endpoint not on it | Evaluation fails with the clear "disabled" message, no queue retry, **no block** | Temporary failure, no pause |
| `unavailable` | transient failures after all retries, or fail-fast window | Evaluation fails, no queue retry, no block | Temporary failure, no pause |

`disabled` does not block (my call): project users cannot fix an env var, and one bad
deploy (e.g. allowlist set on web but missing on worker) would otherwise block every
OAuth2 evaluator in every project, each needing manual reactivation. No new
`EvaluatorBlockReason` (no Prisma migration).

Today `classifyEvaluatorLlmError.ts` only maps `APICallError` status 401 and a few message
patterns to `AUTH_INVALID`, so it must learn this class. The "no queue retry, no block"
behavior must be wired into the eval queue (`worker/src/queues/evalQueue.ts`) and the
experiment queue in whatever way those queues mark a job as finally failed. Topics has
its own mapping in `worker/src/features/topics/provider-error.ts`; it must map the kinds
as in the table.

## 7. SSRF protection and allowlist

- New env var `LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS`: comma-separated exact URLs.
  It applies to the **resolved** token endpoint, whatever the provider (an operator
  allowing Entra for one tenant lists
  `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`).
  Unset/empty ⇒ OAuth2 is disabled: create/update/upsert fail with
  `OAuth2 client credentials are disabled: set LANGFUSE_LLM_OAUTH2_ALLOWED_TOKEN_ENDPOINTS`,
  and calls through existing OAuth2 connections fail with a `disabled` error.
- Match: compare `new URL(x).href` of both sides (normalizes host case and default port;
  otherwise exact). Checked at write time **and** at call time.
- Scheme: `https:` required. Exception (self-hosted only, never on Langfuse Cloud):
  `http:` is allowed when the token endpoint host is also in the existing
  `LANGFUSE_LLM_CONNECTION_WHITELISTED_HOST`. This is what makes the local Keycloak
  test possible; the operator has to opt in twice.
- The request also passes the existing host/IP validation used for LLM base URLs.
- Both env vars go into the shared env module next to
  `LANGFUSE_LLM_CONNECTION_WHITELISTED_HOST` (`packages/shared/src/env.ts`), plus
  `web/src/env.mjs` / `worker/src/env.ts` if those re-declare server vars,
  all `.env*.example` files, and the `docker-compose*.yml` env passthrough.

## 8. Call path

### 8.1 Where the token is resolved

`openLLMConnection` (`packages/shared/src/server/llm/llmText.ts:369`) is sync and
private. Its callers `prepareLLMTextCall` (already async) and `embedLLMText` (async)
are where the token is resolved. For an OAuth2 connection:

1. Decrypt `secretKey`. For `private_key_jwt`, parse the JWK.
2. Resolve the profile, check the allowlist, then get a token from the cache (section 6).
3. Pass the token to the provider:
   - **openai** (both `createOpenAI` and `createOpenAICompatible`): `apiKey: token`
     (already sent as `Authorization: Bearer`).
   - **anthropic**: `authToken: token` and **no** `apiKey` (`@ai-sdk/anthropic` 4.0.79
     throws if both are set, and falls back to `ANTHROPIC_API_KEY` env if neither is).
4. `Authorization` is already in the secure fetch's sensitive-header list (stripped on
   cross-origin redirects).

Non-OAuth2 connections keep the exact current path.

Embeddings (`embedLLMText`, used by topic clustering) share `openLLMConnection`, so they
get OAuth2 through the same resolution. They must never send a raw secret.

### 8.2 Paths that bypass `openLLMConnection`

Some code decrypts `secretKey` itself and sends it as an API key. With an OAuth2
connection that would send the client secret or JWK to the gateway. Known:
- decision-model evaluators: `worker/src/features/evaluation/evalExecutionDeps.ts:302`,
  `web/src/features/evals/v2/server/evaluators/testEvaluator.ts:158`.

Each such path must reject OAuth2 connections with a clear `config` error (out of scope
to support them). The builder must do a repo-wide search for every `decrypt(` of a
connection's `secretKey` and cover all of them.

### 8.3 401 from the gateway

For OAuth2 connections, the fetch passed to the provider is wrapped: if the gateway
answers 401, drop the cache entry, get a fresh token, and re-send the same request
once with the new `Authorization` header. A second 401 goes back to the caller unchanged
(existing behavior: `AUTH_INVALID`). Works for streaming calls too, since the 401
arrives before any body is streamed. No other status is retried beyond today's behavior.

## 9. Write path (`web/src/features/llm-api-key/server/llmConnectionService.ts`)

Validation for OAuth2 connections (create, update, upsert, test, testUpdate):
- Adapter must be `openai` or `anthropic`.
- Config parses for the chosen provider (allowed method, required inputs).
- Allowlist enabled; resolved endpoint on it; scheme rule from section 7; SSRF host check.
- `private_key_jwt`: secret parses as JSON; `kty` ∈ {RSA, EC}; has `d`; resolved `alg`
  fits the key type (RS*/PS* for RSA, ES* matching the curve for EC); `importJWK`
  succeeds; Entra: thumbprint available (6.1).
- `client_secret_jwt`: secret length ≥ hash size of the algorithm (32/48/64 bytes for
  HS256/384/512, RFC 7518 §3.2).
- `client_secret_basic` / `client_secret_post`: non-empty secret.
- `extraHeaders` must not contain `Authorization` (case-insensitive).
- Error messages name the problem, never echo key material.

Update rules (tRPC update; the public API upsert always sends a secret):
- Empty secret keeps the stored one (existing rule), so e.g. `scope` can change
  without re-pasting.
- A new secret is **required** when any of these change: auth type (API key ↔ OAuth2),
  `provider`, `authMethod`, the resolved token endpoint, `clientId` — same reasoning as
  the existing "baseURL change needs a new secret" rule: the stored secret must not be
  sent to a different endpoint or client than it was entered for.

`getDisplaySecretKey`: OAuth2 branch before the existing logic (a JWK ends with `"}`,
which the current branch would mis-handle).

"Test connection": the existing test flow already calls `generateLLMText`, so it does a
real token fetch then a completion; token errors surface in the UI with their message.

## 10. UI and public API

**UI** (`web/src/features/public-api/components/CreateLLMApiKeyForm.tsx`; mockup reviewed
with the user, layout is indicative):
- For `openai` and `anthropic`: an **Authentication** choice using the same `Tabs`
  pattern Bedrock already uses: `API key` (default) | `OAuth2 (machine-to-machine)`.
- OAuth2: an **Identity provider** select (presets from 5.1, then Custom). The fields
  shown come from the provider profile: the provider's inputs, Client ID, a
  **Credential** choice limited to the allowed methods (presets use friendly labels such
  as "Client secret" / "Certificate (private key)"; Custom shows the raw method names),
  and for Custom the extra knobs (scope, audience, resource, assertion audience,
  assertion algorithm, send client_id with assertion).
- A read-only "Token endpoint" line shows the resolved URL for presets, so the operator
  knows what to put on the allowlist.
- Secret field: "Client secret" (`PasswordInput`) for secret methods, "Private JWK
  (JSON)" multi-line textarea for `private_key_jwt`. The design system has no Textarea;
  use `components/ui/textarea` unless the builder finds a better fit.
- Base URL, custom models, extra headers stay.
- Saving already runs the connection test first; no new button.
- Connection list: show the auth type and provider next to `displaySecretKey`. Never the JWK.

**Public API**: `PUT /api/public/llm-connections` and
`/api/public/organizations/llm-connections` accept `config.oauth2` (section 5) for
`openai`/`anthropic` with the section 9 validation; GET returns `config.oauth2`, never
`secretKey`. Update Fern (`fern/apis/server/definition/llm-connections.yml`), regenerate
with `pnpm run openapi:export`, pass `pnpm run openapi:check`.

Example (PingFederate via Custom, the first user's provisioning call):

```json
{
  "provider": "my-genai-gateway", "adapter": "openai",
  "baseURL": "https://genai.example.com/v1",
  "secretKey": "{\"kty\":\"RSA\",\"kid\":\"agent-x-2026\",...}",
  "config": { "oauth2": {
    "provider": "custom", "tokenEndpoint": "https://login.example.com/as/token.oauth2",
    "clientId": "agent-x", "authMethod": "private_key_jwt"
  } }
}
```

**Docs**: a short section in the self-hosting env var docs for the two new env vars
(this repo's docs, if they live here; otherwise note it in the PR).

## 11. Differences from `spec.md`

| spec.md | This design | Why |
|---|---|---|
| Only `private_key_jwt`; `client_secret_*` are non-goals | Four methods + provider presets + Custom | User: upstream, world-wide use; same model as SSO providers |
| `config.oauth2` = `{tokenEndpoint, clientId, scope, assertionAlgorithm}` | Adds `provider` (`custom` for PingFederate) and `authMethod` | Needed to pick preset and method |
| Cache key `endpoint|clientId|kid|scope` | Resolved profile + hash of the secret | A wrong key must never get another project's cached token |
| `https` only | `http` allowed when host also whitelisted (self-hosted) | Local Keycloak e2e test |
| No retry for token fetch | Configurable retries with backoff + 30 s fail-fast | User decision; protects worker slots during outages |
| Redirects not mentioned | Never followed | Would re-send secrets |
| Decision-model paths out of scope | Must reject OAuth2 explicitly | Otherwise raw secret is sent to the gateway |
| Embeddings: "free if same path" | Same path, explicitly must not send raw secret | Shares `openLLMConnection` |
| `openLLMConnection` becomes async (bulk of diff) | Resolve in the already-async callers | Smaller diff |

## 12. Tests

Follow the repo's existing styles. Shared unit tests in `packages/shared`; integration
tests in the worker next to `secureLlmFetch.test.ts` (real local HTTP server,
`helpers/localLlmServer.ts`); web server tests extend the existing suites
(`llm-api-key.servertest.ts`, `llm-connections-api.servertest.ts` and org variants).

**Unit (shared)**
1. Profile resolution for every provider: token endpoint, allowed methods, required
   inputs rejected when missing, assertion `aud`, `client_id` rule, form params.
2. Custom with defaults + `private_key_jwt` = the `spec.md` PingFederate contract
   (header/claims exact, no `client_id` in body); signature verifies with the public
   part of a generated RSA and EC key.
3. `alg` resolution order; no `kid` without JWK `kid`; Entra `x5t#S256` from JWK member
   and from `x5c`, rejection without either.
4. `client_secret_jwt`: HS256 default, verifies with the secret; length check.
5. Request body/headers per method; `client_secret_basic` form-encodes id and secret
   (test with `:`, `%`, `+`, space); optional params only when set.
6. Cache: hit within validity (no HTTP); refetch after `expires_in - 60`; missing
   `expires_in` ⇒ 300; different secret hash ⇒ different entry.
7. Single flight: 10 concurrent calls ⇒ 1 request (also while retrying).
8. Failed fetch is not cached; next call retries.
9. Retries: 5xx/429/timeout/network retried up to the env value then `unavailable`;
   400/401 not retried; backoff respects cap and `Retry-After` (fake timers);
   env `0` ⇒ single attempt; fail-fast window blocks then clears.
10. Errors: specified messages, no secret/assertion/token in message or logs (assert on
    captured log output too); 3xx not followed.
11. Allowlist: unset ⇒ disabled; not listed ⇒ error; exact match ⇒ ok; `http` rule.
12. Bad keys: public-only JWK, unsupported `kty`, `alg`/key mismatch ⇒ `config` error.
13. Evaluator and Topics error classification for each `kind`.

**Integration (worker)**
14. OpenAI adapter + OAuth2: fake token endpoint + fake `/v1/chat/completions`; request
    carries `Authorization: Bearer <minted token>`. One case per auth method.
15. Anthropic adapter (`/v1/messages`): bearer header present, no `x-api-key`.
16. Gateway 401 once then 200 ⇒ exactly one refetch and one retry.
17. Decision-model path with an OAuth2 connection ⇒ `config` error, nothing sent.
18. Existing non-OAuth2 suites unchanged and green.

**Web server**
19. Create/update/test via tRPC and PUT (project + org): stored `secretKey` encrypted,
    `displaySecretKey` correct, no secret in any response; a preset and Custom.
20. Update with empty secret keeps it; changing provider/endpoint/clientId/method
    without a secret is rejected.
21. `Authorization` in `extraHeaders` rejected; Anthropic `config.oauth2` accepted,
    other Anthropic config still rejected; OAuth2 disabled without env ⇒ clear error.

**UI client test**: extend `CreateLLMApiKeyForm.clienttest.tsx` for switching provider
(fields change) and the submitted config shape for one preset and Custom.

**End-to-end (docker-compose, run manually / by the agent, not in CI)**
- Langfuse built from this branch (`docker-compose.build.yml`) plus an override compose
  file adding: Keycloak (realm import with one confidential client per auth method;
  the `private_key_jwt` client registered with a public key generated at setup time),
  a small fake LLM server (Node, OpenAI + Anthropic routes, verifies the bearer token
  against Keycloak's JWKS, can be told to answer 401 once), and a fault-injection
  path in front of the token endpoint (5xx / slow responses) to exercise retries.
- Connections are created both with the **Keycloak preset** and with **Custom**
  (Custom pointed at Keycloak with `assertionAudience` set to the token endpoint, which
  Keycloak still accepts, to mirror the PingFederate shape).
- No real private keys committed: the setup script generates the test key pair into a
  git-ignored folder.
- A script drives the scenarios through the public API: create connections per method ×
  adapter, test connection, run an LLM-as-a-Judge evaluator on an ingested trace and see
  a score, expired token (short Keycloak token lifetime) is refreshed, disabled Keycloak
  client ⇒ evaluator blocked, token endpoint down ⇒ retries then failed evaluation without
  block, endpoint not on allowlist ⇒ rejected, gateway 401 once ⇒ recovered.
- Lives in its own folder (e.g. `scripts/e2e/llm-oauth2/`) with a README.
- Other presets (Entra, Okta, Auth0, ...) are covered by unit tests of their request
  shape only; no live accounts.

## 13. Logging

- Info on each successful token fetch: project id (and connection id if available),
  provider, token endpoint **host**, auth method, `expires_in`, attempt count.
- Warn on each retry: host, attempt, status/error kind.
- Never log the secret, JWK, assertion, access token, or success response bodies.

## 14. Left to the builder

- Exact wiring inside the secure fetch to disable redirect following.
- How `LLMConnectionConfigSchema` is widened (as long as other adapters stay as strict).
- How the "no queue retry, no block" outcome is expressed in the eval/experiment queues.
- Where the provider profile table lives so both server and UI import it (it holds no
  server-only code).
- Keycloak version and realm setup details; fake LLM server shape; e2e script language.
- Whether the UI disables the OAuth2 tab when the allowlist env is unset (server error
  is the minimum).
- Folder and file names not fixed above.

## 15. Delivery

- One PR from `feat/llm-connection-oauth2-client-credentials` to `main` of the fork
  (`labuzniq/langfuse`), additive and isolated so it can be rebased onto upstream and
  offered upstream.
- Before the PR: `/security-review`, a full code review, and `/simplify`.
- PR description: business summary, the section 11 differences, every **VERIFY** item
  from `spec.md` with its finding (below), test evidence, e2e results.

| spec.md VERIFY | Finding |
|---|---|
| Config schema path | `packages/shared/src/interfaces/customLLMProviderConfigSchemas.ts` — correct |
| `openLLMConnection` | `llmText.ts:369`, sync, private; callers already async |
| `createSecureLlmFetch` / `validateLlmConnectionBaseURL` | Correct names; reusable for the token POST |
| `jose` in shared | Not present; web has 6.2.3 |
| Anthropic `authToken` | Present in `@ai-sdk/anthropic` 4.0.79; exclusive with `apiKey` |
| `validateSecret` | `llmConnectionService.ts:267` |
| UI form path | `CreateLLMApiKeyForm.tsx` — correct |
| Env modules | `packages/shared/src/env.ts`, `web/src/env.mjs`, `worker/src/env.ts` |
| `EvaluatorBlockReason.LLM_CONNECTION_AUTH_INVALID` | Exists (`schema.prisma:1236`) |
| Gateway base URL | Not verifiable from code; confirm with the gateway team |
