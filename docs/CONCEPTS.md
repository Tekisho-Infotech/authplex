# AuthPlex — Concepts Guide

A structured learning map for understanding the technologies and patterns that AuthPlex is built on.
Work through the sections in order — each layer builds on the previous one.

---

## 1. Identity & Auth Protocols

### OAuth 2.0 (RFC 6749)
The foundation of modern authorization. OAuth 2.0 is a delegation framework — it lets a user grant an application limited access to their resources without sharing their password.

**Key flows:**
- **Authorization Code** — browser redirects to auth server, gets a short-lived code, exchanges it for tokens. Used by web and mobile apps.
- **Client Credentials** — no user involved; a server authenticates itself directly. Used for machine-to-machine (M2M) communication.
- **Refresh Token** — a long-lived token used to obtain new access tokens without re-authentication.
- **Device Authorization (RFC 8628)** — for input-constrained devices (smart TVs, CLIs); user visits a URL on a separate device to authorize.

**Core concepts:**
- **Authorization Server (AS)** — issues tokens (AuthPlex is this)
- **Resource Server (RS)** — accepts tokens to protect APIs
- **Client** — the application requesting access (public vs confidential)
- **Scope** — what the client is requesting access to (`openid`, `profile`, `email`, `api:read`)
- **Token revocation (RFC 7009)** — explicit endpoint to invalidate a token before its expiry

---

### PKCE (RFC 7636) — Proof Key for Code Exchange
An extension to the Authorization Code flow that protects public clients (SPAs, mobile apps) from authorization code interception attacks.

**How it works:**
1. Client generates a random `code_verifier`
2. Client sends `code_challenge = BASE64URL(SHA256(code_verifier))` at the start of the flow
3. At token exchange, client sends the original `code_verifier`
4. Auth server recomputes the hash and verifies it matches

**Why it matters:** Without PKCE, a malicious app that intercepts the authorization code can exchange it for tokens. PKCE makes the code useless without the verifier.

---

### OpenID Connect (OIDC)
A thin identity layer on top of OAuth 2.0. While OAuth 2.0 answers "what can this app access?", OIDC answers "who is this user?"

**Key additions over OAuth 2.0:**
- **ID Token** — a JWT that identifies the user (sub, email, name, etc.)
- **UserInfo endpoint** — `/userinfo` returns user profile claims
- **Discovery document** — `/.well-known/openid-configuration` describes the server's capabilities (endpoints, algorithms, scopes)
- **Nonce** — prevents replay attacks on ID tokens

**Token types:**
| Token | Purpose | Lifetime |
|-------|---------|----------|
| Access Token | Authorize API calls | Short (1 hour) |
| ID Token | Identify the user | Short (1 hour) |
| Refresh Token | Get new access tokens | Long (30 days) |

---

### JWT — JSON Web Token (RFC 7519)
The wire format used for access tokens and ID tokens.

**Structure:** `BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)`

**Header** — algorithm (`alg`) and key ID (`kid`):
```json
{ "alg": "RS256", "typ": "JWT", "kid": "key-abc" }
```

**Payload** — claims (registered + custom):
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": ["client-1"],
  "exp": 1700000000,
  "iat": 1699996400,
  "jti": "unique-id",
  "tid": "tenant-1",
  "roles": ["admin"]
}
```

**Key registered claims:**
- `iss` — issuer (who created the token)
- `sub` — subject (who the token is about)
- `aud` — audience (who the token is for)
- `exp` — expiry (Unix timestamp)
- `iat` — issued at
- `jti` — JWT ID (unique identifier, used for blacklisting)

**Signing algorithms used in AuthPlex:**
- `RS256` — RSA + SHA-256 (asymmetric; public key verification)
- `ES256` — ECDSA + SHA-256 (asymmetric; smaller keys, faster verification)

---

### JWKS — JSON Web Key Set (RFC 7517)
The mechanism by which AuthPlex publishes its public keys so resource servers can verify token signatures without calling AuthPlex directly.

**Endpoint:** `/jwks`

**Why it matters:** Tokens are self-contained. Any service that has the public key can verify a token offline. This is what makes JWTs scalable.

**Key rotation:** AuthPlex rotates signing keys on a configurable schedule (`AUTHPLEX_KEY_ROTATION_DAYS`). Old tokens remain valid until they expire because the old public key stays in the JWKS until all tokens signed with it have expired.

---

### Token Introspection (RFC 7662)
An endpoint (`POST /introspect`) that lets a resource server ask the auth server "is this token currently valid?"

**When to use instead of local verification:**
- Token may have been revoked (blacklisted) since issuance
- Token uses opaque format (not JWT)
- Resource server doesn't want to manage JWKS rotation

**Response:**
```json
{ "active": true, "sub": "user-123", "exp": 1700000000, "iss": "...", "jti": "..." }
```
If `active: false`, the token is expired, revoked, or malformed.

---

### DPoP — Demonstration of Proof of Possession (RFC 9449)
Binds an access token to a specific client's cryptographic key pair. Even if the token is stolen, it cannot be used from a different client.

**How it works:**
1. Client generates an ephemeral key pair
2. At token request, client sends a `DPoP` header containing a signed JWT (the proof)
3. Auth server includes `cnf.jkt` (JWK Thumbprint of client's public key) in the access token
4. At each API call, client sends a new DPoP proof
5. Resource server verifies `ath` claim in proof = `BASE64URL(SHA256(access_token))`

**AuthPlex implementation:**
- `validateDPoPAth` verifies the `ath` claim in the DPoP proof at introspection
- `token.CNFClaim` carries the `jkt` binding in the JWT

---

## 2. MFA & Credentials

### TOTP — Time-Based One-Time Password (RFC 6238)
How authenticator apps (Google Authenticator, Authy) generate 6-digit codes.

**Algorithm:**
1. Server and client share a secret key (shown as QR code at enrollment)
2. Both compute `HMAC-SHA1(secret, floor(current_unix_time / 30))`
3. Extract 6 digits from the result
4. Codes change every 30 seconds; server accepts ±1 window for clock drift

**AuthPlex flow:** Enroll (`/mfa/totp/enroll`) → scan QR → confirm with first code (`/mfa/totp/confirm`) → required at every login (`/mfa/verify`)

---

### WebAuthn / FIDO2
Passkey authentication. No password, no shared secret — just a public/private key pair stored on the user's device (hardware key, biometric sensor, or platform authenticator).

**Key concepts:**
- **Relying Party (RP)** — the server (AuthPlex), identified by `rpId` (the domain)
- **Authenticator** — the device holding the private key (YubiKey, Face ID, Touch ID)
- **Registration (Attestation)** — device generates a key pair, stores private key, sends public key to server
- **Authentication (Assertion)** — device signs a server-generated challenge with the private key; server verifies with stored public key

**Why it's stronger than passwords:** The private key never leaves the device. Phishing is impossible because the credential is scoped to the exact domain.

---

### OTP via Email / SMS
Single-use codes sent out-of-band. Less secure than TOTP (vulnerable to SIM swap, email compromise) but simpler UX.

**AuthPlex flow:** Request OTP (`/otp/request`) → deliver via email/SMS → verify (`/otp/verify`) → issue session

---

### bcrypt Password Hashing
AuthPlex uses bcrypt to store passwords. Key properties:
- **Adaptive cost factor** — deliberately slow; increasing cost doubles the work for attackers
- **Salt** — random value included in hash; prevents rainbow table attacks
- **72-byte input limit** — bcrypt silently truncates inputs beyond 72 bytes; AuthPlex enforces this cap explicitly to prevent length-extension behavior

---

## 3. Federation

### SAML 2.0
XML-based SSO protocol dominant in enterprise environments. Predates OAuth; used by Okta, ADFS, Azure AD in enterprise SSO scenarios.

**Key concepts:**
- **Identity Provider (IdP)** — authenticates the user (e.g., Okta)
- **Service Provider (SP)** — the app the user wants to access (AuthPlex acts as SP)
- **Assertion** — XML document signed by IdP stating who the user is
- **ACS endpoint** — Assertion Consumer Service; where IdP posts the SAML response
- **Metadata** — XML document describing the SP's endpoints and certificates (`/saml/metadata`)

**AuthPlex flow:** `/saml/sso` → redirect to IdP → IdP posts assertion to `/saml/acs` → AuthPlex validates, issues OIDC tokens

---

### Social Login
Using an external OAuth provider (Google, GitHub, Microsoft, Apple) as an IdP. AuthPlex acts as the OAuth client to the social provider and as the auth server to your app.

**Flow:**
1. User clicks "Sign in with Google"
2. AuthPlex redirects to Google's authorization endpoint
3. Google redirects back to AuthPlex `/callback` with a code
4. AuthPlex exchanges code for Google's tokens, reads profile
5. AuthPlex links the external identity to a local user, issues its own tokens

**External identity linking:** The same Google account can log into multiple tenants. AuthPlex stores `(provider, external_subject_id) → internal_user_id` mappings.

---

### LDAP / Active Directory
Lightweight Directory Access Protocol — the protocol used by corporate directories (Active Directory, OpenLDAP).

**Key concepts:**
- **DN (Distinguished Name)** — unique identifier for an entry: `cn=John,ou=Users,dc=example,dc=com`
- **Bind** — authenticate to the directory (like a login)
- **Search filter** — query syntax: `(&(objectClass=person)(mail=john@example.com))`
- **OU (Organizational Unit)** — directory hierarchy node grouping users or groups

**AuthPlex use case:** Enterprise customers configure an LDAP connector so employees can log in with their corporate credentials without migrating to a new directory.

---

## 4. Multi-Tenancy

### Tenant Isolation
AuthPlex serves multiple organizations (tenants) from a single deployment. Each tenant's users, clients, tokens, and audit logs must be completely isolated — one tenant must never see another's data.

**Resolution strategies (configured via `AUTHPLEX_TENANT_MODE`):**
- `header` — tenant ID in `X-Tenant-ID` header (API / backend use)
- `domain` — tenant resolved from request hostname (`tenant.auth.example.com`)

---

### Row-Level Security (Postgres RLS)
A Postgres feature that enforces tenant isolation at the database level, independent of application code.

**How it works:**
1. Each table has a `tenant_id` column
2. RLS policy: `USING (tenant_id = current_setting('app.tenant_id'))`
3. Before each query, AuthPlex sets `SET LOCAL app.tenant_id = 'tenant-abc'`
4. Postgres automatically filters all reads and blocks all writes to other tenants

**Why it matters:** Even if application code has a bug and omits a `WHERE tenant_id = ?` clause, Postgres will still return only the correct tenant's rows. Defense in depth.

---

## 5. Security Patterns

### RBAC — Role-Based Access Control
Users are assigned roles; roles have permissions. Access decisions are made by checking whether the user's roles include a required permission.

```
User → [role: "editor"] → [permissions: "posts:write", "posts:read"]
```

AuthPlex includes roles and permissions as custom JWT claims (`roles`, `permissions`), so resource servers can make authorization decisions locally without an extra round-trip.

---

### Token Versioning — Instant Revocation
A technique to invalidate all tokens for a user or tenant without maintaining a blocklist of every issued token.

**How it works:**
- Each user and tenant has a `token_version` integer in the database
- Every issued token carries `tv` (token version) as a claim
- At introspection (or resource server verification), if the token's `tv < current_version`, the token is rejected
- To log out all devices: increment `token_version` by 1

**Trade-off:** Requires a database lookup per token verification (introspection). Acceptable for high-security scenarios.

---

### Refresh Token Rotation + Family Tracking
When a refresh token is used, it is immediately retired and a new one is issued. If the old token is presented again (replay), the entire token family is revoked.

**Family:** A chain of refresh tokens originating from a single login. All tokens in the chain share a `family_id`.

**Replay detection logic:**
```
token.rotated == true → replay detected → revoke entire family → alert security alerter
```

This limits the blast radius of a stolen refresh token: the attacker gets at most one use before the family is killed.

---

### Sliding Window Rate Limiting
Limits how many requests a client can make in a rolling time window (not a fixed window that resets at the top of the minute).

**Key:** `client_ip + ":" + client_id` — composite key prevents bypassing IP limits by rotating client IDs.

**AuthPlex defaults:** 20 requests / 1 minute on `/token`, `/mfa/verify`, `/otp/verify`

---

### Security Alerting (Sliding Window Threat Detection)
In-memory counters track failure events per IP. When a threshold is crossed, an alert fires (logged + delivered via webhook).

| Alert | Trigger | Window |
|-------|---------|--------|
| Brute Force | 5 login failures / IP | 10 min |
| MFA Bombing | 5 MFA failures / IP | 5 min |
| OTP Flooding | 5 OTP failures / IP | 5 min |
| Cred Stuffing | 20 login failures / IP (any users) | 15 min |
| Token Replay | 1 refresh token reused | Immediate |

---

### HTTPS Enforcement
`AUTHPLEX_ENFORCE_HTTPS=true` enables the `RequireHTTPS` middleware which:
- Checks `r.TLS != nil` (native TLS)
- Checks `X-Forwarded-Proto: https` (reverse proxy / load balancer)
- Redirects all plain HTTP requests with `301 Moved Permanently`

---

## 6. Go Architecture Patterns

### Hexagonal Architecture (Ports & Adapters)
The codebase is divided into three concentric layers:

```
domain/          ← Pure business logic. No imports from outer layers.
application/     ← Use cases. Orchestrates domain objects. No HTTP/DB imports.
adapter/         ← Infrastructure. HTTP handlers, Postgres repos, Redis cache.
```

**Rule:** Dependencies only point inward. `adapter` imports `application`; `application` imports `domain`; `domain` imports nothing from this project.

**Why:** You can swap Postgres for a different database, or HTTP for gRPC, without touching business logic. In-memory repositories are used in tests and local dev.

---

### Port / Adapter (Interface Pattern)
Domain packages define interfaces (ports):

```go
// domain/user/repository.go
type Repository interface {
    Create(ctx context.Context, u User) error
    GetByID(ctx context.Context, id, tenantID string) (User, error)
    ...
}
```

Adapters implement them:
```go
// adapter/postgres/user_repository.go
type UserRepository struct { db *sql.DB }
func (r *UserRepository) GetByID(...) (user.User, error) { ... }

// adapter/cache/user_repository.go  (in-memory, for dev/tests)
type InMemoryUserRepository struct { mu sync.Mutex; data map[string]user.User }
```

---

### Result[T] Monad
Instead of `(T, error)`, AuthPlex uses `Result[T]` which wraps both a value and an `AppError`. Forces the caller to handle the error path explicitly before accessing the value.

```go
cfgResult := config.Load()
cfg, appErr := cfgResult.Unwrap()
if appErr != nil { ... }
```

---

### Functional Options (`With*` Methods)
Services are constructed with mandatory dependencies, then configured with optional ones:

```go
authSvc := auth.NewService(codeRepo, jwksSvc, signer, log). // required
    WithRefreshRepo(r.refresh).                               // optional
    WithBlacklist(r.blacklist).
    WithAudit(auditService).
    WithAlerter(alerter)
```

This avoids massive constructor signatures and makes zero-value defaults safe.

---

## 7. Infrastructure

### PostgreSQL
- **ACID transactions** — atomicity, consistency, isolation, durability; critical for token operations
- **Connection pooling** — AuthPlex sets `MaxOpenConns(25)`, `MaxIdleConns(5)` to share connections across goroutines
- **Migrations** — schema changes applied in order at startup via embedded SQL files
- **UUID primary keys** — globally unique, no coordination needed across shards

### Redis
Short-lived, ephemeral data stored in Redis with TTL-based expiry:
- Authorization codes (10 min TTL)
- Sessions
- Device codes (15 min TTL)
- Token blacklist entries (TTL = remaining token lifetime)
- State parameters for OAuth flows

### Prometheus Metrics
AuthPlex exposes `/metrics` in Prometheus text format. Scraped by Grafana for dashboards and alerting. Standard HTTP middleware records request counts, latency histograms, and error rates.

### Structured Logging (slog)
All log output is structured (key-value pairs). Format varies by environment:
| Environment | Format | Level |
|-------------|--------|-------|
| local | text (human-readable) | debug |
| staging | JSON | info |
| production | JSON + trace correlation | error |

---

## Recommended Learning Order

Follow this sequence to build up understanding systematically:

```
1. JWT                    — understand the token format first
2. OAuth 2.0              — authorization flows
3. OIDC                   — identity on top of OAuth
4. PKCE                   — why public clients need it
5. Refresh tokens         — rotation, families, replay detection
6. JWKS + Introspection   — how resource servers verify tokens
7. DPoP                   — proof-of-possession binding
8. TOTP                   — MFA fundamentals
9. WebAuthn               — passkeys
10. SAML                  — enterprise federation (optional)
11. Multi-tenancy + RLS   — data isolation
12. RBAC                  — authorization model
13. Go hexagonal arch     — codebase structure
```

**The 80/20:** JWT + OAuth 2.0 + OIDC covers the majority of the codebase. Master those three and the rest is incremental.

---

## Reference — Key RFCs

| RFC | Topic |
|-----|-------|
| RFC 6749 | OAuth 2.0 |
| RFC 6750 | Bearer Token Usage |
| RFC 7009 | Token Revocation |
| RFC 7515 | JSON Web Signature (JWS) |
| RFC 7517 | JSON Web Key (JWK) |
| RFC 7519 | JSON Web Token (JWT) |
| RFC 7636 | PKCE |
| RFC 7662 | Token Introspection |
| RFC 7800 | Proof-of-Possession Key (cnf claim) |
| RFC 8628 | Device Authorization Grant |
| RFC 9449 | DPoP |
| OIDC Core 1.0 | OpenID Connect |
| OIDC Discovery 1.0 | Discovery document |
| RFC 6238 | TOTP |
| W3C WebAuthn | Passkeys / FIDO2 |
