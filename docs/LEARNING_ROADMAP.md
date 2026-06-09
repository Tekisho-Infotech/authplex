# 🗺️ AuthPlex — Expert Learning Roadmap

> **Goal:** Become a full-stack expert in the AuthPlex codebase.
> **Estimated time:** 10–11 weeks
> **Critical path:** Phase 1 → 2 → 3 (non-negotiable foundation)

---

## 📋 Complete Concept Index

| # | Phase | Concepts | Time |
|---|---|---|---|
| 1 | Language & Tooling | Go, patterns, Result monad, HTTP, testing | 1 week |
| 2 | Cryptography | AES, RSA, EC, bcrypt, HMAC, JWK | 1 week |
| 3 | Auth Protocols | JWT, OAuth 2.0, OIDC, PKCE, SAML, DPoP | 3 weeks |
| 4 | Auth Mechanisms | Sessions, TOTP, WebAuthn, Social, OTP | 1 week |
| 5 | Architecture | Hexagonal, DDD, Ports & Adapters | 1 week |
| 6 | Multi-Tenancy & AuthZ | RBAC, RLS, token versioning, agent tokens | 1 week |
| 7 | Database Layer | PostgreSQL, Redis, migrations, repository pattern | 1 week |
| 8 | HTTP Layer | Middleware, security headers, CORS, rate limiting | 3 days |
| 9 | Observability | OpenTelemetry, Prometheus, slog, health checks | 3 days |
| 10 | Event-Driven | Webhooks, security alerting, async patterns | 2 days |
| 11 | Communications | SMTP, Twilio SMS, adapter pattern | 2 days |
| 12 | Testing Strategy | Test pyramid, testcontainers, E2E wiring | 1 week |
| 13 | Frontend | React, Vite, Tailwind, Playwright | 1 week |
| 14 | Deployment & Infra | Docker, feature flags, key rotation, 12-factor | 1 week |

---

## 🔵 Phase 1 — Language & Tooling Foundations

> **Why first:** Every other phase is written in Go. Without this, you can't read the code.

### Concepts

- [ ] **Go language** — types, interfaces, goroutines, channels, error wrapping, `crypto` stdlib
- [ ] **Go patterns** — functional options (`With*()`), build tags, `ldflags`, `slog` structured logging
- [ ] **Result monad** — `Result[T]` pattern, `AppError`, `ErrorCode` → HTTP status mapping
- [ ] **HTTP in Go** — `net/http`, middleware chaining, handler composition
- [ ] **Testify** — `assert`, `require`, table-driven tests
- [ ] **Build tags** — `//go:build functional`, `//go:build e2e`, `make` targets

### Key Files in AuthPlex

```
pkg/sdk/errors/result.go          ← Result[T] monad
pkg/sdk/errors/app_error.go       ← AppError + ErrorCode
pkg/sdk/httputil/                 ← WriteJSON / WriteRaw helpers
pkg/sdk/logger/                   ← slog wrapper
```

### Resources

| Topic | Where to Learn |
|---|---|
| Go tour | tour.golang.org |
| Effective Go | go.dev/doc/effective_go |
| Error handling | blog.golang.org/go1.13-errors |

---

## 🔐 Phase 2 — Cryptography Fundamentals

> **Why second:** Auth protocols are just applied cryptography. Understand the primitives first.

### Concepts

- [ ] **Symmetric crypto** — AES-256-GCM, key derivation, nonce/IV, authenticated encryption
- [ ] **HMAC-SHA256** — keyed hashing, signature verification, webhook signing
- [ ] **Asymmetric crypto** — RSA-2048, EC P-256, public/private key pairs, key generation
- [ ] **Digital signatures** — sign + verify flow, RS256 vs ES256 algorithms
- [ ] **Password hashing** — bcrypt, argon2, why passwords ≠ encryption, cost factors
- [ ] **JWK format** — how keys are serialized (`n`, `e`, `kty`, `use`, `kid`) and distributed

### Key Files in AuthPlex

```
internal/adapter/crypto/          ← KeyGenerator, JWTSigner, BCryptHasher, JWKConverter
internal/domain/token/token.go    ← Token signing/verification logic
```

### Key Insight

```
Encryption  = confidentiality (hide data)
Hashing     = integrity / fingerprint (can't reverse)
Signing     = authenticity (prove who sent it)
```

---

## 🔑 Phase 3 — Core Auth Protocols

> **Why third:** This is the heart of AuthPlex. Spend the most time here — 3 weeks minimum.

### 3a — JWT

- [ ] **Structure** — header.payload.signature, base64url encoding
- [ ] **Standard claims** — `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nonce`
- [ ] **Custom claims** — `tid` (tenant), `tv` (token version), `roles`, `permissions`, `endpoints`
- [ ] **Validation** — signature check, expiry, issuer, audience
- [ ] **Algorithms** — RS256 (RSA + SHA256), ES256 (ECDSA + P-256)

### 3b — OAuth 2.0

- [ ] **Authorization framework** — what OAuth solves, actors (client, server, resource owner)
- [ ] **Authorization Code + PKCE** (RFC 7636) — `code_challenge`, `code_verifier`, S256 method
- [ ] **Client Credentials** — M2M flows, no user context, service accounts
- [ ] **Refresh Token** — rotation, expiry, one-time use, family invalidation
- [ ] **Device Flow** (RFC 8628) — polling pattern for TV/CLI, `device_code`, `user_code`
- [ ] **Token Revocation** (RFC 7009) — revoking access/refresh tokens
- [ ] **Token Introspection** (RFC 7662) — opaque token validation, `active` field
- [ ] **DPoP** (RFC 9449) — proof-of-possession, `cnf` claim, replay protection

### 3c — OIDC

- [ ] **Identity layer on OAuth 2.0** — what OIDC adds (ID token, `userinfo`)
- [ ] **Discovery** — `.well-known/openid-configuration`, auto-configuration
- [ ] **JWKS endpoint** — public key distribution, `kid` matching, key rotation
- [ ] **ID token** — `nonce`, `at_hash`, `auth_time`, `acr`
- [ ] **`/userinfo` endpoint** — bearer token → user claims

### 3d — SAML 2.0

- [ ] **Actors** — Identity Provider (IdP), Service Provider (SP)
- [ ] **Assertions** — authentication + attribute statements, XML signatures
- [ ] **SP metadata** — `/saml/metadata`, entity ID, ACS URL
- [ ] **SSO initiation** — `/saml/sso`, `AuthnRequest`, relay state
- [ ] **ACS** — `/saml/acs`, assertion validation, session creation

### Key Files in AuthPlex

```
internal/application/auth/service.go      ← All OAuth/OIDC grant types
internal/application/auth/request.go      ← Token request validation
internal/application/discovery/           ← OIDC discovery document
internal/application/jwks/                ← Key pair management
internal/application/saml/                ← SAML SP implementation
internal/adapter/http/handler/            ← All HTTP endpoints
```

### OAuth 2.0 Grant Type Cheatsheet

| Grant Type | Use Case | User Involved? |
|---|---|---|
| Authorization Code + PKCE | SPA, mobile, web app | ✅ |
| Client Credentials | M2M, agents, services | ❌ |
| Refresh Token | Renew access without re-login | ✅ |
| Device Code | TV, CLI, IoT | ✅ |
| Resource Owner Password | Legacy only | ✅ |

---

## 🔓 Phase 4 — Authentication Mechanisms

> **Builds on Phase 3.** How users actually prove who they are.

### Concepts

- [ ] **Session management** — cookie security (`HttpOnly`, `Secure`, `SameSite`), TTL, rotation
- [ ] **TOTP (RFC 6238)** — HMAC-OTP, 30s time windows, backup codes, enrollment flow
- [ ] **WebAuthn / FIDO2** — passkeys, authenticator attestation, assertion, credential counter
- [ ] **Social login** — OAuth 2.0 provider callbacks, `state` CSRF protection, external identity linking
- [ ] **OTP via email/SMS** — one-time codes, delivery, expiry, rate limiting
- [ ] **MFA policies** — optional / required / per-tenant enforcement

### Key Files in AuthPlex

```
internal/application/mfa/            ← TOTP + WebAuthn enrollment/verify
internal/application/social/         ← Social login callback + state
internal/adapter/cache/               ← In-memory session store
internal/adapter/redis/               ← Redis-backed session store
```

### MFA Flow

```
Enroll → Store secret → Confirm with first code → Issue backup codes
Login  → Password OK → MFA challenge → TOTP/WebAuthn verify → Session
```

---

## 🏗️ Phase 5 — Software Architecture

> **Why here:** Once you understand what the system does, learn how it's organized.

### Concepts

- [ ] **Hexagonal Architecture** — domain (pure logic) → application (use cases) → adapter (infra)
- [ ] **Domain-Driven Design** — aggregates, value objects, repositories, no framework imports in domain
- [ ] **Port interfaces** — defined in domain packages, implemented in adapters, injected via constructor
- [ ] **Dependency inversion** — high-level modules don't depend on low-level modules
- [ ] **Functional options** — `With*()` for optional wiring (RBAC, audit, webhooks)
- [ ] **In-memory vs persistent adapters** — same interface, swapped per environment

### Layer Map

```
internal/domain/          ← Pure business logic. No I/O. No frameworks.
internal/application/     ← Use cases. Orchestrates domain via port interfaces.
internal/adapter/         ← Infrastructure: HTTP, Postgres, Redis, crypto, email, SMS
cmd/authplex/             ← Wiring: connects adapters to application layer
pkg/                      ← Reusable SDK: errors, httputil, logger, health
```

### Key Insight

```
domain/user/repository.go     ← defines the PORT (interface)
adapter/postgres/user_repo.go ← implements the PORT (Postgres)
adapter/cache/user_repo.go    ← implements the PORT (in-memory)
```

---

## 🏢 Phase 6 — Multi-Tenancy & Authorization

> **Enterprise-grade isolation and access control.**

### Concepts

- [ ] **Tenant resolution** — header-based (`X-Tenant-ID`) vs domain-based (`Host` header)
- [ ] **Tenant isolation** — scoped queries, per-tenant config (algorithm, MFA policy, rate limits)
- [ ] **RBAC model** — roles, permissions (`resource:action`), wildcard matching (`posts:*`)
- [ ] **User → Role assignments** — per-tenant, stored in `user_role_assignments`
- [ ] **JWT enrichment** — embedding `roles` + `permissions` arrays into token claims
- [ ] **Row-Level Security (RLS)** — PostgreSQL-level tenant isolation, policy per table
- [ ] **Token versioning** — `tv` claim for instant revocation without a blacklist lookup
- [ ] **Agent tokens** — `IsAgent` flag, `endpoints` claim, API path restriction

### Key Files in AuthPlex

```
internal/adapter/http/middleware/tenant.go   ← Tenant resolver middleware
internal/application/rbac/                   ← Role CRUD, permission assignment
internal/application/auth/service.go         ← JWT enrichment with roles/permissions
internal/adapter/postgres/migrations/015_*   ← RLS policies
```

### RBAC Model

```
Tenant
  └── Role (e.g. "editor")
        └── Permissions (e.g. ["posts:read", "posts:write", "comments:*"])
              └── User → Role Assignment
```

---

## 🗄️ Phase 7 — Database Layer

> **How data is stored, isolated, and expired.**

### Concepts

- [ ] **PostgreSQL** — DDL, indexes, foreign keys, cascade deletes, unique constraints, JSONB
- [ ] **pgx driver** — Go Postgres driver, connection pooling, `pgxpool`, context cancellation
- [ ] **Schema migrations** — versioned SQL files (001–020), up migrations, rollback strategy
- [ ] **Row-Level Security** — policies, `SET LOCAL app.tenant_id`, per-query isolation
- [ ] **Redis** — key-value store, TTLs, atomic operations, use for ephemeral data
- [ ] **Cache/Redis use cases** — authorization codes, device codes, token blacklist, OAuthState, sessions
- [ ] **go-redis** — Go Redis client, `Set`/`Get`/`Del`/`Expire`, pipeline
- [ ] **Repository pattern** — interface + multiple implementations (in-memory / Postgres / Redis)
- [ ] **In-memory cache adapter** — `internal/adapter/cache/` — used in dev and unit tests

### Key Files in AuthPlex

```
internal/adapter/postgres/            ← All Postgres repository implementations
internal/adapter/postgres/migrations/ ← 20 SQL migration files
internal/adapter/redis/               ← Redis-backed repos (sessions, codes, blacklist)
internal/adapter/cache/               ← In-memory repos (dev + unit tests)
internal/domain/*/repository.go       ← Port interfaces for each repo
pkg/sdk/database/                     ← DB connection utilities
```

### What Lives Where

| Store | Data | Why |
|---|---|---|
| PostgreSQL | Users, tenants, clients, roles, audit | Persistent, relational, RLS |
| Redis | Sessions, auth codes, device codes, blacklist, OAuthState | Ephemeral, TTL-native, fast |
| In-Memory | All of the above | Dev + unit tests (no Docker needed) |

---

## 🌐 Phase 8 — HTTP Layer & Security Headers

> **Production-grade HTTP server hardening.**

### Concepts

- [ ] **Middleware composition** — ordered chain, early exit, context propagation via `context.WithValue`
- [ ] **Security headers** — HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, referrer policy
- [ ] **CORS** — preflight (`OPTIONS`), origin allowlist, `Access-Control-*` headers
- [ ] **Rate limiting** — sliding window algorithm, per-IP limits, `Retry-After` header
- [ ] **HTTPS redirect** — HTTP → HTTPS 301, HSTS preload
- [ ] **Request ID** — unique per-request tracing token, `X-Request-ID` propagation
- [ ] **Admin auth** — dual: API key OR JWT, management endpoint protection

### Middleware Stack Order

```
RequireHTTPS       → redirect HTTP to HTTPS
RequestID          → attach unique request ID
SecurityHeaders    → set HSTS, CSP, X-Frame-Options
Tracing            → OpenTelemetry span start
CORS               → validate origin, handle preflight
TenantResolver     → extract tenant from header/domain
AdminAuth          → verify API key or JWT (management routes)
RateLimiter        → 20 req/min per IP, sliding window
```

### Key Files in AuthPlex

```
internal/adapter/http/middleware/    ← All middleware implementations
```

---

## 📊 Phase 9 — Observability

> **Seeing what the system is doing in production.**

### Concepts

- [ ] **OpenTelemetry** — traces, spans, attributes, instrumentation, exporter config
- [ ] **Prometheus** — counters/gauges/histograms, `/metrics` scraping, `client_golang`
- [ ] **Structured logging** — `slog` JSON output, log levels per environment, request ID in log lines
- [ ] **Health checks** — pluggable registry, liveness vs readiness, `/health` endpoint
- [ ] **Audit logging** — immutable append-only events, actor/resource/action model, query with filters

### Audit Event Types (25+)

```
login_success / login_failure / logout
register / email_verified / password_reset
token_issued / token_refreshed / token_revoked / agent_token_issued
mfa_enrolled / mfa_verified / mfa_failed
role_assigned / role_revoked
```

---

## 📡 Phase 10 — Event-Driven & Async Patterns

### Concepts

- [ ] **Webhooks** — event subscription per tenant, HMAC-SHA256 payload signing, event filtering
- [ ] **Async delivery** — goroutine-based fire-and-forget, 10s timeout, no retry on failure
- [ ] **Security alerting** — sliding window threat detection (configurable thresholds)
- [ ] **Alert types** — brute force (5 login fails/10 min), MFA bombing (5 fails/5 min), credential stuffing

### Key Files in AuthPlex

```
internal/application/webhook/      ← Webhook CRUD + event delivery
internal/application/security/     ← Threat detection + alerting
internal/application/audit/        ← Audit event logging + querying
```

---

## 📨 Phase 11 — Communications

### Concepts

- [ ] **SMTP** — email delivery, TLS/STARTTLS, authentication, dev console sender
- [ ] **Twilio SMS** — REST API, `AccountSID`/`AuthToken`, OTP SMS delivery
- [ ] **Adapter pattern for comms** — console sender (dev) vs real provider (prod), same interface

### Key Files in AuthPlex

```
internal/adapter/email/     ← SMTP sender + console sender
internal/adapter/sms/       ← Twilio sender + console sender
```

---

## 🧪 Phase 12 — Testing Strategy

> **How to test an auth system properly — no shortcuts.**

### Concepts

- [ ] **Test pyramid** — 85% unit / 10% functional / 5% E2E split and why
- [ ] **Build tags** — `//go:build functional` (Docker), `//go:build e2e` (full stack)
- [ ] **Testcontainers** — ephemeral Docker-based Postgres + Redis spun up per test
- [ ] **Table-driven tests** — Go idiom for exhaustive case coverage, `t.Run()` subtests
- [ ] **In-memory repos** — fake implementations for fast, no-infra unit tests
- [ ] **E2E wiring** — full server setup with real handlers, real middleware, zero mocks
- [ ] **Coverage enforcement** — 80% line threshold, `make coverage-check` in CI

### Test Pyramid in AuthPlex

```
Unit (85%)       → internal/application/*_test.go, no build tag, in-memory repos
Functional (10%) → //go:build functional, testcontainers, real Postgres/Redis
E2E (5%)         → //go:build e2e, full server, 141 subtests
Playwright (30)  → admin/ browser tests against running server
```

### Commands

```bash
make test-unit        # Fast — no Docker
make test-func        # Requires Docker (testcontainers)
make test-e2e         # Requires Docker, 300s timeout
make coverage-check   # Enforce 80% threshold
```

---

## ⚛️ Phase 13 — Frontend

### Concepts

- [ ] **React 18** — hooks (`useState`, `useEffect`, `useContext`), React Router v6, component model
- [ ] **Vite** — dev server, HMR, build tool, proxy config for API calls
- [ ] **Tailwind CSS** — utility-first, responsive prefixes, `@tailwind` directives
- [ ] **Playwright** — browser automation, `page.goto()`, `expect(locator)`, test fixtures

### Key Directories

```
web/       ← End-user facing app (login, register, MFA)
admin/     ← Admin dashboard (tenant management, user management, audit)
```

---

## 🚀 Phase 14 — Deployment & Infrastructure

### Concepts

- [ ] **Docker multi-stage builds** — build stage (Go compiler) + runtime stage (Alpine ~20MB)
- [ ] **Docker Compose** — dev / staging / prod environment files, service dependencies
- [ ] **ldflags** — injecting `version` and `commit` at build time (`-X main.Version=$(git rev-parse HEAD)`)
- [ ] **12-factor app** — config via env vars, stateless processes, disposable containers
- [ ] **Key rotation** — 90-day JWK rotation, overlap period, old key grace expiry
- [ ] **Feature flags** — `AUTHPLEX_FEATURE_SAML`, `_WEBAUTHN`, `_AUDIT`, `_ADMIN_UI` toggles
- [ ] **Environment-based config** — `caarlos0/env` struct tags, `AUTHPLEX_*` namespace

### Config Cheatsheet

```bash
AUTHPLEX_ENV=production              # local | staging | production
AUTHPLEX_DATABASE_DSN=postgres://... # Postgres connection string
AUTHPLEX_REDIS_URL=redis://...       # Redis (optional)
AUTHPLEX_TENANT_MODE=header          # header | domain
AUTHPLEX_ENFORCE_HTTPS=true
AUTHPLEX_KEY_ROTATION_DAYS=90
AUTHPLEX_FEATURE_SAML=true
AUTHPLEX_FEATURE_WEBAUTHN=true
```

---

## 🗓️ Suggested Weekly Schedule

```
Week 1    → Phase 1  (Go foundations)
Week 2    → Phase 2  (Cryptography)
Week 3-5  → Phase 3  (Auth protocols — JWT, OAuth, OIDC, SAML)
Week 6    → Phase 4  (MFA mechanisms)
Week 7    → Phase 5 + 6 (Architecture + Multi-tenancy)
Week 8    → Phase 7  (Database: Postgres + Redis + cache)
Week 9    → Phase 8 + 9 + 10 (HTTP + Observability + Events)
Week 10   → Phase 11 + 12 (Comms + Testing)
Week 11   → Phase 13 + 14 (Frontend + Deployment)
```

---

## ⚠️ Critical Path

> Skip these at your own risk. Everything else depends on them.

1. **Go interfaces + error handling** — the entire codebase is interface-driven
2. **JWT** — every request in AuthPlex touches a token
3. **OAuth 2.0 + OIDC** — the primary protocol this system implements
4. **Hexagonal Architecture** — without this, the code structure won't make sense

---

## 📚 Quick Reference — All Concepts (Flat List)

<details>
<summary>Click to expand full concept list (70+ concepts)</summary>

**Go & Tooling**
- Go language (types, interfaces, goroutines, channels, error wrapping)
- Functional options pattern (`With*()`)
- Build tags (`//go:build functional`, `//go:build e2e`)
- `ldflags` build metadata injection
- `slog` structured logging
- `Result[T]` monad pattern
- `AppError` with `ErrorCode` → HTTP status mapping
- `net/http` middleware composition

**Cryptography**
- AES-256-GCM symmetric encryption
- HMAC-SHA256 keyed hashing
- RSA-2048 key pairs
- EC P-256 key pairs
- Digital signatures (RS256, ES256)
- bcrypt / argon2 password hashing
- JWK format serialization

**Auth Protocols**
- JWT (structure, claims, validation)
- OAuth 2.0 (authorization framework)
- Authorization Code + PKCE (RFC 7636)
- Client Credentials grant
- Refresh Token grant + rotation
- Device Authorization Flow (RFC 8628)
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
- DPoP proof-of-possession (RFC 9449)
- OIDC discovery + JWKS
- SAML 2.0 SP/IdP flow

**Authentication Mechanisms**
- Session management (cookies, TTL, rotation)
- TOTP (RFC 6238)
- WebAuthn / FIDO2
- Social login (OAuth 2.0 callbacks)
- OTP via email + SMS
- MFA policies (optional / required)

**Architecture**
- Hexagonal Architecture (Ports & Adapters)
- Domain-Driven Design (aggregates, value objects)
- Port interfaces (domain → adapter)
- Dependency inversion principle
- Repository pattern

**Multi-Tenancy & Authorization**
- Header-based vs domain-based tenant resolution
- Per-tenant isolation (scoped queries)
- RBAC (roles, permissions, wildcard matching)
- JWT enrichment (roles + permissions in claims)
- Row-Level Security (PostgreSQL)
- Token versioning (`tv` claim)
- Agent tokens (`endpoints` claim)

**Database**
- PostgreSQL (DDL, indexes, RLS)
- pgx Go driver + connection pooling
- Schema migrations (versioned SQL)
- Redis (key-value, TTL, atomic ops)
- go-redis client
- In-memory cache adapter

**HTTP Layer**
- Middleware chain composition
- Security headers (HSTS, CSP, X-Frame-Options)
- CORS handling
- Sliding window rate limiting
- HTTPS redirect
- Request ID propagation
- Admin auth middleware (API key + JWT)

**Observability**
- OpenTelemetry tracing
- Prometheus metrics
- `slog` JSON logging (env-based levels)
- Health check registry
- Audit logging (immutable, queryable)

**Event-Driven**
- Webhook subscriptions + HMAC delivery
- Async fire-and-forget goroutines
- Security alerting (sliding window threat detection)

**Communications**
- SMTP email delivery
- Twilio SMS delivery
- Console adapters for dev

**Testing**
- Test pyramid (unit / functional / E2E)
- Testcontainers (Docker-based integration tests)
- Table-driven tests
- In-memory repository fakes
- E2E server wiring (zero mocks)
- 80% coverage enforcement

**Frontend**
- React 18 + React Router
- Vite build tool + HMR
- Tailwind CSS
- Playwright E2E

**Deployment**
- Docker multi-stage builds
- Docker Compose (dev / staging / prod)
- 12-factor app principles
- JWK key rotation (90-day cycle)
- Feature flags (env-based toggles)
- `caarlos0/env` config loading

</details>

---

*Last updated: 2026-06-06 | AuthPlex v0.x*
