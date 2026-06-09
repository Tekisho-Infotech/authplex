# AuthPlex — Go-To-Market & Career Plan

## Profile

**.NET and Java Architect** with protocol-level IAM expertise.  
Built AuthPlex from scratch — a production-grade, RFC-compliant OAuth 2.0/OIDC/SAML server.

### Positioning Statement

> "I'm a .NET and Java architect who built a production-grade OAuth 2.0/OIDC/SAML server from scratch.
> I understand identity at the protocol level — not just the config file level."

### Differentiators

- Built IAM from scratch (most architects only configure it)
- Protocol-level knowledge: RFC 9449 (DPoP), RFC 9126 (PAR), WebAuthn/FIDO2, SAML 2.0
- Polyglot: Go + Java + .NET + Node + Python (5-language SDK strategy)
- Compliance awareness: GDPR, HIPAA, SOC 2 architecture built-in
- Full-stack thinking: domain modeling → production hardening → DevOps → SDKs → Admin UI

---

## Four Revenue Tracks

---

## Track 1 — Remote Job ($140K–$220K)

### Target Roles (Priority Order)

| Role | Target Salary | Why You Win |
|---|---|---|
| Identity & Access Engineer | $160K–220K | Built IAM from scratch — direct proof |
| Security Architect (.NET/Java) | $150K–210K | Crypto, threat model, compliance demonstrated |
| Principal Backend Engineer | $150K–200K | Hexagonal architecture, multi-tenancy, Go + Java + .NET |
| Solutions Architect | $140K–190K | 5-language SDK strategy, system design breadth |
| Staff Engineer | $170K–240K | Architecture depth + implementation proof |

### Target Companies

**Tier 1 — IAM Specialists (Highest Match)**
- Okta / Auth0 — hire architects who understand protocols deeply
- Ping Identity — enterprise IAM, heavy Java/.NET
- ForgeRock (Ping) — open-source IAM background valued
- CyberArk — PAM + IAM, enterprise .NET/Java
- SailPoint — IGA (Identity Governance), Java-heavy

**Tier 2 — Enterprise SaaS (High Budget)**
- Fintech: Stripe, Plaid, Brex, Ramp
- Healthcare SaaS: Epic, Veeva, Athenahealth
- B2B SaaS: Salesforce, ServiceNow, Workday

**Tier 3 — Remote-First**
- GitLab, Shopify, Cloudflare, HashiCorp, 1Password

### CV / LinkedIn Positioning

**Headline:**
```
Identity & Access Architect | .NET • Java • Go | OAuth 2.0 • OIDC • SAML • WebAuthn
```

**Three bullets for every application:**
1. Designed and built a multi-tenant OAuth 2.0/OIDC/SAML server in Go — RFC 9449 (DPoP),
   RFC 9126 (PAR), WebAuthn/FIDO2, 57 endpoints, 812 tests, 80%+ coverage enforced
2. Implemented Postgres Row-Level Security, AES-256-GCM encryption at rest, bcrypt cost 12,
   mTLS — 9/10 OWASP Top 10 coverage
3. Architected 5-language SDK strategy (Go, Java, .NET, Node, Python) with Spring Boot
   and ASP.NET Core integration clients

### Interview Preparation

| Question | Your Answer Source |
|---|---|
| "How does PKCE prevent auth code interception?" | You implemented it — explain S256 hash flow |
| "What's the difference between opaque and JWT tokens?" | Built both — explain trade-offs |
| "How do you handle token revocation at scale?" | Token versioning on User/Client/Tenant — O(1) |
| "How would you design multi-tenant IAM?" | RLS, per-tenant keys, per-tenant MFA policy |
| "Walk me through your threat model" | You have THREAT_MODEL.md — use it |

### Timeline

| Month | Action |
|---|---|
| 1 | Polish CV, update LinkedIn, make AuthPlex repo public |
| 1–2 | Apply to 5 Tier 1 companies, 10 Tier 2 |
| 2–3 | Interview pipeline active |
| 3–4 | Offer stage |

---

## Track 2 — Consulting ($150–$300/hr)

### Platform Strategy

| Platform | Approach | Expected Rate |
|---|---|---|
| **Toptal** | Apply as architect — AuthPlex is your vetting proof | $150–250/hr |
| **Upwork** | Enterprise projects only ($10K+ budget filter) | $100–180/hr |
| **LinkedIn** | Direct inbound from CTOs — most valuable channel | $200–300/hr |
| **Direct outreach** | Auth0/Okta customers paying $30K+/year | $200–300/hr |

> **Drop Fiverr entirely.** Your floor rate is $150/hr. Fiverr cannot support that market.

### Five Consulting Services

**Service 1 — Auth Migration** *(Highest value)*
- Pitch: "Migrate your legacy auth (ADFS, custom sessions, Auth0) to a modern, self-hosted OAuth 2.0/OIDC stack"
- Target: Companies on Auth0 paying $20K–100K/year
- Value proposition: "Cut your auth bill by 80% and own your user data"
- Price: $15K–50K per project
- Timeline: 4–12 weeks

**Service 2 — IAM Architecture Review**
- Pitch: "Security audit and architecture review of your existing identity system"
- Target: Fintech, healthcare, B2B SaaS
- Deliverable: Written report, threat model, remediation roadmap
- Price: $5K–15K
- Timeline: 1–2 weeks

**Service 3 — Spring Security / ASP.NET Core OAuth Integration**
- Pitch: "Correctly configure OAuth 2.0 resource server in your Java or .NET application"
- Target: Teams who got it wrong (most of them)
- Price: $3K–10K
- Timeline: 1–3 weeks

**Service 4 — GDPR/HIPAA Auth Compliance**
- Pitch: "Bring your authentication layer into GDPR and HIPAA compliance"
- Target: EU-facing SaaS, healthcare platforms
- Price: $8K–25K
- Timeline: 2–6 weeks

**Service 5 — AuthPlex Deployment & Customisation**
- Pitch: "Self-hosted AuthPlex setup, customised to your stack and compliance requirements"
- Target: Companies who discover the open-source project
- Price: $5K–20K
- Timeline: 2–4 weeks

### LinkedIn Outreach Template

Target: CTOs/VPs Engineering at companies using Auth0/Okta

```
Hi [Name],

I noticed [Company] is using Auth0. I'm an identity architect
who recently built an OAuth 2.0/OIDC server from scratch —
I know exactly what Auth0 does under the hood.

If you're paying $30K+/year and considering alternatives,
or have specific compliance requirements Auth0 can't meet,
I'd love to chat.

15 minutes? Happy to share what I've learned.
```

### Consulting Timeline

| Month | Action |
|---|---|
| 1 | Apply to Toptal, set up Upwork profile with AuthPlex as centrepiece |
| 1–2 | 20 LinkedIn outreach messages/week to CTOs |
| 2–3 | First paid engagement ($3K–10K) |
| 3–6 | 2–3 concurrent clients, $15K–30K/month potential |

---

## Track 3 — Open Source Monetization (Open Core)

### Model

AuthPlex core stays **free and open-source (MIT)**. Premium features require a commercial license.

### Open Core Feature Split

| Feature | Community (Free) | Enterprise (Paid) |
|---|---|---|
| OAuth 2.0 / OIDC | ✅ | ✅ |
| Multi-tenancy | ✅ | ✅ |
| RBAC | ✅ | ✅ |
| Social login (6 providers) | ✅ | ✅ |
| SAML 2.0 | ✅ | ✅ |
| Audit logging (25+ events) | ✅ | ✅ |
| Admin UI | ✅ | ✅ |
| WebAuthn / FIDO2 | ✅ | ✅ |
| **LDAP / Active Directory** | ❌ | ✅ |
| **Risk-based adaptive MFA** | ❌ | ✅ |
| **Policy engine (ABAC)** | ❌ | ✅ |
| **Analytics dashboard** | ❌ | ✅ |
| **Auth flow builder** | ❌ | ✅ |
| **Commercial support SLA** | ❌ | ✅ |
| **Multi-region deployment** | ❌ | ✅ |

### License Pricing

| Tier | Price | Target |
|---|---|---|
| Community | Free | Developers, startups |
| Startup | $299/month | <$5M ARR SaaS, up to 10 tenants |
| Business | $999/month | Mid-market, up to 50 tenants, SLA |
| Enterprise | $3K–10K/month | Large orgs, unlimited tenants, LDAP, custom SLA |
| Self-hosted license | $5K–20K one-time | Companies that cannot use SaaS |

### Features To Build For Monetization (Priority Order)

| Feature | Effort | Revenue Impact |
|---|---|---|
| LDAP / Active Directory | 2–3 weeks | **Critical** — unlocks all enterprise deals |
| Magic links | 2 days | Competitive table checkbox |
| Account lockout | 2 days | Compliance requirement |
| Analytics dashboard | 1 week | Visible value, justifies subscription |
| Auth flow builder | 2 weeks | Key differentiator vs Keycloak |
| Risk-based adaptive MFA | 3 weeks | Enterprise upsell |

### Launch Steps

1. MIT license the core repo
2. Write README with: 30-second explainer, one-command Docker quickstart, comparison table, live demo link
3. Post to Hacker News "Show HN"
4. Post LinkedIn announcement with architecture diagram
5. Submit to awesome-go, awesome-selfhosted

---

## Track 4 — SaaS (AuthPlex Cloud)

### Positioning

> "Self-hosted Keycloak simplicity, Auth0 developer experience, at 20% of the cost."

### Competitor Comparison

| | Auth0 | Keycloak | **AuthPlex Cloud** |
|---|---|---|---|
| Setup time | Minutes | Days | Minutes |
| Self-hosted option | ❌ | ✅ | ✅ |
| Multi-tenant native | ✅ | Partial | ✅ |
| SAML | ✅ (paid tier) | ✅ | ✅ |
| LDAP | ✅ (paid tier) | ✅ | Roadmap |
| Price (10K MAU) | $240/month | Free (self-host) | $99/month |
| Price (100K MAU) | $2,000+/month | Free (self-host) | $499/month |

### SaaS Pricing Tiers

| Plan | MAU Limit | Price | Includes |
|---|---|---|---|
| Developer | 1,000 | Free | 1 tenant, community support |
| Startup | 10,000 | $99/month | 5 tenants, email support |
| Growth | 50,000 | $299/month | 20 tenants, SLA, SAML |
| Scale | 200,000 | $799/month | Unlimited tenants, priority support |
| Enterprise | Custom | Custom | LDAP, custom SLA, private deploy |

### Infrastructure Stack

| Component | Tool | Est. Monthly Cost |
|---|---|---|
| Compute | Fly.io or Hetzner | $50–200 |
| Postgres | Supabase or Neon | $25–100 |
| Redis | Upstash | $10–50 |
| Monitoring | Grafana Cloud (free tier) | $0 |
| Billing | Stripe (2.9% + 30¢) | Usage-based |
| DNS / CDN | Cloudflare | $0–20 |
| **Total fixed cost** | | **~$100–400/month** |

Break-even: **2 Startup customers** ($198/month covers infrastructure).

### SaaS Build Phases

| Phase | What To Build | Target Month |
|---|---|---|
| 1 | Deploy AuthPlex publicly, Stripe billing, basic dashboard | Month 2–3 |
| 2 | Tenant provisioning on signup, email onboarding flow | Month 3–4 |
| 3 | MAU usage metering, billing portal, upgrade/downgrade | Month 4–5 |
| 4 | LDAP connector (enterprise unlock), analytics dashboard | Month 5–6 |
| 5 | Multi-region, 99.9% SLA, enterprise contracts | Month 6–12 |

---

## Technical Fixes Required Before Launch

These must be done before any public positioning. Estimated: **10 working days**.

| Priority | Fix | Effort | Unlocks |
|---|---|---|---|
| 1 | Security headers (HSTS, CSP, X-Frame-Options) | 30 min | OWASP 10/10 |
| 2 | TLS enforcement middleware | 1 day | HIPAA partial close |
| 3 | Hard delete with cascade (`/users/{id}/purge`) | 2–3 days | GDPR Art. 17 |
| 4 | Data export endpoint (`/users/{id}/export`) | 1 day | GDPR Art. 15/20 |
| 5 | Alerting on suspicious activity | 2–3 days | SOC 2 CC7.1 |
| 6 | Secrets backend support (Vault / AWS Secrets Manager) | 3 days | SOC 2 secret management |
| 7 | Make repo public with polished README | 1 day | All tracks |
| 8 | Deploy live demo | 1 day | All tracks |

---

## 12-Month Roadmap

### Month 1 — Foundation (Do This First)

- [ ] Fix RLS wiring, query timeouts, security headers
- [ ] Make repo public with polished README
- [ ] Deploy live demo on Fly.io or Railway
- [ ] Post "Show HN" and LinkedIn announcement
- [ ] Apply to Toptal
- [ ] Submit remote job applications (5–10/week)

### Month 2–3 — First Revenue

- [ ] First consulting engagement via Toptal or Upwork ($3K–10K)
- [ ] Remote job interview pipeline active
- [ ] Add LDAP connector (largest enterprise unlock)
- [ ] AuthPlex Cloud live (Stripe billing + tenant provisioning)
- [ ] First paying SaaS customer

### Month 3–6 — Establish All Four Streams

- [ ] Remote job offer signed ($140K–180K)
- [ ] 2–3 concurrent consulting clients ($15K–25K/month potential)
- [ ] 10–20 SaaS customers ($1K–5K MRR)
- [ ] 500+ GitHub stars
- [ ] Conference talk submitted (NDC, JavaOne, Spring One, DevConf)

### Month 6–12 — Scale

- [ ] Grow SaaS to $10K–30K MRR
- [ ] Raise consulting rate to $200–250/hr
- [ ] Build enterprise pipeline (LDAP, ABAC, risk-based MFA)
- [ ] First enterprise contract ($3K–10K/month)
- [ ] Evaluate: is consulting or SaaS growing faster — double down on the winner

---

## Income Projection

| Stream | Month 3 | Month 6 | Month 12 |
|---|---|---|---|
| Remote job | $10K–15K/month | $13K–18K/month | $15K–20K/month |
| Consulting | $5K–10K/month | $15K–25K/month | $20K–40K/month |
| SaaS MRR | $500–1K | $2K–8K | $10K–30K |
| Open-source licensing | $0 | $500–2K | $3K–10K |
| **Total** | **$15K–26K** | **$30K–53K** | **$48K–100K** |

---

## The Single Most Important Action

**Make the repo public within the next 7 days.**

Every other track depends on it:
- Consulting clients Google you
- Recruiters check GitHub
- SaaS customers inspect the code before paying
- Conference organisers vet speakers by their public work

The code is good enough. Do not wait for it to be perfect.
