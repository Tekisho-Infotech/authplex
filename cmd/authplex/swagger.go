// Authplex API — swagger metadata for swag code generation.
//
// Run `swag init -g cmd/authplex/main.go -o docs` to regenerate docs/docs.go.
//
// @title           Authplex API
// @version         1.0.0
// @description     Multi-tenant authentication and identity platform with OAuth 2.0, OIDC, SAML 2.0, MFA (TOTP + WebAuthn), and a full management API.
//
// @contact.name   Authplex Support
// @contact.email  support@authplex.io
//
// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host      localhost:8080
// @BasePath  /
//
// @securityDefinitions.apikey  AdminAuth
// @in                          header
// @name                        Authorization
// @description                 Admin JWT from POST /admin/login (1-hour TTL). Format: Bearer <token>
//
// @securityDefinitions.apikey  SessionAuth
// @in                          header
// @name                        Authorization
// @description                 User session token from POST /login. Format: Bearer <session_token>
//
// @tag.name         oidc
// @tag.description  OAuth 2.0 / OIDC protocol endpoints — RFC-compliant raw JSON (no envelope)
//
// @tag.name         auth
// @tag.description  User authentication — register, login, logout, OTP, password reset
//
// @tag.name         mfa
// @tag.description  Multi-factor authentication — TOTP and WebAuthn
//
// @tag.name         saml
// @tag.description  SAML 2.0 identity federation
//
// @tag.name         social
// @tag.description  Social login OAuth callback
//
// @tag.name         admin
// @tag.description  Admin user bootstrap and management
//
// @tag.name         tenants
// @tag.description  Tenant management (admin auth required)
//
// @tag.name         clients
// @tag.description  OAuth client management (admin auth required)
//
// @tag.name         providers
// @tag.description  Identity provider management (admin auth required)
//
// @tag.name         roles
// @tag.description  Role-based access control (admin auth required)
//
// @tag.name         users
// @tag.description  User management — admin CRUD and GDPR operations (admin auth required)
//
// @tag.name         webhooks
// @tag.description  Webhook management (admin auth required)
//
// @tag.name         audit
// @tag.description  Audit log access (admin auth required)
//
// @tag.name         system
// @tag.description  Health check and Prometheus metrics
package main
