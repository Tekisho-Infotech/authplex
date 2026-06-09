package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/authplex/internal/domain/admin"
	"github.com/authplex/pkg/sdk/httputil"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

type adminContextKey string

const adminCtxKey adminContextKey = "admin_context"

// AdminContext holds the authenticated admin's identity and permissions.
type AdminContext struct {
	Role      admin.AdminRole
	TenantIDs []string
	AdminID   string
}

// AdminFromContext extracts the AdminContext from the request context.
func AdminFromContext(ctx context.Context) *AdminContext {
	ac, _ := ctx.Value(adminCtxKey).(*AdminContext)
	return ac
}

// WithAdminContext returns a context with the AdminContext set.
func WithAdminContext(ctx context.Context, ac *AdminContext) context.Context {
	return context.WithValue(ctx, adminCtxKey, ac)
}

// JWTVerifier is a function that verifies a JWT token string and returns admin context.
// If nil, signature verification is skipped (backward-compatible for tests).
type JWTVerifier func(tokenStr string) (*AdminContext, error)

// AdminAuth is middleware that protects management endpoints with an API key or admin JWT.
type AdminAuth struct {
	apiKey    string
	verifyJWT JWTVerifier
}

// NewAdminAuth creates a new AdminAuth middleware.
// If apiKey is empty, all requests are allowed (development mode).
func NewAdminAuth(apiKey string) *AdminAuth {
	return &AdminAuth{apiKey: apiKey}
}

// WithJWTVerifier sets a JWT verification function for admin token authentication.
// When set, admin JWTs are cryptographically verified before trust.
func (a *AdminAuth) WithJWTVerifier(v JWTVerifier) *AdminAuth {
	a.verifyJWT = v
	return a
}

// Middleware returns an http.Handler that checks for a valid API key or admin JWT.
func (a *AdminAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no API key is configured (development mode)
		if a.apiKey == "" {
			ctx := WithAdminContext(r.Context(), &AdminContext{
				Role:    admin.RoleSuperAdmin,
				AdminID: "dev-mode",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		tokenStr := extractAPIKey(r)
		if tokenStr == "" {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "API key or admin token required")) //nolint:errcheck
			return
		}

		// Check if the token is an API key
		if subtle.ConstantTimeCompare([]byte(tokenStr), []byte(a.apiKey)) == 1 {
			ctx := WithAdminContext(r.Context(), &AdminContext{
				Role:    admin.RoleSuperAdmin,
				AdminID: "api-key",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try to verify as admin JWT — signature verification is required
		if a.verifyJWT == nil {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "invalid API key or admin token")) //nolint:errcheck
			return
		}
		ac, err := a.verifyJWT(tokenStr)
		if err != nil {
			httputil.WriteError(w, apperrors.New(apperrors.ErrUnauthorized, "invalid API key or admin token")) //nolint:errcheck
			return
		}

		// Enforce role-based access
		if enforceErr := enforceRole(ac, r); enforceErr != nil {
			httputil.WriteError(w, enforceErr) //nolint:errcheck
			return
		}

		ctx := WithAdminContext(r.Context(), ac)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// enforceRole checks if the admin's role permits the request.
func enforceRole(ac *AdminContext, r *http.Request) *apperrors.AppError {
	switch ac.Role {
	case admin.RoleSuperAdmin:
		return nil

	case admin.RoleReadonly:
		if r.Method != http.MethodGet {
			return apperrors.New(apperrors.ErrForbidden, "readonly admins can only perform GET requests")
		}
		return nil

	case admin.RoleAuditor:
		if r.Method != http.MethodGet {
			return apperrors.New(apperrors.ErrForbidden, "auditor admins can only perform GET requests")
		}
		if !strings.Contains(r.URL.Path, "/audit") {
			return apperrors.New(apperrors.ErrForbidden, "auditor admins can only access audit endpoints")
		}
		return nil

	case admin.RoleTenantAdmin:
		// Tokens issued before tenant scoping was introduced have a nil TenantIDs slice.
		// Return 401 rather than 403 so clients know to re-authenticate and get a new token.
		if ac.TenantIDs == nil {
			return apperrors.New(apperrors.ErrUnauthorized, "token predates tenant scoping — please re-authenticate to obtain a scoped token")
		}
		tenantID := extractTenantFromPath(r.URL.Path)
		if tenantID == "" {
			return apperrors.New(apperrors.ErrForbidden, "tenant_admin requires a specific tenant scope")
		}
		for _, id := range ac.TenantIDs {
			if id == tenantID {
				return nil
			}
		}
		return apperrors.New(apperrors.ErrForbidden, "tenant_admin is not authorized for this tenant")

	default:
		return apperrors.New(apperrors.ErrForbidden, "unknown admin role")
	}
}

// extractTenantFromPath returns the tenant ID segment from paths like /tenants/{id}/...
func extractTenantFromPath(path string) string {
	const prefix = "/tenants/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if idx := strings.Index(rest, "/"); idx != -1 {
		return rest[:idx]
	}
	return rest
}

// extractAPIKey gets the API key from Authorization: Bearer or X-API-Key header.
func extractAPIKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}
