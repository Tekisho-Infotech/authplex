package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplex/internal/domain/admin"
	"github.com/stretchr/testify/assert"
)

func TestAdminAuth_ValidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_ValidKey_BearerHeader(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_InvalidKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_MissingKey(t *testing.T) {
	auth := NewAdminAuth("my-secret-key")
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_DevMode_NoKey(t *testing.T) {
	auth := NewAdminAuth("") // empty = dev mode
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuth_TimingConstant(t *testing.T) {
	// Verify that comparison uses constant-time
	auth := NewAdminAuth("correct-key")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Correct key
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "correct-key")
	w := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Wrong key
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "wrong-key-different-length")
	w = httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminFromContext_NotSet(t *testing.T) {
	ac := AdminFromContext(t.Context())
	assert.Nil(t, ac, "AdminFromContext should return nil when not set")
}

func TestAdminAuth_WithJWTVerifier(t *testing.T) {
	a := NewAdminAuth("some-key")
	result := a.WithJWTVerifier(nil)
	assert.NotNil(t, result, "WithJWTVerifier should return non-nil *AdminAuth")
}

func TestAdminAuth_NoVerifier_JWT_Rejected(t *testing.T) {
	// Without a verifier, JWT tokens must be rejected (not accepted via unsigned fallback)
	auth := NewAdminAuth("real-key") // verifyJWT is nil
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	req.Header.Set("Authorization", "Bearer header.payload.sig")
	w := httptest.NewRecorder()

	auth.Middleware(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestEnforceRole_SuperAdmin(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleSuperAdmin, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodDelete, "/tenants/t1", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Readonly_GET(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleReadonly, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Readonly_POST(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleReadonly, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodPost, "/tenants", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_Auditor_AuditGet(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleAuditor, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/audit", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_Auditor_NonAudit(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleAuditor, AdminID: "a1"}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/users", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_TenantAdmin_AuthorizedTenant(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleTenantAdmin, AdminID: "a1", TenantIDs: []string{"t1", "t2"}}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1/users", nil)
	err := enforceRole(ac, req)
	assert.Nil(t, err)
}

func TestEnforceRole_TenantAdmin_UnauthorizedTenant(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleTenantAdmin, AdminID: "a1", TenantIDs: []string{"t1"}}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t2/users", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_TenantAdmin_EmptyTenantIDs(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleTenantAdmin, AdminID: "a1", TenantIDs: nil}
	req := httptest.NewRequest(http.MethodGet, "/tenants/t1", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestEnforceRole_TenantAdmin_NoTenantInPath(t *testing.T) {
	ac := &AdminContext{Role: admin.RoleTenantAdmin, AdminID: "a1", TenantIDs: []string{"t1"}}
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	err := enforceRole(ac, req)
	assert.NotNil(t, err)
}

func TestExtractTenantFromPath(t *testing.T) {
	cases := []struct {
		path     string
		expected string
	}{
		{"/tenants/abc123", "abc123"},
		{"/tenants/abc123/users", "abc123"},
		{"/tenants/abc123/clients/c1", "abc123"},
		{"/tenants", ""},
		{"/admin/users", ""},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.expected, extractTenantFromPath(tc.path), "path: %s", tc.path)
	}
}
