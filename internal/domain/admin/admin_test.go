package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidRoles(t *testing.T) {
	roles := ValidRoles()
	assert.Contains(t, roles, RoleSuperAdmin)
	assert.Contains(t, roles, RoleTenantAdmin)
	assert.Contains(t, roles, RoleReadonly)
	assert.Contains(t, roles, RoleAuditor)
	assert.Len(t, roles, 4)
}

func TestAdminRole_IsValid(t *testing.T) {
	assert.True(t, RoleSuperAdmin.IsValid())
	assert.True(t, RoleTenantAdmin.IsValid())
	assert.True(t, RoleReadonly.IsValid())
	assert.True(t, RoleAuditor.IsValid())
	assert.False(t, AdminRole("unknown").IsValid())
	assert.False(t, AdminRole("").IsValid())
}
