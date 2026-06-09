package admin

import "time"

// AdminRole defines the role of an admin user.
type AdminRole string

const (
	RoleSuperAdmin  AdminRole = "super_admin"
	RoleTenantAdmin AdminRole = "tenant_admin"
	RoleReadonly    AdminRole = "readonly"
	RoleAuditor    AdminRole = "auditor"
)

// ValidRoles returns all valid admin roles.
func ValidRoles() []AdminRole {
	return []AdminRole{RoleSuperAdmin, RoleTenantAdmin, RoleReadonly, RoleAuditor}
}

// IsValid checks if the role is a recognized admin role.
func (r AdminRole) IsValid() bool {
	switch r {
	case RoleSuperAdmin, RoleTenantAdmin, RoleReadonly, RoleAuditor:
		return true
	default:
		return false
	}
}

// AdminUser represents an admin user who can manage the AuthPlex system.
type AdminUser struct {
	ID           string
	Email        string
	PasswordHash []byte
	Role         AdminRole
	TenantIDs    []string // for tenant_admin scope
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AdminSession represents an active admin session.
type AdminSession struct {
	ID          string
	AdminUserID string
	Token       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}
