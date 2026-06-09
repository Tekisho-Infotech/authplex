package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	domainadmin "github.com/authplex/internal/domain/admin"
	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides admin user management operations.
type Service struct {
	repo   domainadmin.AdminUserRepository
	hasher user.PasswordHasher
	logger *slog.Logger
}

// NewService creates a new admin service.
func NewService(repo domainadmin.AdminUserRepository, hasher user.PasswordHasher, logger *slog.Logger) *Service {
	return &Service{
		repo:   repo,
		hasher: hasher,
		logger: logger,
	}
}

// BootstrapRequest is the request to create the first admin user.
type BootstrapRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	BootstrapKey string `json:"bootstrap_key"`
}

// BootstrapResponse is the response after creating the first admin user.
type BootstrapResponse struct {
	ID    string              `json:"id"`
	Email string              `json:"email"`
	Role  domainadmin.AdminRole `json:"role"`
}

// Bootstrap creates the first super_admin user. Only works if no admin users exist.
// The bootstrapKey must match the configured admin API key.
func (s *Service) Bootstrap(ctx context.Context, req BootstrapRequest, configuredKey string) (*BootstrapResponse, *apperrors.AppError) {
	if configuredKey == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "AUTHPLEX_ADMIN_API_KEY must be configured for bootstrap")
	}

	if subtle.ConstantTimeCompare([]byte(req.BootstrapKey), []byte(configuredKey)) != 1 {
		return nil, apperrors.New(apperrors.ErrUnauthorized, "invalid bootstrap key")
	}

	count, err := s.repo.Count(ctx)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to count admin users", err)
	}
	if count > 0 {
		return nil, apperrors.New(apperrors.ErrConflict, "admin users already exist, bootstrap not allowed")
	}

	return s.createAdmin(ctx, req.Email, req.Password, domainadmin.RoleSuperAdmin, nil)
}

// LoginRequest is the request to authenticate an admin user.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login validates admin credentials and returns the admin user.
// The handler is responsible for signing the JWT.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*domainadmin.AdminUser, *apperrors.AppError) {
	if req.Email == "" || req.Password == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "email and password are required")
	}

	admin, err := s.repo.GetByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Warn("admin login failed: user not found", "email_hash", hashPII(req.Email))
		return nil, apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}

	if verifyErr := s.hasher.Verify(req.Password, admin.PasswordHash); verifyErr != nil {
		s.logger.Warn("admin login failed: invalid password", "admin_id", admin.ID)
		return nil, apperrors.New(apperrors.ErrUnauthorized, "invalid credentials")
	}

	s.logger.Info("admin login successful", "admin_id", admin.ID)
	return &admin, nil
}

// CreateAdminRequest is the request to create a new admin user.
type CreateAdminRequest struct {
	Email     string                `json:"email"`
	Password  string                `json:"password"`
	Role      domainadmin.AdminRole `json:"role"`
	TenantIDs []string              `json:"tenant_ids"`
}

// CreateAdmin creates a new admin user. Only super_admin can call this.
func (s *Service) CreateAdmin(ctx context.Context, req CreateAdminRequest) (*BootstrapResponse, *apperrors.AppError) {
	if !req.Role.IsValid() {
		return nil, apperrors.New(apperrors.ErrBadRequest, "invalid admin role")
	}

	return s.createAdmin(ctx, req.Email, req.Password, req.Role, req.TenantIDs)
}

// ListAdmins returns all admin users.
func (s *Service) ListAdmins(ctx context.Context) ([]BootstrapResponse, *apperrors.AppError) {
	admins, err := s.repo.List(ctx)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to list admin users", err)
	}

	result := make([]BootstrapResponse, 0, len(admins))
	for _, a := range admins {
		result = append(result, BootstrapResponse{
			ID:    a.ID,
			Email: a.Email,
			Role:  a.Role,
		})
	}
	return result, nil
}

func (s *Service) createAdmin(ctx context.Context, email, password string, role domainadmin.AdminRole, tenantIDs []string) (*BootstrapResponse, *apperrors.AppError) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "email is required")
	}
	if password == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "password is required")
	}
	if len(password) < 8 {
		return nil, apperrors.New(apperrors.ErrBadRequest, "password must be at least 8 characters")
	}

	id, err := generateID()
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to generate admin user ID", err)
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to hash password", err)
	}

	if tenantIDs == nil {
		tenantIDs = []string{}
	}

	now := time.Now().UTC()
	adminUser := domainadmin.AdminUser{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Role:         role,
		TenantIDs:    tenantIDs,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if createErr := s.repo.Create(ctx, adminUser); createErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to create admin user", createErr)
	}

	s.logger.Info("admin user created", "admin_id", id, "role", role)
	return &BootstrapResponse{
		ID:    id,
		Email: email,
		Role:  role,
	}, nil
}

func generateID() (string, error) {
	return uuid.New().String(), nil
}

// hashPII returns a truncated SHA-256 hash of PII for safe logging.
func hashPII(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", h[:8])
}
