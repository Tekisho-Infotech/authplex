package admin

import (
	"context"
	"log/slog"
	"testing"

	"github.com/authplex/internal/adapter/cache"
	adaptcrypto "github.com/authplex/internal/adapter/crypto"
	domainadmin "github.com/authplex/internal/domain/admin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService() *Service {
	repo := cache.NewInMemoryAdminUserRepository()
	hasher := adaptcrypto.NewBcryptHasher()
	return NewService(repo, hasher, slog.Default())
}

func TestBootstrap_Success(t *testing.T) {
	svc := newTestService()
	resp, err := svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "test-key",
	}, "test-key")
	require.Nil(t, err)
	assert.NotEmpty(t, resp.ID)
}

func TestBootstrap_WrongKey(t *testing.T) {
	svc := newTestService()
	_, err := svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "wrong",
	}, "test-key")
	require.NotNil(t, err)
}

func TestBootstrap_SecondTime_Fails(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "key",
	}, "key")
	_, err := svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin2@test.com", Password: "password123", BootstrapKey: "key",
	}, "key")
	require.NotNil(t, err)
}

func TestLogin_Success(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "key",
	}, "key")

	admin, err := svc.Login(context.Background(), LoginRequest{Email: "admin@test.com", Password: "password123"})
	require.Nil(t, err)
	assert.NotEmpty(t, admin.ID)
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "key",
	}, "key")

	_, err := svc.Login(context.Background(), LoginRequest{Email: "admin@test.com", Password: "wrong"})
	require.NotNil(t, err)
}

func TestLogin_NonexistentUser(t *testing.T) {
	svc := newTestService()
	_, err := svc.Login(context.Background(), LoginRequest{Email: "nobody@test.com", Password: "pass"})
	require.NotNil(t, err)
}

func TestLogin_EmptyFields(t *testing.T) {
	svc := newTestService()
	_, err := svc.Login(context.Background(), LoginRequest{})
	require.NotNil(t, err)
}

func TestCreateAdmin(t *testing.T) {
	svc := newTestService()
	resp, err := svc.CreateAdmin(context.Background(), CreateAdminRequest{
		Email: "new@test.com", Password: "password123", Role: domainadmin.RoleReadonly,
	})
	require.Nil(t, err)
	assert.NotEmpty(t, resp.ID)
}

func TestCreateAdmin_ShortPassword(t *testing.T) {
	svc := newTestService()
	_, err := svc.CreateAdmin(context.Background(), CreateAdminRequest{
		Email: "new@test.com", Password: "short", Role: domainadmin.RoleReadonly,
	})
	require.NotNil(t, err)
}

func TestCreateAdmin_InvalidRole(t *testing.T) {
	svc := newTestService()
	_, err := svc.CreateAdmin(context.Background(), CreateAdminRequest{
		Email: "new@test.com", Password: "password123", Role: "invalid_role",
	})
	require.NotNil(t, err)
}

func TestListAdmins(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Bootstrap(context.Background(), BootstrapRequest{
		Email: "admin@test.com", Password: "password123", BootstrapKey: "key",
	}, "key")
	_, _ = svc.CreateAdmin(context.Background(), CreateAdminRequest{
		Email: "other@test.com", Password: "password123", Role: domainadmin.RoleReadonly,
	})

	admins, err := svc.ListAdmins(context.Background())
	require.Nil(t, err)
	assert.Len(t, admins, 2)
}

func TestHashPII(t *testing.T) {
	h := hashPII("user@example.com")
	assert.Contains(t, h, "sha256:")
	assert.Equal(t, h, hashPII("user@example.com"))
	assert.NotEqual(t, h, hashPII("other@example.com"))
}
