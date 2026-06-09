package admin

import "context"

// AdminUserRepository is the port interface for admin user persistence.
type AdminUserRepository interface {
	Create(ctx context.Context, user AdminUser) error
	GetByEmail(ctx context.Context, email string) (AdminUser, error)
	GetByID(ctx context.Context, id string) (AdminUser, error)
	List(ctx context.Context) ([]AdminUser, error)
	Count(ctx context.Context) (int, error)
}
