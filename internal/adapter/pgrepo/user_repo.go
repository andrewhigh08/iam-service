package pgrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	resourceUser = "user"

	// Values of port.UserFilter.Status that narrow a listing.
	statusActive  = "active"
	statusBlocked = "blocked"

	// uniqueViolation is the PostgreSQL SQLSTATE of a unique constraint violation.
	uniqueViolation = "23505"
)

// likeEscaper makes the LIKE wildcard characters of a search term match literally.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// UserRepository implements port.UserRepository on PostgreSQL.
type UserRepository struct {
	repo
}

// NewUserRepository returns a UserRepository backed by db.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{repo: repo{db: db}}
}

// Create inserts user, filling its generated ID and timestamps.
// A taken email yields apperror.Conflict.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	if err := r.conn(ctx).Create(user).Error; err != nil {
		if isUniqueViolation(err) {
			return apperror.Conflict(resourceUser, "email", user.Email)
		}
		return apperror.Internal("failed to create user", err)
	}
	return nil
}

// FindByID returns the user with the given id or apperror.NotFound.
func (r *UserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	return r.findOne(ctx, "id = ?", id)
}

// FindByEmail returns the user with the given email or apperror.NotFound.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.findOne(ctx, "email = ?", email)
}

// findOne loads the single user matching the condition, reporting value as the missing id.
func (r *UserRepository) findOne(ctx context.Context, cond string, value any) (*domain.User, error) {
	var user domain.User
	if err := r.conn(ctx).Where(cond, value).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NotFound(resourceUser, value)
		}
		return nil, apperror.Internal("failed to find user", err)
	}
	return &user, nil
}

// UpdatePassword replaces the password columns of the user id and refreshes updated_at.
// Returns apperror.NotFound when no row matched.
func (r *UserRepository) UpdatePassword(ctx context.Context, id int64, hash string, temporary bool, changedAt time.Time) error {
	return r.updateColumns(ctx, id, map[string]any{
		"password_hash":       hash,
		"password_temporary":  temporary,
		"password_changed_at": changedAt,
	})
}

// SetBlocked writes the blocked flag of the user id and refreshes updated_at.
// Returns apperror.NotFound when no row matched.
func (r *UserRepository) SetBlocked(ctx context.Context, id int64, blocked bool) error {
	return r.updateColumns(ctx, id, map[string]any{"is_blocked": blocked})
}

// updateColumns writes columns plus updated_at to the row of the user id; the explicit column
// map keeps every other column untouched, so concurrent writers never overwrite each other.
func (r *UserRepository) updateColumns(ctx context.Context, id int64, columns map[string]any) error {
	columns["updated_at"] = r.db.NowFunc()
	res := r.conn(ctx).Model(&domain.User{}).Where("id = ?", id).Updates(columns)
	if res.Error != nil {
		return apperror.Internal("failed to update user", res.Error)
	}
	if res.RowsAffected == 0 {
		return apperror.NotFound(resourceUser, id)
	}
	return nil
}

// HardDelete physically removes the user with the given id. A missing user is not an error.
func (r *UserRepository) HardDelete(ctx context.Context, id int64) error {
	if err := r.conn(ctx).Where("id = ?", id).Delete(&domain.User{}).Error; err != nil {
		return apperror.Internal("failed to delete user", err)
	}
	return nil
}

// List returns one page of the users matching f, newest first, with the total match count.
// f.Page and f.PageSize must be positive: the handler clamps both, so any other value is a
// programming error and yields apperror.Internal rather than a substituted default.
func (r *UserRepository) List(ctx context.Context, f port.UserFilter) ([]domain.User, int64, error) {
	if f.Page < 1 || f.PageSize < 1 {
		return nil, 0, apperror.Internal("failed to list users",
			fmt.Errorf("invalid page %d or page size %d: both must be positive", f.Page, f.PageSize))
	}
	var total int64
	if err := r.filtered(ctx, f).Count(&total).Error; err != nil {
		return nil, 0, apperror.Internal("failed to count users", err)
	}
	users := []domain.User{}
	if total == 0 {
		return users, 0, nil
	}

	err := r.filtered(ctx, f).
		Order("created_at DESC, id DESC").
		Limit(f.PageSize).
		Offset((f.Page - 1) * f.PageSize).
		Find(&users).Error
	if err != nil {
		return nil, 0, apperror.Internal("failed to list users", err)
	}
	return users, total, nil
}

// ExistsByEmail reports whether a user with the given email exists.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.conn(ctx).Model(&domain.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, apperror.Internal("failed to check email existence", err)
	}
	return count > 0, nil
}

func (r *UserRepository) filtered(ctx context.Context, f port.UserFilter) *gorm.DB {
	q := r.conn(ctx).Model(&domain.User{})
	switch f.Status {
	case statusActive:
		q = q.Where("is_blocked = ?", false)
	case statusBlocked:
		q = q.Where("is_blocked = ?", true)
	}
	if search := strings.TrimSpace(f.Search); search != "" {
		pattern := "%" + likeEscaper.Replace(search) + "%"
		q = q.Where("email ILIKE ? OR full_name ILIKE ?", pattern, pattern)
	}
	return q
}

// isUniqueViolation reports whether err is a unique constraint violation, either translated
// by GORM or reported by the PostgreSQL driver.
func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}
