package fixtures

import (
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// UserFixtures provides test user data
type UserFixtures struct{}

// NewUserFixtures creates a new UserFixtures instance
func NewUserFixtures() *UserFixtures {
	return &UserFixtures{}
}

// ValidUser returns a valid user for testing
func (f *UserFixtures) ValidUser() *domain.User {
	return &domain.User{
		ID:           1,
		Email:        "test@example.com",
		PasswordHash: "$2a$10$rQJjO5KFz3v5KTjcPNTmEOl8y7Xz5k7Jw9q5n3YxV1z2A3B4C5D6E", // hashed "Password123!"
		PasswordType: domain.PasswordTypePermanent,
		FullName:     "Test User",
		IsBlocked:    false,
		CreatedAt:    time.Now().Add(-24 * time.Hour),
		UpdatedAt:    time.Now(),
		DeletedAt:    nil,
	}
}

// ValidUserWithID returns a valid user with a specific ID
func (f *UserFixtures) ValidUserWithID(id int64) *domain.User {
	user := f.ValidUser()
	user.ID = id
	return user
}

// BlockedUser returns a blocked user for testing
func (f *UserFixtures) BlockedUser() *domain.User {
	user := f.ValidUser()
	user.ID = 2
	user.Email = "blocked@example.com"
	user.IsBlocked = true
	return user
}

// OTPUser returns a user with one-time password for testing
func (f *UserFixtures) OTPUser() *domain.User {
	user := f.ValidUser()
	user.ID = 3
	user.Email = "otp@example.com"
	user.PasswordType = domain.PasswordTypeOneTime
	return user
}

// AdminUser returns an admin user for testing
func (f *UserFixtures) AdminUser() *domain.User {
	user := f.ValidUser()
	user.ID = 4
	user.Email = "admin@example.com"
	user.FullName = "Admin User"
	return user
}

// ValidCreateUserRequest returns a valid create user request
func (f *UserFixtures) ValidCreateUserRequest() *domain.CreateUserRequest {
	return &domain.CreateUserRequest{
		Email:        "newuser@example.com",
		Password:     "SecurePass123!",
		FullName:     "New User",
		Role:         "viewer",
		PasswordType: domain.PasswordTypePermanent,
	}
}

// ValidCreateUserRequestWithRole returns a create user request with specific role
func (f *UserFixtures) ValidCreateUserRequestWithRole(role string) *domain.CreateUserRequest {
	req := f.ValidCreateUserRequest()
	req.Role = role
	return req
}

// UsersList returns a list of users for testing pagination
func (f *UserFixtures) UsersList(count int) []domain.User {
	users := make([]domain.User, count)
	for i := 0; i < count; i++ {
		users[i] = domain.User{
			ID:           int64(i + 1),
			Email:        "user" + string(rune('0'+i)) + "@example.com",
			PasswordHash: "$2a$10$rQJjO5KFz3v5KTjcPNTmEOl8y7Xz5k7Jw9q5n3YxV1z2A3B4C5D6E",
			PasswordType: domain.PasswordTypePermanent,
			FullName:     "User " + string(rune('0'+i)),
			IsBlocked:    i%5 == 0, // Every 5th user is blocked
			CreatedAt:    time.Now().Add(-time.Duration(i) * time.Hour),
			UpdatedAt:    time.Now(),
		}
	}
	return users
}

// AuditLogFixtures provides test audit log data
type AuditLogFixtures struct{}

// NewAuditLogFixtures creates a new AuditLogFixtures instance
func NewAuditLogFixtures() *AuditLogFixtures {
	return &AuditLogFixtures{}
}

// ValidAuditLog returns a valid audit log for testing
func (f *AuditLogFixtures) ValidAuditLog() *domain.AuditLog {
	ip := "192.168.1.1"
	ua := "Mozilla/5.0"
	return &domain.AuditLog{
		ID:           1,
		UserID:       1,
		Action:       "user.create",
		ResourceType: "user",
		ResourceID:   "2",
		Details:      []byte(`{"email":"test@example.com"}`),
		IPAddress:    &ip,
		UserAgent:    &ua,
		CreatedAt:    time.Now(),
	}
}

// AuditLogsList returns a list of audit logs for testing
func (f *AuditLogFixtures) AuditLogsList(count int) []domain.AuditLog {
	logs := make([]domain.AuditLog, count)
	actions := []string{"user.create", "user.update", "user.block", "user.login"}

	for i := 0; i < count; i++ {
		logs[i] = domain.AuditLog{
			ID:           int64(i + 1),
			UserID:       int64(i%10 + 1),
			Action:       actions[i%len(actions)],
			ResourceType: "user",
			ResourceID:   string(rune('0' + i%10)),
			Details:      []byte(`{}`),
			CreatedAt:    time.Now().Add(-time.Duration(i) * time.Minute),
		}
	}
	return logs
}
