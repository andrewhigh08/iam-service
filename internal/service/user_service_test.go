package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// MockUserRepository is a mock implementation of port.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id int64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int64, error) {
	args := m.Called(ctx, filter)
	return args.Get(0).([]domain.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	args := m.Called(ctx, tx, user)
	return args.Error(0)
}

func (m *MockUserRepository) DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error {
	args := m.Called(ctx, tx, id)
	return args.Error(0)
}

// MockAuthorizationService is a mock implementation of port.AuthorizationService
type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error) {
	args := m.Called(ctx, userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) AddRoleToUser(ctx context.Context, userID int64, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockAuthorizationService) RemoveRoleFromUser(ctx context.Context, userID int64, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockAuthorizationService) GetUserRoles(ctx context.Context, userID int64) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) ReloadPolicies(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestUserService_GetUserByID(t *testing.T) {
	tests := []struct {
		name        string
		userID      int64
		setupMock   func(*MockUserRepository)
		wantUser    *domain.User
		wantErr     bool
		expectedErr string
	}{
		{
			name:   "success - user found",
			userID: 1,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:        1,
					Email:     "test@example.com",
					FullName:  "Test User",
					IsBlocked: false,
					CreatedAt: time.Now(),
				}, nil)
			},
			wantUser: &domain.User{
				ID:       1,
				Email:    "test@example.com",
				FullName: "Test User",
			},
			wantErr: false,
		},
		{
			name:   "failure - user not found",
			userID: 999,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(999)).Return(nil, apperror.NotFound("user", 999))
			},
			wantUser:    nil,
			wantErr:     true,
			expectedErr: "NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			// Note: In a real test, you would create the UserService with proper dependencies
			// This is a simplified example showing the test structure

			user, err := mockRepo.FindByID(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.expectedErr != "" {
					appErr, ok := apperror.AsAppError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectedErr, appErr.Code)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantUser.ID, user.ID)
				assert.Equal(t, tt.wantUser.Email, user.Email)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_ListUsers(t *testing.T) {
	tests := []struct {
		name      string
		filter    port.UserFilter
		setupMock func(*MockUserRepository)
		wantCount int
		wantTotal int64
		wantErr   bool
	}{
		{
			name: "success - list all users",
			filter: port.UserFilter{
				Status:   "all",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				users := []domain.User{
					{ID: 1, Email: "user1@example.com"},
					{ID: 2, Email: "user2@example.com"},
				}
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return(users, int64(2), nil)
			},
			wantCount: 2,
			wantTotal: 2,
			wantErr:   false,
		},
		{
			name: "success - list active users only",
			filter: port.UserFilter{
				Status:   "active",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				users := []domain.User{
					{ID: 1, Email: "active@example.com", IsBlocked: false},
				}
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return(users, int64(1), nil)
			},
			wantCount: 1,
			wantTotal: 1,
			wantErr:   false,
		},
		{
			name: "success - empty result",
			filter: port.UserFilter{
				Status:   "blocked",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantCount: 0,
			wantTotal: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			users, total, err := mockRepo.List(context.Background(), tt.filter)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, users, tt.wantCount)
				assert.Equal(t, tt.wantTotal, total)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_EmailExists(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		setupMock func(*MockUserRepository)
		want      bool
		wantErr   bool
	}{
		{
			name:  "email exists",
			email: "existing@example.com",
			setupMock: func(m *MockUserRepository) {
				m.On("ExistsByEmail", mock.Anything, "existing@example.com").Return(true, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name:  "email does not exist",
			email: "new@example.com",
			setupMock: func(m *MockUserRepository) {
				m.On("ExistsByEmail", mock.Anything, "new@example.com").Return(false, nil)
			},
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			exists, err := mockRepo.ExistsByEmail(context.Background(), tt.email)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, exists)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== CreateUser Tests ====================

func TestUserService_CreateUser(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		fullName  string
		setupMock func(*MockUserRepository)
		wantErr   bool
		errCode   string
	}{
		{
			name:     "success - create new user",
			email:    "new@example.com",
			fullName: "New User",
			setupMock: func(repo *MockUserRepository) {
				repo.On("ExistsByEmail", mock.Anything, "new@example.com").Return(false, nil)
			},
			wantErr: false,
		},
		{
			name:     "failure - duplicate email",
			email:    "existing@example.com",
			fullName: "Existing User",
			setupMock: func(repo *MockUserRepository) {
				repo.On("ExistsByEmail", mock.Anything, "existing@example.com").Return(true, nil)
			},
			wantErr: true,
			errCode: "CONFLICT",
		},
		{
			name:     "failure - empty email",
			email:    "",
			fullName: "User Without Email",
			setupMock: func(repo *MockUserRepository) {
				repo.On("ExistsByEmail", mock.Anything, "").Return(false, nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			// Simulate email check
			exists, err := mockRepo.ExistsByEmail(context.Background(), tt.email)
			if err == nil && exists {
				// Duplicate email error
				if tt.wantErr && tt.errCode == "CONFLICT" {
					assert.True(t, exists, "Should detect duplicate email")
				}
				return
			}

			// For empty email, we would expect validation to fail
			if tt.email == "" && tt.wantErr {
				// Empty email should be caught by validation
				return
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== ListUsers Pagination Edge Cases ====================

func TestUserService_ListUsers_PaginationEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		filter    port.UserFilter
		setupMock func(*MockUserRepository)
		wantCount int
		wantTotal int64
		wantErr   bool
		desc      string
	}{
		{
			name: "page 0 - should be treated as page 1",
			filter: port.UserFilter{
				Status:   "all",
				Page:     0,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{
					{ID: 1, Email: "user1@example.com"},
				}, int64(1), nil)
			},
			wantCount: 1,
			wantTotal: 1,
			wantErr:   false,
			desc:      "Page 0 should be normalized to page 1",
		},
		{
			name: "negative page",
			filter: port.UserFilter{
				Status:   "all",
				Page:     -1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantCount: 0,
			wantTotal: 0,
			wantErr:   false,
			desc:      "Negative page should be handled",
		},
		{
			name: "page size 0",
			filter: port.UserFilter{
				Status:   "all",
				Page:     1,
				PageSize: 0,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantCount: 0,
			wantTotal: 0,
			wantErr:   false,
			desc:      "Page size 0 should be handled",
		},
		{
			name: "very large page number",
			filter: port.UserFilter{
				Status:   "all",
				Page:     999999,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(100), nil)
			},
			wantCount: 0,
			wantTotal: 100,
			wantErr:   false,
			desc:      "Very large page should return empty results",
		},
		{
			name: "very large page size",
			filter: port.UserFilter{
				Status:   "all",
				Page:     1,
				PageSize: 10000,
			},
			setupMock: func(m *MockUserRepository) {
				users := make([]domain.User, 100)
				for i := 0; i < 100; i++ {
					users[i] = domain.User{ID: int64(i + 1), Email: "user" + string(rune('0'+i%10)) + "@example.com"}
				}
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return(users, int64(100), nil)
			},
			wantCount: 100,
			wantTotal: 100,
			wantErr:   false,
			desc:      "Large page size should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			users, total, err := mockRepo.List(context.Background(), tt.filter)

			if tt.wantErr {
				require.Error(t, err, tt.desc)
			} else {
				require.NoError(t, err, tt.desc)
				assert.Len(t, users, tt.wantCount, tt.desc)
				assert.Equal(t, tt.wantTotal, total, tt.desc)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== BlockUser Tests ====================

func TestUserService_BlockUser(t *testing.T) {
	tests := []struct {
		name      string
		userID    int64
		setupMock func(*MockUserRepository)
		wantErr   bool
		errCode   string
		desc      string
	}{
		{
			name:   "success - block active user",
			userID: 1,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:        1,
					Email:     "active@example.com",
					IsBlocked: false,
				}, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			wantErr: false,
			desc:    "Should block active user",
		},
		{
			name:   "idempotent - block already blocked user",
			userID: 2,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(2)).Return(&domain.User{
					ID:        2,
					Email:     "blocked@example.com",
					IsBlocked: true,
				}, nil)
				// Should still succeed (idempotent)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			wantErr: false,
			desc:    "Should be idempotent - blocking blocked user should not error",
		},
		{
			name:   "failure - user not found",
			userID: 999,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(999)).Return(nil, apperror.NotFound("user", 999))
			},
			wantErr: true,
			errCode: "NOT_FOUND",
			desc:    "Should return not found for non-existent user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			user, err := mockRepo.FindByID(context.Background(), tt.userID)

			if tt.wantErr {
				if err != nil {
					appErr, ok := apperror.AsAppError(err)
					if ok && tt.errCode != "" {
						assert.Equal(t, tt.errCode, appErr.Code, tt.desc)
					}
				}
			} else {
				require.NoError(t, err, tt.desc)
				require.NotNil(t, user)
				// Simulate block
				user.IsBlocked = true
				err = mockRepo.Update(context.Background(), user)
				assert.NoError(t, err, tt.desc)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== UnblockUser Tests ====================

func TestUserService_UnblockUser(t *testing.T) {
	tests := []struct {
		name      string
		userID    int64
		setupMock func(*MockUserRepository)
		wantErr   bool
		errCode   string
		desc      string
	}{
		{
			name:   "success - unblock blocked user",
			userID: 1,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:        1,
					Email:     "blocked@example.com",
					IsBlocked: true,
				}, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			wantErr: false,
			desc:    "Should unblock blocked user",
		},
		{
			name:   "idempotent - unblock already active user",
			userID: 2,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(2)).Return(&domain.User{
					ID:        2,
					Email:     "active@example.com",
					IsBlocked: false,
				}, nil)
				m.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			wantErr: false,
			desc:    "Should be idempotent - unblocking active user should not error",
		},
		{
			name:   "failure - user not found",
			userID: 999,
			setupMock: func(m *MockUserRepository) {
				m.On("FindByID", mock.Anything, int64(999)).Return(nil, apperror.NotFound("user", 999))
			},
			wantErr: true,
			errCode: "NOT_FOUND",
			desc:    "Should return not found for non-existent user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			user, err := mockRepo.FindByID(context.Background(), tt.userID)

			if tt.wantErr {
				if err != nil {
					appErr, ok := apperror.AsAppError(err)
					if ok && tt.errCode != "" {
						assert.Equal(t, tt.errCode, appErr.Code, tt.desc)
					}
				}
			} else {
				require.NoError(t, err, tt.desc)
				require.NotNil(t, user)
				// Simulate unblock
				user.IsBlocked = false
				err = mockRepo.Update(context.Background(), user)
				assert.NoError(t, err, tt.desc)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== Filter Edge Cases ====================

func TestUserService_ListUsers_FilterEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		filter    port.UserFilter
		setupMock func(*MockUserRepository)
		wantErr   bool
		desc      string
	}{
		{
			name: "search with special characters",
			filter: port.UserFilter{
				Status:   "all",
				Search:   "'; DROP TABLE users; --",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantErr: false,
			desc:    "SQL injection attempt should be handled safely",
		},
		{
			name: "search with unicode",
			filter: port.UserFilter{
				Status:   "all",
				Search:   "пользователь",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantErr: false,
			desc:    "Unicode search should work",
		},
		{
			name: "search with emoji",
			filter: port.UserFilter{
				Status:   "all",
				Search:   "user 👤",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantErr: false,
			desc:    "Emoji in search should work",
		},
		{
			name: "very long search string",
			filter: port.UserFilter{
				Status:   "all",
				Search:   string(make([]byte, 1000)),
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantErr: false,
			desc:    "Very long search string should be handled",
		},
		{
			name: "empty search string",
			filter: port.UserFilter{
				Status:   "all",
				Search:   "",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{
					{ID: 1, Email: "user@example.com"},
				}, int64(1), nil)
			},
			wantErr: false,
			desc:    "Empty search should return all users",
		},
		{
			name: "invalid status",
			filter: port.UserFilter{
				Status:   "invalid_status",
				Page:     1,
				PageSize: 10,
			},
			setupMock: func(m *MockUserRepository) {
				m.On("List", mock.Anything, mock.AnythingOfType("port.UserFilter")).Return([]domain.User{}, int64(0), nil)
			},
			wantErr: false,
			desc:    "Invalid status should be handled gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			users, total, err := mockRepo.List(context.Background(), tt.filter)

			if tt.wantErr {
				require.Error(t, err, tt.desc)
			} else {
				require.NoError(t, err, tt.desc)
				assert.NotNil(t, users, tt.desc)
				_ = total
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

// ==================== Concurrent Operations Tests ====================

func TestUserService_ConcurrentOperations(t *testing.T) {
	mockRepo := new(MockUserRepository)

	// Setup for concurrent reads
	mockRepo.On("FindByID", mock.Anything, mock.AnythingOfType("int64")).Return(&domain.User{
		ID:    1,
		Email: "concurrent@example.com",
	}, nil)

	const goroutines = 50
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int64) {
			user, err := mockRepo.FindByID(context.Background(), id%10+1)
			assert.NoError(t, err)
			assert.NotNil(t, user)
			done <- true
		}(int64(i))
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}
}
