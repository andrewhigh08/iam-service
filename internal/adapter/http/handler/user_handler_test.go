package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// usersRouter mounts the user administration endpoints of f behind the test authentication.
func usersRouter(f *userFixture) *gin.Engine {
	r := gin.New()
	users := r.Group("/api/v1/users", authenticated)
	users.GET("", f.h.ListUsers)
	users.GET("/:id", f.h.GetUser)
	users.POST("", f.h.CreateUser)
	users.POST("/:id/block", f.h.BlockUser)
	users.POST("/:id/unblock", f.h.UnblockUser)
	return r
}

// sampleUser returns a stored user created at 03:04:05 UTC on 2024-01-02, expressed in UTC+3.
func sampleUser(id int64, email string, blocked bool) *domain.User {
	zone := time.FixedZone("UTC+3", 3*60*60)
	return &domain.User{
		ID:                id,
		Email:             email,
		PasswordHash:      "$2a$10$secret-hash",
		PasswordChangedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		FullName:          "Sample User",
		IsBlocked:         blocked,
		CreatedAt:         time.Date(2024, 1, 2, 6, 4, 5, 0, zone),
		UpdatedAt:         time.Date(2024, 1, 2, 6, 4, 5, 0, zone),
	}
}

// listUsers sends GET /api/v1/users with the given raw query string.
func listUsers(t *testing.T, f *userFixture, query string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/users"
	if query != "" {
		target += "?" + query
	}
	return serve(usersRouter(f), newRequest(t, http.MethodGet, target, nil))
}

func TestListUsers_BuildsTheFilterFromTheQuery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  port.UserFilter
	}{
		{"defaults", "", port.UserFilter{Page: 1, PageSize: 10}},
		{"explicit values", "status=active&search=%20bob%20&page=2&page_size=20", port.UserFilter{Status: "active", Search: "bob", Page: 2, PageSize: 20}},
		{"status all", "status=all", port.UserFilter{Status: "all", Page: 1, PageSize: 10}},
		{"status blocked", "status=blocked", port.UserFilter{Status: "blocked", Page: 1, PageSize: 10}},
		{"page below one is clamped", "page=0", port.UserFilter{Page: 1, PageSize: 10}},
		{"negative page is clamped", "page=-3", port.UserFilter{Page: 1, PageSize: 10}},
		{"page size above the maximum is clamped", "page_size=500", port.UserFilter{Page: 1, PageSize: 100}},
		{"page size at the maximum is kept", "page_size=100", port.UserFilter{Page: 1, PageSize: 100}},
		{"page size below one is clamped", "page_size=0", port.UserFilter{Page: 1, PageSize: 1}},
		{"non-numeric values fall back to the defaults", "page=abc&page_size=xyz", port.UserFilter{Page: 1, PageSize: 10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newUserFixture(t)
			f.users.EXPECT().List(gomock.Any(), tt.want).Return(nil, int64(0), nil)

			rec := listUsers(t, f, tt.query)

			require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
			env := decode[ListUsersResponse](t, rec)
			require.NotNil(t, env.Meta)
			assert.Equal(t, tt.want.Page, env.Meta.Page)
			assert.Equal(t, tt.want.PageSize, env.Meta.PageSize)
		})
	}
}

func TestListUsers_RejectsAnUnknownStatus(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)

	rec := listUsers(t, f, "status=deleted")

	assertError(t, rec, http.StatusBadRequest, apperror.CodeBadRequest, "status must be one of: all, active, blocked")
}

func TestListUsers_ReturnsUsersWithPaginationMeta(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	stored := []domain.User{*sampleUser(11, "a@example.com", false), *sampleUser(12, "b@example.com", true)}
	f.users.EXPECT().List(gomock.Any(), port.UserFilter{Page: 2, PageSize: 10}).Return(stored, int64(25), nil)

	rec := listUsers(t, f, "page=2&page_size=10")

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	env := decode[ListUsersResponse](t, rec)
	assert.True(t, env.Success)
	require.NotNil(t, env.Meta)
	assert.Equal(t, 2, env.Meta.Page)
	assert.Equal(t, 10, env.Meta.PageSize)
	assert.Equal(t, int64(25), env.Meta.Total)
	assert.Equal(t, 3, env.Meta.TotalPages)
	require.Len(t, env.Data.Users, 2)
	assert.Equal(t, UserResponse{
		ID: 11, Email: "a@example.com", FullName: "Sample User", IsBlocked: false,
		CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}, env.Data.Users[0])
	assert.True(t, env.Data.Users[1].IsBlocked)
	assert.Contains(t, rec.Body.String(), `"created_at":"2024-01-02T03:04:05Z"`, "timestamps are rendered in UTC")
	assert.NotContains(t, rec.Body.String(), "secret-hash", "password hashes never leave the service")
}

func TestListUsers_EmptyListIsAnArray(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	f.users.EXPECT().List(gomock.Any(), port.UserFilter{Page: 1, PageSize: 10}).Return(nil, int64(0), nil)

	rec := listUsers(t, f, "")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"users":[]`)
	env := decode[ListUsersResponse](t, rec)
	require.NotNil(t, env.Meta)
	assert.Zero(t, env.Meta.TotalPages)
}

func TestListUsers_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	f.users.EXPECT().List(gomock.Any(), port.UserFilter{Page: 1, PageSize: 10}).
		Return(nil, int64(0), apperror.Internal("failed to list users", errors.New("pq: relation missing")))

	rec := listUsers(t, f, "")

	assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to list users")
	assert.NotContains(t, rec.Body.String(), "pq:")
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	t.Run("returns the user", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().GetByID(gomock.Any(), int64(42)).Return(sampleUser(42, "u@example.com", true), nil)

		rec := serve(usersRouter(f), newRequest(t, http.MethodGet, "/api/v1/users/42", nil))

		data := decodeSuccess[UserResponse](t, rec, http.StatusOK)
		assert.Equal(t, UserResponse{
			ID: 42, Email: "u@example.com", FullName: "Sample User", IsBlocked: true,
			CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		}, data)
	})

	t.Run("reports an unknown user", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().GetByID(gomock.Any(), int64(99)).Return(nil, apperror.NotFound("user", int64(99)))

		rec := serve(usersRouter(f), newRequest(t, http.MethodGet, "/api/v1/users/99", nil))

		errBody := assertError(t, rec, http.StatusNotFound, apperror.CodeNotFound, "user not found")
		assert.Equal(t, "user", errBody.Details["resource"])
	})

	t.Run("rejects an invalid id", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"abc", "0", "-1", "1.5", "9223372036854775808"} {
			t.Run(id, func(t *testing.T) {
				t.Parallel()
				f := newUserFixture(t)

				rec := serve(usersRouter(f), newRequest(t, http.MethodGet, "/api/v1/users/"+id, nil))

				assertError(t, rec, http.StatusBadRequest, apperror.CodeBadRequest, "invalid user id")
			})
		}
	})
}

func TestCreateUser_CreatesTheUser(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	in := port.CreateUserInput{Email: "new@example.com", Password: "Str0ng-Pass!", FullName: "New User", Role: domain.RoleViewer, Temporary: true}
	created := sampleUser(77, "new@example.com", false)
	created.FullName = "New User"
	f.users.EXPECT().Create(gomock.Any(), in, testActor).Return(created, nil)
	body := CreateUserRequest{Email: "new@example.com", Password: "Str0ng-Pass!", FullName: "New User", Role: domain.RoleViewer, PasswordTemporary: true}

	rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users", body))

	data := decodeSuccess[CreateUserResponse](t, rec, http.StatusCreated)
	assert.Equal(t, CreateUserResponse{
		ID: 77, Email: "new@example.com", FullName: "New User", CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}, data)
	assert.NotContains(t, rec.Body.String(), "secret-hash")
}

func TestCreateUser_RejectsInvalidBodies(t *testing.T) {
	t.Parallel()
	valid := CreateUserRequest{Email: "new@example.com", Password: "Str0ng-Pass!", FullName: "New User", Role: domain.RoleAnalyst}
	withoutEmail, withoutRole, badRole, badEmail := valid, valid, valid, valid
	withoutEmail.Email = ""
	withoutRole.Role = ""
	badRole.Role = "superuser"
	badEmail.Email = "not-an-email"

	tests := []struct {
		name       string
		body       any
		wantFields map[string]any
		wantReason string
	}{
		{name: "missing everything", body: map[string]any{}, wantFields: map[string]any{
			"email": "required", "password": "required", "full_name": "required", "role": "required",
		}},
		{name: "missing email", body: withoutEmail, wantFields: map[string]any{"email": "required"}},
		{name: "missing role", body: withoutRole, wantFields: map[string]any{"role": "required"}},
		{name: "unknown role", body: badRole, wantFields: map[string]any{"role": "oneof=admin analyst viewer"}},
		{name: "malformed email", body: badEmail, wantFields: map[string]any{"email": "email"}},
		{name: "wrong field type", body: `{"email":"new@example.com","password":"x","full_name":"n","role":"viewer","password_temporary":"yes"}`, wantFields: map[string]any{"password_temporary": "invalid type"}},
		{name: "not json", body: "<xml/>", wantReason: "body must be a JSON object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newUserFixture(t)

			rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users", tt.body))

			errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, errBody.Details["reason"])
				return
			}
			assert.Equal(t, tt.wantFields, validationFields(t, errBody))
		})
	}
}

func TestCreateUser_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	body := CreateUserRequest{Email: "dup@example.com", Password: "Str0ng-Pass!", FullName: "Dup", Role: domain.RoleViewer}
	in := port.CreateUserInput{Email: "dup@example.com", Password: "Str0ng-Pass!", FullName: "Dup", Role: domain.RoleViewer}

	t.Run("duplicate email", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().Create(gomock.Any(), in, testActor).Return(nil, apperror.Conflict("user", "email", "dup@example.com"))

		rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users", body))

		errBody := assertError(t, rec, http.StatusConflict, apperror.CodeConflict, "user with this email already exists")
		assert.Equal(t, "email", errBody.Details["field"])
	})

	t.Run("password policy violation", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().Create(gomock.Any(), in, testActor).
			Return(nil, apperror.ValidationError("password does not meet the policy", map[string]any{"violations": []string{"digit"}}))

		rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users", body))

		errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "password does not meet the policy")
		assert.Equal(t, []any{"digit"}, errBody.Details["violations"])
	})

	t.Run("internal failure", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().Create(gomock.Any(), in, testActor).Return(nil, apperror.Internal("failed to create user", errors.New("pq: boom")))

		rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users", body))

		assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to create user")
		assert.NotContains(t, rec.Body.String(), "pq:")
	})
}

func TestBlockAndUnblockUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		action      string
		wantMessage string
		expect      func(f *userFixture, id int64) *gomock.Call
	}{
		{
			name: "block", action: "block", wantMessage: "user blocked",
			expect: func(f *userFixture, id int64) *gomock.Call {
				return f.users.EXPECT().Block(gomock.Any(), id, testActor)
			},
		},
		{
			name: "unblock", action: "unblock", wantMessage: "user unblocked",
			expect: func(f *userFixture, id int64) *gomock.Call {
				return f.users.EXPECT().Unblock(gomock.Any(), id, testActor)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			t.Run("succeeds", func(t *testing.T) {
				t.Parallel()
				f := newUserFixture(t)
				tt.expect(f, 42).Return(nil)

				rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users/42/"+tt.action, nil))

				data := decodeSuccess[MessageResponse](t, rec, http.StatusOK)
				assert.Equal(t, tt.wantMessage, data.Message)
			})

			t.Run("reports an unknown user", func(t *testing.T) {
				t.Parallel()
				f := newUserFixture(t)
				tt.expect(f, 99).Return(apperror.NotFound("user", int64(99)))

				rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users/99/"+tt.action, nil))

				assertError(t, rec, http.StatusNotFound, apperror.CodeNotFound, "user not found")
			})

			t.Run("rejects an invalid id", func(t *testing.T) {
				t.Parallel()
				f := newUserFixture(t)

				rec := serve(usersRouter(f), newRequest(t, http.MethodPost, "/api/v1/users/abc/"+tt.action, nil))

				assertError(t, rec, http.StatusBadRequest, apperror.CodeBadRequest, "invalid user id")
			})
		})
	}
}

func TestQueryInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"absent", "", 5},
		{"integer", "page=3", 3},
		{"negative integer", "page=-2", -2},
		{"not a number", "page=three", 5},
		{"float", "page=1.5", 5},
		{"empty value", "page=", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = newRequest(t, http.MethodGet, "/?"+tt.query, nil)

			assert.Equal(t, tt.want, queryInt(c, "page", 5))
		})
	}
}
