package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// run serves one GET /test request through h and returns the recorded response.
func run(t *testing.T, h gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.GET("/test", h)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody))
	return rec
}

// decode parses the envelope in rec.
func decode(t *testing.T, rec *httptest.ResponseRecorder) APIResponse {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), "body: %s", rec.Body.String())
	return resp
}

// assertErrorEnvelope checks the status and the error section of rec and returns the error body.
func assertErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, status int, code, message string) *ErrorBody {
	t.Helper()
	require.Equal(t, status, rec.Code, "body: %s", rec.Body.String())
	resp := decode(t, rec)
	assert.False(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Nil(t, resp.Meta)
	require.NotNil(t, resp.Error)
	assert.Equal(t, code, resp.Error.Code)
	assert.Equal(t, message, resp.Error.Message)
	return resp.Error
}

func TestSuccess(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) { Success(c, map[string]string{"message": "hello"}) })

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"success":true,"data":{"message":"hello"}}`, rec.Body.String())
}

func TestSuccessWithMeta(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) {
		SuccessWithMeta(c, []string{"item1", "item2"}, &Meta{Page: 1, PageSize: 10, Total: 100, TotalPages: 10})
	})

	assert.Equal(t, http.StatusOK, rec.Code)
	resp := decode(t, rec)
	assert.True(t, resp.Success)
	assert.Equal(t, []any{"item1", "item2"}, resp.Data)
	assert.Nil(t, resp.Error)
	assert.Equal(t, &Meta{Page: 1, PageSize: 10, Total: 100, TotalPages: 10}, resp.Meta)
}

func TestCreated(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) { Created(c, map[string]int{"id": 123}) })

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.JSONEq(t, `{"success":true,"data":{"id":123}}`, rec.Body.String())
}

func TestError(t *testing.T) {
	t.Parallel()

	t.Run("app error keeps its status, code and details", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) { Error(c, apperror.NotFound("user", 123)) })

		errBody := assertErrorEnvelope(t, rec, http.StatusNotFound, apperror.CodeNotFound, "user not found")
		assert.Equal(t, map[string]any{"resource": "user", "id": float64(123)}, errBody.Details)
	})

	t.Run("plain error becomes a generic 500", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) { Error(c, errors.New("something went wrong")) })

		assertErrorEnvelope(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "an unexpected error occurred")
		assert.NotContains(t, rec.Body.String(), "something went wrong")
	})

	t.Run("nil error becomes a generic 500", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) { Error(c, nil) })

		assertErrorEnvelope(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "an unexpected error occurred")
	})

	t.Run("wrapped cause is never sent", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) {
			Error(c, apperror.Internal("database failure", errors.New("dsn=postgres://user:secret@db")))
		})

		assertErrorEnvelope(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "database failure")
		assert.NotContains(t, rec.Body.String(), "secret")
	})

	t.Run("invalid status falls back to 500", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) { Error(c, &apperror.AppError{Code: "CUSTOM", Message: "no status"}) })

		assertErrorEnvelope(t, rec, http.StatusInternalServerError, "CUSTOM", "no status")
	})

	t.Run("wrapped app error is unwrapped", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) {
			Error(c, errors.Join(errors.New("context"), apperror.Forbidden("nope")))
		})

		assertErrorEnvelope(t, rec, http.StatusForbidden, apperror.CodeForbidden, "nope")
	})
}

func TestError_AttachesServerErrorsToTheContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		attached int
	}{
		{"client error is not attached", apperror.BadRequest("bad"), 0},
		{"server error is attached", apperror.Internal("broken", nil), 1},
		{"plain error is attached", errors.New("boom"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var attached int
			r := gin.New()
			r.GET("/test", func(c *gin.Context) {
				Error(c, tt.err)
				attached = len(c.Errors)
			})

			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody))

			assert.Equal(t, tt.attached, attached)
		})
	}
}

func TestErrorWithStatus(t *testing.T) {
	t.Parallel()

	t.Run("with details", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) {
			ErrorWithStatus(c, http.StatusTeapot, "CUSTOM_ERROR", "I'm a teapot", map[string]any{"hint": "try coffee"})
		})

		errBody := assertErrorEnvelope(t, rec, http.StatusTeapot, "CUSTOM_ERROR", "I'm a teapot")
		assert.Equal(t, map[string]any{"hint": "try coffee"}, errBody.Details)
	})

	t.Run("without details", func(t *testing.T) {
		t.Parallel()
		rec := run(t, func(c *gin.Context) {
			ErrorWithStatus(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body too large", nil)
		})

		assertErrorEnvelope(t, rec, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body too large")
		assert.JSONEq(t, `{"success":false,"error":{"code":"PAYLOAD_TOO_LARGE","message":"request body too large"}}`, rec.Body.String())
	})
}

func TestBadRequest(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) { BadRequest(c, "invalid input") })

	assertErrorEnvelope(t, rec, http.StatusBadRequest, apperror.CodeBadRequest, "invalid input")
}

func TestUnauthorized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		message     string
		wantMessage string
	}{
		{"with message", "invalid token", "invalid token"},
		{"empty message", "", "authentication required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := run(t, func(c *gin.Context) { Unauthorized(c, tt.message) })

			assertErrorEnvelope(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, tt.wantMessage)
		})
	}
}

func TestForbidden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		message     string
		wantMessage string
	}{
		{"with message", "insufficient permissions", "insufficient permissions"},
		{"empty message", "", "access denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := run(t, func(c *gin.Context) { Forbidden(c, tt.message) })

			assertErrorEnvelope(t, rec, http.StatusForbidden, apperror.CodeForbidden, tt.wantMessage)
		})
	}
}

func TestInternalError(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) { InternalError(c, "database connection failed") })

	assertErrorEnvelope(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "database connection failed")
}

func TestTooManyRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		retryAfter int
		wantHeader string
	}{
		{"positive retry after", 60, "60"},
		{"zero is raised to one second", 0, "1"},
		{"negative is raised to one second", -5, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := run(t, func(c *gin.Context) { TooManyRequests(c, "rate limit exceeded", tt.retryAfter) })

			errBody := assertErrorEnvelope(t, rec, http.StatusTooManyRequests, apperror.CodeTooManyRequests, "rate limit exceeded")
			assert.Equal(t, tt.wantHeader, rec.Header().Get("Retry-After"))
			assert.Equal(t, map[string]any{"retry_after_seconds": float64(max(1, tt.retryAfter))}, errBody.Details)
		})
	}
}

func TestValidationError(t *testing.T) {
	t.Parallel()
	rec := run(t, func(c *gin.Context) {
		ValidationError(c, "validation failed", map[string]any{"email": "invalid format", "password": "too short"})
	})

	errBody := assertErrorEnvelope(t, rec, http.StatusBadRequest, apperror.CodeValidation, "validation failed")
	assert.Equal(t, map[string]any{"email": "invalid format", "password": "too short"}, errBody.Details)
}

func TestNewMeta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		page           int
		pageSize       int
		total          int64
		wantTotalPages int
	}{
		{"exact division", 1, 10, 100, 10},
		{"with remainder", 1, 10, 95, 10},
		{"single page", 1, 10, 5, 1},
		{"empty", 1, 10, 0, 0},
		{"large total", 1, 25, 1000, 40},
		{"zero page size yields no pages", 1, 0, 50, 0},
		{"negative page size yields no pages", 1, -1, 50, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, &Meta{Page: tt.page, PageSize: tt.pageSize, Total: tt.total, TotalPages: tt.wantTotalPages}, NewMeta(tt.page, tt.pageSize, tt.total))
		})
	}
}
