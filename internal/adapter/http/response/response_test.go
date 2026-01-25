package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestSuccess(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		Success(c, map[string]string{"message": "hello"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Data)
	assert.Nil(t, resp.Error)
	assert.Nil(t, resp.Meta)
}

func TestSuccessWithMeta(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		data := []string{"item1", "item2"}
		meta := &Meta{Page: 1, PageSize: 10, Total: 100, TotalPages: 10}
		SuccessWithMeta(c, data, meta)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Data)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Meta)
	assert.Equal(t, 1, resp.Meta.Page)
	assert.Equal(t, 10, resp.Meta.PageSize)
	assert.Equal(t, int64(100), resp.Meta.Total)
	assert.Equal(t, 10, resp.Meta.TotalPages)
}

func TestCreated(t *testing.T) {
	router := setupTestRouter()
	router.POST("/test", func(c *gin.Context) {
		Created(c, map[string]int{"id": 123})
	})

	req := httptest.NewRequest(http.MethodPost, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Data)
}

func TestNoContent(t *testing.T) {
	router := setupTestRouter()
	router.DELETE("/test", func(c *gin.Context) {
		NoContent(c)
	})

	req := httptest.NewRequest(http.MethodDelete, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func TestError_AppError(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		Error(c, apperror.NotFound("user", 123))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, apperror.CodeNotFound, resp.Error.Code)
	assert.Equal(t, "user not found", resp.Error.Message)
}

func TestError_RegularError(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		Error(c, errors.New("something went wrong"))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeInternal, resp.Error.Code)
}

func TestErrorWithStatus(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		ErrorWithStatus(c, http.StatusTeapot, "CUSTOM_ERROR", "I'm a teapot", map[string]interface{}{
			"hint": "try coffee",
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTeapot, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, "CUSTOM_ERROR", resp.Error.Code)
	assert.Equal(t, "I'm a teapot", resp.Error.Message)
	assert.Equal(t, "try coffee", resp.Error.Details["hint"])
}

func TestBadRequest(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		BadRequest(c, "invalid input")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeBadRequest, resp.Error.Code)
	assert.Equal(t, "invalid input", resp.Error.Message)
}

func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{"with message", "invalid token", "invalid token"},
		{"empty message", "", "authentication required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := setupTestRouter()
			router.GET("/test", func(c *gin.Context) {
				Unauthorized(c, tt.message)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)

			var resp APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)

			assert.False(t, resp.Success)
			assert.Equal(t, apperror.CodeUnauthorized, resp.Error.Code)
			assert.Equal(t, tt.expectedMessage, resp.Error.Message)
		})
	}
}

func TestForbidden(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{"with message", "insufficient permissions", "insufficient permissions"},
		{"empty message", "", "access denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := setupTestRouter()
			router.GET("/test", func(c *gin.Context) {
				Forbidden(c, tt.message)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)

			var resp APIResponse
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)

			assert.False(t, resp.Success)
			assert.Equal(t, apperror.CodeForbidden, resp.Error.Code)
			assert.Equal(t, tt.expectedMessage, resp.Error.Message)
		})
	}
}

func TestNotFound(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		NotFound(c, "user", 123)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeNotFound, resp.Error.Code)
	assert.Equal(t, "user not found", resp.Error.Message)
}

func TestConflict(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		Conflict(c, "user", "email", "test@example.com")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeConflict, resp.Error.Code)
}

func TestInternalError(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		InternalError(c, "database connection failed")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeInternal, resp.Error.Code)
	assert.Equal(t, "database connection failed", resp.Error.Message)
}

func TestTooManyRequests(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		TooManyRequests(c, "rate limit exceeded", 60)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeTooManyRequests, resp.Error.Code)
	assert.Equal(t, "rate limit exceeded", resp.Error.Message)
}

func TestValidationError(t *testing.T) {
	router := setupTestRouter()
	router.GET("/test", func(c *gin.Context) {
		ValidationError(c, "validation failed", map[string]interface{}{
			"email":    "invalid format",
			"password": "too short",
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Success)
	assert.Equal(t, apperror.CodeValidation, resp.Error.Code)
	assert.Equal(t, "validation failed", resp.Error.Message)
	assert.Equal(t, "invalid format", resp.Error.Details["email"])
	assert.Equal(t, "too short", resp.Error.Details["password"])
}

func TestNewMeta(t *testing.T) {
	tests := []struct {
		name               string
		page               int
		pageSize           int
		total              int64
		expectedTotalPages int
	}{
		{"exact division", 1, 10, 100, 10},
		{"with remainder", 1, 10, 95, 10},
		{"single page", 1, 10, 5, 1},
		{"empty", 1, 10, 0, 0},
		{"large total", 1, 25, 1000, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := NewMeta(tt.page, tt.pageSize, tt.total)

			assert.Equal(t, tt.page, meta.Page)
			assert.Equal(t, tt.pageSize, meta.PageSize)
			assert.Equal(t, tt.total, meta.Total)
			assert.Equal(t, tt.expectedTotalPages, meta.TotalPages)
		})
	}
}
