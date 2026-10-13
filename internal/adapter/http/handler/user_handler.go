// Package handler provides HTTP request handlers for the IAM service.
package handler

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// UserHandler handles user-related HTTP requests.
//
// Provides CRUD endpoints for user management.
type UserHandler struct {
	userService port.UserService // User service
	logger      *logger.Logger   // Logger instance
}

// NewUserHandler creates a new UserHandler instance.
func NewUserHandler(userService port.UserService, log *logger.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      log.WithComponent("user_handler"),
	}
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID        int64  `json:"id"`                   // User ID
	Email     string `json:"email"`                // User email
	FullName  string `json:"full_name"`            // Full name
	IsBlocked bool   `json:"is_blocked"`           // Blocked status
	CreatedAt string `json:"created_at,omitempty"` // Creation timestamp
}

// ListUsersResponse represents the list users response.
type ListUsersResponse struct {
	Users []UserResponse `json:"users"` // Users list
}

// ListUsers handles GET /api/v1/users.
// @Summary List users
// @Description Get paginated list of users with optional filtering
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param status query string false "Filter by status: active, blocked, all" default(all)
// @Param search query string false "Search by email or name"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Items per page (max 100)" default(10)
// @Success 200 {object} response.APIResponse{data=ListUsersResponse,meta=response.Meta}
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Router /api/v1/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	// Parse query parameters
	status := c.DefaultQuery("status", "all")
	search := c.Query("search")

	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if err != nil {
		pageSize = 10
	}

	// Validate pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100 // Maximum page size
	}

	filter := port.UserFilter{
		Status:   status,
		Search:   search,
		Page:     page,
		PageSize: pageSize,
	}

	users, total, err := h.userService.ListUsers(c.Request.Context(), filter)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Transform to response format
	userResponses := make([]UserResponse, 0, len(users))
	for _, u := range users {
		userResponses = append(userResponses, UserResponse{
			ID:        u.ID,
			Email:     u.Email,
			FullName:  u.FullName,
			IsBlocked: u.IsBlocked,
			CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	response.SuccessWithMeta(c, ListUsersResponse{Users: userResponses}, response.NewMeta(page, pageSize, total))
}

// CreateUserRequest represents the create user request body.
type CreateUserRequest struct {
	Email        string `json:"email" binding:"required,email"`                            // User email
	Password     string `json:"password" binding:"required,min=8"`                         // Password (min 8 chars)
	FullName     string `json:"full_name" binding:"required"`                              // Full name
	Role         string `json:"role" binding:"required,oneof=admin analyst viewer"`        // User role
	PasswordType string `json:"password_type" binding:"omitempty,oneof=permanent onetime"` // Password type
}

// CreateUserResponse represents the create user response.
type CreateUserResponse struct {
	ID        int64  `json:"id"`         // User ID
	Email     string `json:"email"`      // User email
	FullName  string `json:"full_name"`  // Full name
	CreatedAt string `json:"created_at"` // Creation timestamp
}

// CreateUser handles POST /api/v1/users.
// @Summary Create user
// @Description Create a new user with specified role
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateUserRequest true "User data"
// @Success 201 {object} response.APIResponse{data=CreateUserResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 409 {object} response.APIResponse
// @Router /api/v1/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req domain.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	// Get admin context
	adminID := c.GetInt64("user_id")
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	user, err := h.userService.CreateUser(c.Request.Context(), &req, adminID, ipAddress, userAgent)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Created(c, CreateUserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName,
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// GetUser handles GET /api/v1/users/:id.
// @Summary Get user
// @Description Get user details by ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} response.APIResponse{data=UserResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), id)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName,
		IsBlocked: user.IsBlocked,
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// BlockUser handles POST /api/v1/users/:id/block.
// @Summary Block user
// @Description Block a user account
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} response.APIResponse
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id}/block [post]
func (h *UserHandler) BlockUser(c *gin.Context) {
	targetID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	// Get admin context
	adminID := c.GetInt64("user_id")
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	if err := h.userService.BlockUser(c.Request.Context(), targetID, adminID, ipAddress, userAgent); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "user blocked successfully"})
}

// UnblockUser handles POST /api/v1/users/:id/unblock.
// @Summary Unblock user
// @Description Unblock a user account
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} response.APIResponse
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id}/unblock [post]
func (h *UserHandler) UnblockUser(c *gin.Context) {
	targetID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	// Get admin context
	adminID := c.GetInt64("user_id")
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	if err := h.userService.UnblockUser(c.Request.Context(), targetID, adminID, ipAddress, userAgent); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "user unblocked successfully"})
}
