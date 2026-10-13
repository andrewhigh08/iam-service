package handler

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	defaultPageSize = 10
	maxPageSize     = 100
)

// UserHandler serves the user administration endpoints.
type UserHandler struct {
	users port.UserService
	log   *logger.Logger
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(users port.UserService, log *logger.Logger) *UserHandler {
	return &UserHandler{users: users, log: log.WithComponent("user_handler")}
}

// UserResponse describes a user.
type UserResponse struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	IsBlocked bool      `json:"is_blocked"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUsersResponse is the body of GET /api/v1/users.
type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
}

// CreateUserRequest is the body of POST /api/v1/users. PasswordTemporary forces a password
// change at the first login.
type CreateUserRequest struct {
	Email             string `json:"email" binding:"required,max=254,email"`
	Password          string `json:"password" binding:"required"`
	FullName          string `json:"full_name" binding:"required"`
	Role              string `json:"role" binding:"required,oneof=admin analyst viewer"`
	PasswordTemporary bool   `json:"password_temporary"`
}

// CreateUserResponse is the body of a successful POST /api/v1/users.
type CreateUserResponse struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUsers handles GET /api/v1/users.
// @Summary List users
// @Description Lists users page by page, optionally filtered by status and a search over email and name.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param status query string false "all, active or blocked" default(all)
// @Param search query string false "Substring of the email or full name"
// @Param page query int false "Page number, from 1" default(1)
// @Param page_size query int false "Users per page, 1 to 100" default(10)
// @Success 200 {object} response.APIResponse{data=ListUsersResponse,meta=response.Meta}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Router /api/v1/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	status := c.Query("status")
	switch status {
	case "", "all", "active", "blocked":
	default:
		response.BadRequest(c, "status must be one of: all, active, blocked")
		return
	}
	filter := port.UserFilter{
		Status:   status,
		Search:   strings.TrimSpace(c.Query("search")),
		Page:     max(1, queryInt(c, "page", 1)),
		PageSize: min(max(1, queryInt(c, "page_size", defaultPageSize)), maxPageSize),
	}

	users, total, err := h.users.List(c.Request.Context(), filter)
	if err != nil {
		response.Error(c, err)
		return
	}

	items := make([]UserResponse, len(users))
	for i := range users {
		items[i] = newUserResponse(&users[i])
	}
	response.SuccessWithMeta(c, ListUsersResponse{Users: items}, response.NewMeta(filter.Page, filter.PageSize, total))
}

// GetUser handles GET /api/v1/users/:id.
// @Summary Get a user
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path int true "User id"
// @Success 200 {object} response.APIResponse{data=UserResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, newUserResponse(user))
}

// CreateUser handles POST /api/v1/users.
// @Summary Create a user
// @Description Creates a user with the given role. The password must satisfy the password policy.
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body CreateUserRequest true "New user"
// @Success 201 {object} response.APIResponse{data=CreateUserResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 409 {object} response.APIResponse
// @Router /api/v1/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if !bindJSON(c, &req) {
		return
	}

	in := port.CreateUserInput{
		Email:     req.Email,
		Password:  req.Password,
		FullName:  req.FullName,
		Role:      req.Role,
		Temporary: req.PasswordTemporary,
	}
	user, err := h.users.Create(c.Request.Context(), in, actorFrom(c))
	if err != nil {
		response.Error(c, err)
		return
	}
	response.Created(c, CreateUserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName,
		CreatedAt: user.CreatedAt.UTC(),
	})
}

// BlockUser handles POST /api/v1/users/:id/block.
// @Summary Block a user
// @Description Blocks the account and ends all of its sessions and tokens.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path int true "User id"
// @Success 200 {object} response.APIResponse{data=MessageResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id}/block [post]
func (h *UserHandler) BlockUser(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}
	if err := h.users.Block(c.Request.Context(), id, actorFrom(c)); err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, MessageResponse{Message: "user blocked"})
}

// UnblockUser handles POST /api/v1/users/:id/unblock.
// @Summary Unblock a user
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path int true "User id"
// @Success 200 {object} response.APIResponse{data=MessageResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/users/{id}/unblock [post]
func (h *UserHandler) UnblockUser(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}
	if err := h.users.Unblock(c.Request.Context(), id, actorFrom(c)); err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, MessageResponse{Message: "user unblocked"})
}

// userIDParam parses the :id path parameter, answering 400 when it is not a positive integer.
func userIDParam(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id < 1 {
		response.BadRequest(c, "invalid user id")
		return 0, false
	}
	return id, true
}

func queryInt(c *gin.Context, name string, def int) int {
	raw := c.Query(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func newUserResponse(u *domain.User) UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		FullName:  u.FullName,
		IsBlocked: u.IsBlocked,
		CreatedAt: u.CreatedAt.UTC(),
	}
}
