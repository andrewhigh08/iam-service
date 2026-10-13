package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

// Identity of the client and caller behind every request built by newRequest.
const (
	testIP              = "203.0.113.5"
	testUserAgent       = "iam-test/1.0"
	testUserID    int64 = 7
	testSessionID       = "0123456789abcdef"
)

// testMeta is the client identity the handlers derive from a request built by newRequest.
var testMeta = domain.ClientMeta{IP: testIP, UserAgent: testUserAgent}

// overlongEmail is a well-formed address one character longer than the 254 the API accepts.
var overlongEmail = strings.Repeat("a", 255-len("@example.com")) + "@example.com"

// testActor is the actor the handlers derive from an authenticated request.
var testActor = domain.Actor{UserID: testUserID, ClientMeta: testMeta}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// authFixture bundles an AuthHandler with its mocked services and the log output it produced.
type authFixture struct {
	h     *AuthHandler
	auth  *mocks.MockAuthService
	authz *mocks.MockAuthorizationService
	logs  *bytes.Buffer
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	ctrl := gomock.NewController(t)
	f := &authFixture{
		auth:  mocks.NewMockAuthService(ctrl),
		authz: mocks.NewMockAuthorizationService(ctrl),
		logs:  &bytes.Buffer{},
	}
	f.h = NewAuthHandler(f.auth, f.authz, newTestLogger(f.logs))
	return f
}

// userFixture bundles a UserHandler with its mocked service and the log output it produced.
type userFixture struct {
	h     *UserHandler
	users *mocks.MockUserService
	logs  *bytes.Buffer
}

func newUserFixture(t *testing.T) *userFixture {
	t.Helper()
	f := &userFixture{users: mocks.NewMockUserService(gomock.NewController(t)), logs: &bytes.Buffer{}}
	f.h = NewUserHandler(f.users, newTestLogger(f.logs))
	return f
}

func newTestLogger(buf *bytes.Buffer) *logger.Logger {
	return logger.New(logger.Config{Level: "debug", Format: "json", Output: buf})
}

// authenticated stands in for AuthMiddleware by storing the test user's identity in the context.
func authenticated(c *gin.Context) {
	c.Set(ContextKeyUserID, testUserID)
	c.Set(ContextKeySessionID, testSessionID)
	c.Next()
}

// newRequest builds a request from testIP with the test user agent. A nil body sends no body,
// a string is sent verbatim and anything else is JSON-encoded.
func newRequest(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	var reader io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, target, reader)
	req.RemoteAddr = testIP + ":4321"
	req.Header.Set("User-Agent", testUserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type envelope[T any] struct {
	Success bool                `json:"success"`
	Data    T                   `json:"data"`
	Error   *response.ErrorBody `json:"error"`
	Meta    *response.Meta      `json:"meta"`
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) envelope[T] {
	t.Helper()
	var env envelope[T]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body: %s", rec.Body.String())
	return env
}

func decodeSuccess[T any](t *testing.T, rec *httptest.ResponseRecorder, status int) T {
	t.Helper()
	require.Equal(t, status, rec.Code, "body: %s", rec.Body.String())
	env := decode[T](t, rec)
	assert.True(t, env.Success)
	assert.Nil(t, env.Error)
	return env.Data
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code, message string) *response.ErrorBody {
	t.Helper()
	require.Equal(t, status, rec.Code, "body: %s", rec.Body.String())
	env := decode[any](t, rec)
	assert.False(t, env.Success)
	assert.Nil(t, env.Data)
	require.NotNil(t, env.Error)
	assert.Equal(t, code, env.Error.Code)
	assert.Equal(t, message, env.Error.Message)
	return env.Error
}

func validationFields(t *testing.T, errBody *response.ErrorBody) map[string]any {
	t.Helper()
	fields, ok := errBody.Details["fields"].(map[string]any)
	require.True(t, ok, "details.fields must be an object, got %v", errBody.Details)
	return fields
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal(line, &rec), "log line: %s", line)
		records = append(records, rec)
	}
	return records
}

func assertErrorLogged(t *testing.T, buf *bytes.Buffer, msg string) {
	t.Helper()
	for _, rec := range logRecords(t, buf) {
		if rec["level"] == "ERROR" && rec["msg"] == msg {
			return
		}
	}
	assert.Failf(t, "log record not found", "no ERROR record %q in:\n%s", msg, buf.String())
}
