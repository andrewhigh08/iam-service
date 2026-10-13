package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// newLogger returns a debug-level JSON logger writing into buf.
func newLogger(buf *bytes.Buffer) *logger.Logger {
	return logger.New(logger.Config{Level: "debug", Format: "json", Output: buf})
}

// logRecords parses every JSON line written to buf, in order.
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

// serve runs req through h and returns the recorded response.
func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeEnvelope parses the JSON response envelope from rec.
func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) response.APIResponse {
	t.Helper()
	var env response.APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body: %s", rec.Body.String())
	return env
}

// okHandler answers 200 with a plain "ok" body.
func okHandler(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}
