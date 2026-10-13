package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The metrics tests share the process-wide in-flight gauge, so they do not run in parallel.

func TestMetrics_CountsRequestsByRouteTemplateAndStatus(t *testing.T) {
	// The route is unique per run so that the metrics, which are process-wide, start from a clean series.
	prefix := "/metrics-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	var inFlightDuringRequest float64
	r := gin.New()
	r.Use(Metrics())
	r.GET(prefix+"/:id", func(c *gin.Context) {
		inFlightDuringRequest = testutil.ToFloat64(httpRequestsInFlight)
		c.Status(http.StatusNoContent)
	})
	status := strconv.Itoa(http.StatusNoContent)
	byRoute := httpRequestsTotal.WithLabelValues(http.MethodGet, prefix+"/:id", status)
	byRawPath := httpRequestsTotal.WithLabelValues(http.MethodGet, prefix+"/42", status)
	countBefore := testutil.ToFloat64(byRoute)
	seriesBefore := testutil.CollectAndCount(httpRequestDuration)
	inFlightBefore := testutil.ToFloat64(httpRequestsInFlight)

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, prefix+"/42", http.NoBody))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.InDelta(t, countBefore+1, testutil.ToFloat64(byRoute), 0)
	assert.InDelta(t, 0, testutil.ToFloat64(byRawPath), 0, "the raw path is never used as a label")
	assert.InDelta(t, inFlightBefore+1, inFlightDuringRequest, 0)
	assert.InDelta(t, inFlightBefore, testutil.ToFloat64(httpRequestsInFlight), 0)
	assert.Equal(t, seriesBefore+1, testutil.CollectAndCount(httpRequestDuration), "the duration is observed for the route")
}

func TestMetrics_UnmatchedRouteIsLabelledUnknown(t *testing.T) {
	r := gin.New()
	r.Use(Metrics())
	unknown := httpRequestsTotal.WithLabelValues(http.MethodGet, "unknown", strconv.Itoa(http.StatusNotFound))
	before := testutil.ToFloat64(unknown)

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/no-such-route", http.NoBody))

	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.InDelta(t, before+1, testutil.ToFloat64(unknown), 0)
}
