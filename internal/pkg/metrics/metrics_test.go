package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// The counters are process-wide and survive repeated runs, so every assertion is a delta.

func TestRecordAuthAttempt(t *testing.T) {
	before := testutil.ToFloat64(AuthAttempts.WithLabelValues(ResultLocked))
	untouched := testutil.ToFloat64(AuthAttempts.WithLabelValues(ResultSuccess))

	RecordAuthAttempt(ResultLocked)

	assert.InDelta(t, before+1, testutil.ToFloat64(AuthAttempts.WithLabelValues(ResultLocked)), 0)
	assert.InDelta(t, untouched, testutil.ToFloat64(AuthAttempts.WithLabelValues(ResultSuccess)), 0, "other results are not touched")
}

func TestRecordAuthzDecision(t *testing.T) {
	allowed := testutil.ToFloat64(AuthzDecisions.WithLabelValues(ResultAllowed, "users", "read"))
	denied := testutil.ToFloat64(AuthzDecisions.WithLabelValues(ResultDenied, "users", "write"))

	RecordAuthzDecision(true, "users", "read")
	RecordAuthzDecision(false, "users", "write")
	RecordAuthzDecision(false, "users", "write")

	assert.InDelta(t, allowed+1, testutil.ToFloat64(AuthzDecisions.WithLabelValues(ResultAllowed, "users", "read")), 0)
	assert.InDelta(t, denied+2, testutil.ToFloat64(AuthzDecisions.WithLabelValues(ResultDenied, "users", "write")), 0)
}
