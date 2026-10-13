// Package metrics exposes the Prometheus counters recorded by the service layer.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Values of the result label of AuthAttempts.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultLocked  = "locked"
)

// Values of the result label of AuthzDecisions.
const (
	ResultAllowed = "allowed"
	ResultDenied  = "denied"
)

var (
	// AuthAttempts counts login attempts by result: success, failure or locked.
	AuthAttempts = newAuthAttempts()

	// AuthzDecisions counts authorization decisions by result, resource and action.
	AuthzDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_authz_decisions_total",
		Help: "Number of authorization decisions by result, resource and action.",
	}, []string{"result", "resource", "action"})
)

// newAuthAttempts registers the counter and pre-creates every known result so each series
// is exported from the start.
func newAuthAttempts() *prometheus.CounterVec {
	vec := promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_auth_attempts_total",
		Help: "Number of login attempts by result.",
	}, []string{"result"})
	for _, result := range []string{ResultSuccess, ResultFailure, ResultLocked} {
		vec.WithLabelValues(result)
	}
	return vec
}

// RecordAuthAttempt increments AuthAttempts for result.
func RecordAuthAttempt(result string) {
	AuthAttempts.WithLabelValues(result).Inc()
}

// RecordAuthzDecision increments AuthzDecisions for an allowed or denied check of action on resource.
func RecordAuthzDecision(allowed bool, resource, action string) {
	result := ResultDenied
	if allowed {
		result = ResultAllowed
	}
	AuthzDecisions.WithLabelValues(result, resource, action).Inc()
}
