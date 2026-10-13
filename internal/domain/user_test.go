package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUser_PasswordExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	const maxAge = 90 * 24 * time.Hour
	tests := []struct {
		name      string
		changedAt time.Time
		maxAge    time.Duration
		want      bool
	}{
		{name: "zero max age disables expiry", changedAt: now.Add(-10 * maxAge), maxAge: 0},
		{name: "negative max age disables expiry", changedAt: now.Add(-10 * maxAge), maxAge: -time.Hour},
		{name: "fresh password", changedAt: now.Add(-time.Hour), maxAge: maxAge},
		{name: "exactly at max age is still valid", changedAt: now.Add(-maxAge), maxAge: maxAge},
		{name: "one nanosecond past max age", changedAt: now.Add(-maxAge - time.Nanosecond), maxAge: maxAge, want: true},
		{name: "long past max age", changedAt: now.Add(-10 * maxAge), maxAge: maxAge, want: true},
		{name: "changed in the future", changedAt: now.Add(time.Hour), maxAge: time.Minute},
		{name: "never changed", changedAt: time.Time{}, maxAge: maxAge, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u := &User{PasswordChangedAt: tt.changedAt}

			assert.Equal(t, tt.want, u.PasswordExpired(now, tt.maxAge))
		})
	}
}

func TestUser_TableName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "users", User{}.TableName())
}
