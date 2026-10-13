package redisstore

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

func TestRevocationStore_Check(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	instant := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	recorded := strconv.FormatInt(instant.Unix(), 10)
	tests := []struct {
		name          string
		exists        func(t *testing.T) *redis.IntCmd
		get           func(t *testing.T) *redis.StringCmd
		wantRevoked   bool
		wantInstant   time.Time
		wantErr       bool
		wantErrSource error
	}{
		{
			name:   "nothing recorded",
			exists: func(t *testing.T) *redis.IntCmd { return intCmd(t, 0, nil) },
			get:    func(t *testing.T) *redis.StringCmd { return stringCmd(t, "", redis.Nil) },
		},
		{
			name:        "blacklisted jti",
			exists:      func(t *testing.T) *redis.IntCmd { return intCmd(t, 1, nil) },
			get:         func(t *testing.T) *redis.StringCmd { return stringCmd(t, "", redis.Nil) },
			wantRevoked: true,
		},
		{
			name:        "revocation instant recorded",
			exists:      func(t *testing.T) *redis.IntCmd { return intCmd(t, 0, nil) },
			get:         func(t *testing.T) *redis.StringCmd { return stringCmd(t, recorded, nil) },
			wantInstant: instant,
		},
		{
			name:        "both recorded",
			exists:      func(t *testing.T) *redis.IntCmd { return intCmd(t, 1, nil) },
			get:         func(t *testing.T) *redis.StringCmd { return stringCmd(t, recorded, nil) },
			wantRevoked: true,
			wantInstant: instant,
		},
		{
			name:          "transport failure marks every command",
			exists:        func(t *testing.T) *redis.IntCmd { return intCmd(t, 0, boom) },
			get:           func(t *testing.T) *redis.StringCmd { return stringCmd(t, "", boom) },
			wantErr:       true,
			wantErrSource: boom,
		},
		{
			name:          "instant lookup failure",
			exists:        func(t *testing.T) *redis.IntCmd { return intCmd(t, 0, nil) },
			get:           func(t *testing.T) *redis.StringCmd { return stringCmd(t, "", boom) },
			wantErr:       true,
			wantErrSource: boom,
		},
		{
			name:    "malformed instant",
			exists:  func(t *testing.T) *redis.IntCmd { return intCmd(t, 0, nil) },
			get:     func(t *testing.T) *redis.StringCmd { return stringCmd(t, "soon", nil) },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{pipeline: &fakePipeliner{exists: tt.exists(t), get: tt.get(t)}}

			revoked, revokedBefore, err := NewRevocationStore(client).Check(t.Context(), "j1", 42)

			assert.Equal(t, 1, client.pipelines, "both keys are read in one round trip")
			assert.Equal(t, []string{"iam:revoked:jti:j1", "iam:user:42:revoked_before"}, client.pipeline.keys)
			if tt.wantErr {
				var appErr *apperror.AppError
				require.ErrorAs(t, err, &appErr)
				assert.Equal(t, apperror.CodeInternal, appErr.Code)
				assert.Equal(t, msgCheckRevocationFailed, appErr.Message)
				if tt.wantErrSource != nil {
					require.ErrorIs(t, err, tt.wantErrSource)
				}
				assert.False(t, revoked)
				assert.True(t, revokedBefore.IsZero())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRevoked, revoked)
			assert.Equal(t, tt.wantInstant, revokedBefore)
		})
	}
}
