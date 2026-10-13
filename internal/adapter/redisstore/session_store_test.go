package redisstore

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

func TestSessionFields_RoundTrip(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", 32)
	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	sess := domain.Session{
		ID:              "ababababababab00",
		TokenHash:       hash,
		UserID:          42,
		CreatedAt:       now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
		IP:              "203.0.113.7",
		UserAgent:       "test-agent/1.0",
		AccessJTI:       "jti-1",
		AccessExpiresAt: now.Add(15 * time.Minute),
	}

	stored := make(map[string]string, 8)
	for k, v := range sessionFields(sess) {
		stored[k] = toString(t, v)
	}
	parsed, err := parseSession(hash, stored)

	require.NoError(t, err)
	assert.Equal(t, sess, *parsed)
}

func TestSessionFields_OmitsAccessTokenWhenNoneIsRecorded(t *testing.T) {
	t.Parallel()
	fields := sessionFields(domain.Session{UserID: 1})

	assert.NotContains(t, fields, fieldAccessJTI)
	assert.NotContains(t, fields, fieldAccessExpiresAt)
}

func TestParseSession(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("cd", 32)
	tests := []struct {
		name    string
		fields  map[string]string
		want    *domain.Session
		wantErr string
	}{
		{
			name:   "sid is derived when the field is missing",
			fields: map[string]string{fieldUID: "7", fieldCreatedAt: "100", fieldExpiresAt: "200"},
			want: &domain.Session{
				ID: hash[:domain.SessionIDLength], TokenHash: hash, UserID: 7,
				CreatedAt: time.Unix(100, 0).UTC(), ExpiresAt: time.Unix(200, 0).UTC(),
			},
		},
		{
			name:   "zero access expiry means no access token",
			fields: map[string]string{fieldUID: "7", fieldCreatedAt: "100", fieldExpiresAt: "200", fieldAccessJTI: "j", fieldAccessExpiresAt: "0"},
			want: &domain.Session{
				ID: hash[:domain.SessionIDLength], TokenHash: hash, UserID: 7, AccessJTI: "j",
				CreatedAt: time.Unix(100, 0).UTC(), ExpiresAt: time.Unix(200, 0).UTC(),
			},
		},
		{name: "missing user id", fields: map[string]string{fieldCreatedAt: "100", fieldExpiresAt: "200"}, wantErr: "field uid"},
		{name: "malformed created_at", fields: map[string]string{fieldUID: "7", fieldCreatedAt: "soon", fieldExpiresAt: "200"}, wantErr: "field created_at"},
		{name: "malformed expires_at", fields: map[string]string{fieldUID: "7", fieldCreatedAt: "100", fieldExpiresAt: ""}, wantErr: "field expires_at"},
		{name: "malformed access expiry", fields: map[string]string{fieldUID: "7", fieldCreatedAt: "100", fieldExpiresAt: "200", fieldAccessExpiresAt: "x"}, wantErr: "field access_exp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSession(hash, tt.fields)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSidOf(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("f", 64)

	assert.Equal(t, long[:domain.SessionIDLength], sidOf(long))
	assert.Equal(t, "short", sidOf("short"))
	assert.Empty(t, sidOf(""))
}

func TestKeys(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "iam:session:abc", sessionKey("abc"))
	assert.Equal(t, "iam:session:rotated:abc", rotatedSessionKey("abc"))
	assert.Equal(t, "iam:user:42:sessions", userSessionsKey(42))
	assert.Equal(t, "iam:revoked:jti:j1", revokedJTIKey("j1"))
	assert.Equal(t, "iam:user:42:revoked_before", userRevokedBeforeKey(42))
	assert.Equal(t, "iam:login:fail:a@b", loginFailKey("a@b"))
	assert.Equal(t, "iam:login:lock:a@b", loginLockKey("a@b"))
}

// toString renders a hash field value the way Redis hands it back.
func toString(t *testing.T, v any) string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		t.Fatalf("unexpected field type %T", v)
		return ""
	}
}
