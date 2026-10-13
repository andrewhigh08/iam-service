package redis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// Fields of the session hash.
const (
	fieldUID             = "uid"
	fieldSID             = "sid"
	fieldCreatedAt       = "created_at"
	fieldExpiresAt       = "expires_at"
	fieldIP              = "ip"
	fieldUserAgent       = "ua"
	fieldAccessJTI       = "jti"
	fieldAccessExpiresAt = "access_exp"
)

const resourceSession = "session"

// takeSessionScript reads and deletes a session hash, drops it from the user's index and
// records the hash as consumed, all in one step. It returns the hash fields as a flat list,
// which is empty when there was no session.
var takeSessionScript = redis.NewScript(`
local fields = redis.call('HGETALL', KEYS[1])
if #fields == 0 then
	return fields
end
local uid = redis.call('HGET', KEYS[1], 'uid')
redis.call('DEL', KEYS[1])
if uid then
	redis.call('SREM', 'iam:user:' .. uid .. ':sessions', ARGV[1])
	redis.call('SET', KEYS[2], uid, 'PX', ARGV[2])
end
return fields
`)

// SessionStore implements port.SessionStore on Redis hashes indexed by a per-user set.
type SessionStore struct {
	client redis.Cmdable
}

// NewSessionStore returns a SessionStore using client.
func NewSessionStore(client redis.Cmdable) *SessionStore {
	return &SessionStore{client: client}
}

// Create stores sess under its token hash for ttl and adds it to the user's session index,
// whose TTL is extended to at least ttl.
func (s *SessionStore) Create(ctx context.Context, sess domain.Session, ttl time.Duration) error {
	if sess.TokenHash == "" {
		return apperror.Internal("failed to create session", errEmptyTokenHash)
	}
	if ttl <= 0 {
		return apperror.Internal("failed to create session", errNonPositiveTTL)
	}

	key := sessionKey(sess.TokenHash)
	setKey := userSessionsKey(sess.UserID)
	_, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, key, sessionFields(sess))
		p.Expire(ctx, key, ttl)
		p.SAdd(ctx, setKey, sess.TokenHash)
		// GT extends an index that already has a shorter TTL; NX covers one just created by SADD.
		p.ExpireGT(ctx, setKey, ttl)
		p.ExpireNX(ctx, setKey, ttl)
		return nil
	})
	if err != nil {
		return apperror.Internal("failed to create session", err)
	}
	return nil
}

// Get returns the session stored under tokenHash or apperror.NotFound.
func (s *SessionStore) Get(ctx context.Context, tokenHash string) (*domain.Session, error) {
	fields, err := s.client.HGetAll(ctx, sessionKey(tokenHash)).Result()
	if err != nil {
		return nil, apperror.Internal("failed to load session", err)
	}
	if len(fields) == 0 {
		return nil, apperror.NotFound(resourceSession, sidOf(tokenHash))
	}
	sess, err := parseSession(tokenHash, fields)
	if err != nil {
		return nil, apperror.Internal("failed to decode session", err)
	}
	return sess, nil
}

// Take removes the session stored under tokenHash and returns it, remembering the hash as
// consumed for keep. The read, the deletion and the record are one atomic script, so only one
// of several concurrent callers obtains the session; the others get apperror.NotFound.
func (s *SessionStore) Take(ctx context.Context, tokenHash string, keep time.Duration) (*domain.Session, error) {
	if keep <= 0 {
		return nil, apperror.Internal("failed to take session", errNonPositiveTTL)
	}
	keys := []string{sessionKey(tokenHash), rotatedSessionKey(tokenHash)}
	raw, err := takeSessionScript.Run(ctx, s.client, keys, tokenHash, max(keep.Milliseconds(), 1)).StringSlice()
	if err != nil {
		return nil, apperror.Internal("failed to take session", err)
	}
	if len(raw) == 0 {
		return nil, apperror.NotFound(resourceSession, sidOf(tokenHash))
	}
	fields := make(map[string]string, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		fields[raw[i]] = raw[i+1]
	}
	sess, err := parseSession(tokenHash, fields)
	if err != nil {
		return nil, apperror.Internal("failed to decode session", err)
	}
	return sess, nil
}

// ConsumedBy returns the user id recorded when Take consumed the session under tokenHash, or
// 0 when the hash is unknown or the record has expired.
func (s *SessionStore) ConsumedBy(ctx context.Context, tokenHash string) (int64, error) {
	userID, err := s.client.Get(ctx, rotatedSessionKey(tokenHash)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, apperror.Internal("failed to check consumed session", err)
	}
	return userID, nil
}

// Delete removes the session stored under tokenHash and drops it from the user's index.
// A missing session is not an error.
func (s *SessionStore) Delete(ctx context.Context, tokenHash string) error {
	key := sessionKey(tokenHash)
	userID, err := s.client.HGet(ctx, key, fieldUID).Int64()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return apperror.Internal("failed to load session", err)
	}

	_, err = s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Del(ctx, key)
		p.SRem(ctx, userSessionsKey(userID), tokenHash)
		return nil
	})
	if err != nil {
		return apperror.Internal("failed to delete session", err)
	}
	return nil
}

// DeleteAllForUser removes every session of the user and returns how many were still live.
func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID int64) (int, error) {
	setKey := userSessionsKey(userID)
	hashes, err := s.client.SMembers(ctx, setKey).Result()
	if err != nil {
		return 0, apperror.Internal("failed to list user sessions", err)
	}
	if len(hashes) == 0 {
		return 0, nil
	}

	keys := make([]string, len(hashes))
	members := make([]any, len(hashes))
	for i, h := range hashes {
		keys[i] = sessionKey(h)
		members[i] = h
	}
	var removed *redis.IntCmd
	_, err = s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		removed = p.Del(ctx, keys...)
		// Removing only the members seen keeps a session added concurrently in the index.
		p.SRem(ctx, setKey, members...)
		return nil
	})
	if err != nil {
		return 0, apperror.Internal("failed to delete user sessions", err)
	}
	return int(removed.Val()), nil
}

// ListForUser returns the live sessions of the user, newest first. Index entries whose session
// has expired are pruned on a best-effort basis.
func (s *SessionStore) ListForUser(ctx context.Context, userID int64) ([]domain.Session, error) {
	setKey := userSessionsKey(userID)
	hashes, err := s.client.SMembers(ctx, setKey).Result()
	if err != nil {
		return nil, apperror.Internal("failed to list user sessions", err)
	}
	if len(hashes) == 0 {
		return []domain.Session{}, nil
	}

	sessions, dead, err := s.loadSessions(ctx, hashes)
	if err != nil {
		return nil, err
	}
	if len(dead) > 0 {
		// Pruning is housekeeping; a failure must not hide the sessions already read.
		_ = s.client.SRem(ctx, setKey, dead...).Err()
	}
	slices.SortFunc(sessions, func(a, b domain.Session) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return sessions, nil
}

// loadSessions fetches the hashes of the given token hashes in one round trip and returns the
// decoded live sessions together with the token hashes whose session no longer exists.
func (s *SessionStore) loadSessions(ctx context.Context, hashes []string) ([]domain.Session, []any, error) {
	cmds := make([]*redis.MapStringStringCmd, len(hashes))
	_, err := s.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		for i, h := range hashes {
			cmds[i] = p.HGetAll(ctx, sessionKey(h))
		}
		return nil
	})
	if err != nil {
		return nil, nil, apperror.Internal("failed to load user sessions", err)
	}

	sessions := make([]domain.Session, 0, len(hashes))
	var dead []any
	for i, cmd := range cmds {
		fields := cmd.Val()
		if len(fields) == 0 {
			dead = append(dead, hashes[i])
			continue
		}
		sess, perr := parseSession(hashes[i], fields)
		if perr != nil {
			return nil, nil, apperror.Internal("failed to decode session", perr)
		}
		sessions = append(sessions, *sess)
	}
	return sessions, dead, nil
}

// sessionFields encodes sess as the hash stored in Redis. The access-token fields are stored
// only when the session carries them, and a zero AccessExpiresAt is stored as 0.
func sessionFields(sess domain.Session) map[string]any {
	fields := map[string]any{
		fieldUID:       sess.UserID,
		fieldSID:       sess.ID,
		fieldCreatedAt: sess.CreatedAt.Unix(),
		fieldExpiresAt: sess.ExpiresAt.Unix(),
		fieldIP:        sess.IP,
		fieldUserAgent: sess.UserAgent,
	}
	if sess.AccessJTI != "" {
		fields[fieldAccessJTI] = sess.AccessJTI
		fields[fieldAccessExpiresAt] = unixOrZero(sess.AccessExpiresAt)
	}
	return fields
}

// unixOrZero renders t as unix seconds, or 0 for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// parseSession decodes the hash stored under tokenHash.
func parseSession(tokenHash string, fields map[string]string) (*domain.Session, error) {
	userID, err := strconv.ParseInt(fields[fieldUID], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("field %s: %w", fieldUID, err)
	}
	createdAt, err := parseUnix(fields[fieldCreatedAt])
	if err != nil {
		return nil, fmt.Errorf("field %s: %w", fieldCreatedAt, err)
	}
	expiresAt, err := parseUnix(fields[fieldExpiresAt])
	if err != nil {
		return nil, fmt.Errorf("field %s: %w", fieldExpiresAt, err)
	}

	id := fields[fieldSID]
	if id == "" {
		id = sidOf(tokenHash)
	}
	sess := &domain.Session{
		ID:        id,
		TokenHash: tokenHash,
		UserID:    userID,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		IP:        fields[fieldIP],
		UserAgent: fields[fieldUserAgent],
		AccessJTI: fields[fieldAccessJTI],
	}
	if raw, ok := fields[fieldAccessExpiresAt]; ok && raw != "" && raw != "0" {
		if sess.AccessExpiresAt, err = parseUnix(raw); err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldAccessExpiresAt, err)
		}
	}
	return sess, nil
}

// parseUnix converts a unix-seconds string into a UTC time.
func parseUnix(value string) (time.Time, error) {
	sec, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0).UTC(), nil
}

// sidOf returns the session id that corresponds to tokenHash.
func sidOf(tokenHash string) string {
	if len(tokenHash) <= domain.SessionIDLength {
		return tokenHash
	}
	return tokenHash[:domain.SessionIDLength]
}
