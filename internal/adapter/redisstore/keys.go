package redisstore

import "strconv"

// keyPrefix starts every key written by this package. The schema is:
//
//	iam:session:<tokenHash>         HASH {uid, sid, created_at, expires_at, ip, ua, jti, access_exp}; TTL = refresh TTL
//	iam:session:rotated:<tokenHash> uid of the session Take consumed under the hash, deleted by the first ConsumedBy; TTL = refresh TTL
//	iam:user:<uid>:sessions         SET of token hashes; TTL extended to the refresh TTL on write
//	iam:revoked:jti:<jti>           "1"; TTL = remaining access TTL
//	iam:user:<uid>:revoked_before   unix seconds; TTL = access TTL plus grace
//	iam:login:fail:<key>            failure counter; TTL = lockout window, set when created
//	iam:login:lock:<key>            "1"; TTL = lockout duration
//
// Timestamps are stored as unix seconds.
const keyPrefix = "iam:"

func sessionKey(tokenHash string) string {
	return keyPrefix + "session:" + tokenHash
}

func rotatedSessionKey(tokenHash string) string {
	return keyPrefix + "session:rotated:" + tokenHash
}

func userSessionsKey(userID int64) string {
	return keyPrefix + "user:" + strconv.FormatInt(userID, 10) + ":sessions"
}

func revokedJTIKey(jti string) string {
	return keyPrefix + "revoked:jti:" + jti
}

func userRevokedBeforeKey(userID int64) string {
	return keyPrefix + "user:" + strconv.FormatInt(userID, 10) + ":revoked_before"
}

func loginFailKey(key string) string {
	return keyPrefix + "login:fail:" + key
}

func loginLockKey(key string) string {
	return keyPrefix + "login:lock:" + key
}
