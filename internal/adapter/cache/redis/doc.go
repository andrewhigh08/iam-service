// Package redis implements the session, revocation and login-attempt stores on Redis.
//
// Every key carries the "iam:" prefix; keys.go documents the schema. Redis 7.0 or newer is
// required because the session index relies on EXPIRE with the NX and GT options.
package redis
