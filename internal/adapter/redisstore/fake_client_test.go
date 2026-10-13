package redisstore

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
)

// fakeClient is a redis.Cmdable that answers only the commands the tests script. Any other
// command reaches the nil embedded interface and panics, which keeps a store honest about
// the commands and round trips it makes.
type fakeClient struct {
	redis.Cmdable
	getDel    *redis.StringCmd
	getDelKey string
	pipeline  *fakePipeliner
	pipelines int
}

// GetDel records the key and returns the scripted answer.
func (c *fakeClient) GetDel(_ context.Context, key string) *redis.StringCmd {
	c.getDelKey = key
	return c.getDel
}

// Pipelined runs fn against the scripted pipeliner and, like go-redis, returns the queued
// commands together with the first error among them, redis.Nil included.
func (c *fakeClient) Pipelined(_ context.Context, fn func(redis.Pipeliner) error) ([]redis.Cmder, error) {
	c.pipelines++
	if err := fn(c.pipeline); err != nil {
		return nil, err
	}
	for _, cmd := range c.pipeline.queued {
		if err := cmd.Err(); err != nil {
			return c.pipeline.queued, err
		}
	}
	return c.pipeline.queued, nil
}

// fakePipeliner queues EXISTS and GET with scripted answers and records the keys asked for.
type fakePipeliner struct {
	redis.Pipeliner
	exists *redis.IntCmd
	get    *redis.StringCmd
	keys   []string
	queued []redis.Cmder
}

// Exists queues the scripted EXISTS answer.
func (p *fakePipeliner) Exists(_ context.Context, keys ...string) *redis.IntCmd {
	p.keys = append(p.keys, keys...)
	p.queued = append(p.queued, p.exists)
	return p.exists
}

// Get queues the scripted GET answer.
func (p *fakePipeliner) Get(_ context.Context, key string) *redis.StringCmd {
	p.keys = append(p.keys, key)
	p.queued = append(p.queued, p.get)
	return p.get
}

func intCmd(t *testing.T, val int64, err error) *redis.IntCmd {
	t.Helper()
	cmd := redis.NewIntCmd(t.Context())
	cmd.SetVal(val)
	if err != nil {
		cmd.SetErr(err)
	}
	return cmd
}

func stringCmd(t *testing.T, val string, err error) *redis.StringCmd {
	t.Helper()
	cmd := redis.NewStringCmd(t.Context())
	cmd.SetVal(val)
	if err != nil {
		cmd.SetErr(err)
	}
	return cmd
}
