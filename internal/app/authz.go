package app

import (
	"fmt"

	"github.com/casbin/casbin/v3"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	rediswatcher "github.com/casbin/redis-watcher/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// policyChannel is the Redis channel on which replicas announce policy changes.
const policyChannel = "/casbin"

// newEnforcer builds the casbin enforcer on the application database, loads its policies and,
// when AUTHZ_WATCHER_ENABLED is set, subscribes it to policy changes made by other replicas.
// A synced enforcer is used because role assignments and watcher updates run concurrently
// with the access checks of in-flight requests. The adapter's own schema migration is turned
// off: the casbin_rule table belongs to the embedded migrations alone.
func (a *App) newEnforcer() (casbin.IEnforcer, error) {
	adapterDB := a.db.Session(&gorm.Session{})
	gormadapter.TurnOffAutoMigrate(adapterDB)
	adapter, err := gormadapter.NewAdapterByDB(adapterDB)
	if err != nil {
		return nil, fmt.Errorf("create policy adapter: %w", err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(a.cfg.Casbin.ModelPath, adapter)
	if err != nil {
		return nil, fmt.Errorf("create enforcer: %w", err)
	}
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	enforcer.EnableAutoSave(true)

	if !a.cfg.Casbin.WatcherEnabled {
		return enforcer, nil
	}
	if err := a.attachWatcher(enforcer); err != nil {
		return nil, err
	}
	return enforcer, nil
}

// attachWatcher connects enforcer to the Redis policy watcher so that policy changes made by
// one replica are applied by the others.
func (a *App) attachWatcher(enforcer casbin.IEnforcer) error {
	watcher, err := rediswatcher.NewWatcher(a.cfg.RedisAddr(), rediswatcher.WatcherOptions{
		Options: redis.Options{
			Addr:     a.cfg.RedisAddr(),
			Password: a.cfg.Redis.Password,
			DB:       a.cfg.Redis.DB,
		},
		Channel:    policyChannel,
		IgnoreSelf: true,
	})
	if err != nil {
		return fmt.Errorf("create policy watcher: %w", err)
	}
	a.watcher = watcher
	if err := enforcer.SetWatcher(watcher); err != nil {
		return fmt.Errorf("attach policy watcher: %w", err)
	}
	if err := watcher.SetUpdateCallback(rediswatcher.DefaultUpdateCallback(enforcer)); err != nil {
		return fmt.Errorf("configure policy watcher: %w", err)
	}
	a.log.Info("policy watcher enabled", "channel", policyChannel)
	return nil
}
