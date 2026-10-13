// Package main is the entry point of the IAM service HTTP server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrewhigh08/iam-service/internal/app"
	"github.com/andrewhigh08/iam-service/internal/config"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// version is the build version, injected with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

// run loads the configuration, builds the application and serves it until SIGINT or SIGTERM.
func run() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "iam-service: invalid configuration: %v\n", err)
		return 1
	}

	logCfg := logger.DefaultConfig()
	logCfg.Level = cfg.Log.Level
	logCfg.Format = cfg.Log.Format
	log := logger.New(logCfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting iam-service", "version", version)
	application, err := app.New(ctx, cfg, log, version)
	if err != nil {
		log.Error("failed to start iam-service", "error", err)
		return 1
	}
	if err := application.Run(ctx); err != nil {
		log.Error("iam-service stopped with an error", "error", err)
		return 1
	}
	log.Info("iam-service stopped")
	return 0
}
