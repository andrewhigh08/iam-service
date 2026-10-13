package app

import (
	"context"
	"errors"
	"fmt"
)

// Run starts the HTTP server and the rate-limiter janitor, blocks until ctx is canceled or
// the server fails, then shuts the server down gracefully within SERVER_SHUTDOWN_TIMEOUT and
// releases every resource with Close.
func (a *App) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.limiter.Start(runCtx)

	serveErr := make(chan error, 1)
	go func() {
		a.log.Info("http server listening", "addr", a.srv.Addr)
		serveErr <- a.srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		// Shutdown has not been called yet, so the server did not stop on purpose.
		return errors.Join(fmt.Errorf("http server: %w", err), a.Close())
	case <-ctx.Done():
	}

	a.log.Info("shutting down", "timeout", a.closeTimeout().String())
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), a.closeTimeout())
	defer cancelShutdown()
	var errs []error
	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("http server shutdown: %w", err))
	}
	errs = append(errs, a.Close())
	a.log.Info("shutdown complete")
	return errors.Join(errs...)
}
