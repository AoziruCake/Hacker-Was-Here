//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"hacker-was-here/internal/cli"
)

func commandContext(parent context.Context) (context.Context, func()) {
	signal.Ignore(syscall.SIGPIPE)
	ctx, cancel := context.WithCancelCause(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-ch:
			if sig == syscall.SIGTERM {
				cancel(cli.ErrTerminated)
			} else {
				cancel(context.Canceled)
			}
		case <-ctx.Done():
		}
	}()
	return ctx, func() { signal.Stop(ch); cancel(context.Canceled) }
}
