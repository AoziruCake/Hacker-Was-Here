package main

import (
	"context"
	"os"
	"runtime"

	"hacker-was-here/internal/cli"
)

func main() {
	// Keep the credential checks and filesystem operations on one OS thread.
	runtime.LockOSThread()
	ctx, stop := commandContext(context.Background())
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
