//go:build linux

package cli

import (
	"context"
	"errors"
	"hacker-was-here/internal/safefs"
	"runtime"
)

func check(ctx context.Context, root string) Report {
	if ctx.Err() != nil {
		return interruption(ctx, root)
	}
	if runtime.GOARCH != "amd64" {
		return result(root, "rejected", "unsupported_environment", 3)
	}
	r, err := safefs.OpenRoot(root)
	if err == nil {
		if r.Close() != nil {
			return result(root, "failed", "internal_error", 4)
		}
	}
	if err == nil {
		return result(root, "passed", "conditions_passed", 0)
	}
	return preflightError(root, err)
}

func preflightError(root string, err error) Report {
	reason := "unsupported_environment"
	switch {
	case errors.Is(err, safefs.ErrRoot), errors.Is(err, safefs.ErrExcluded):
		reason = "invalid_root"
	case errors.Is(err, safefs.ErrPrivilege):
		reason = "privileged_execution"
	case errors.Is(err, safefs.ErrMount):
		reason = "unsupported_mount"
	case errors.Is(err, safefs.ErrPermission):
		reason = "permission_denied"
	case errors.Is(err, safefs.ErrTargetChanged), errors.Is(err, safefs.ErrEnvironmentChanged):
		return result(root, "failed", "environment_changed", 5)
	case errors.Is(err, safefs.ErrInvariant):
		return result(root, "failed", "internal_error", 4)
	case errors.Is(err, safefs.ErrIO):
		return result(root, "failed", "io_error", 6)
	}
	return result(root, "rejected", reason, 3)
}
