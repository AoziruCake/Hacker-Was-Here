//go:build !linux

package cli

import "context"

func check(_ context.Context, root string) Report {
	return result(root, "rejected", "unsupported_environment", 3)
}
