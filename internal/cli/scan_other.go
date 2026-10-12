//go:build !linux

package cli

import "context"

func scan(ctx context.Context, root, mode string) Report {
	r := scanReport(root, mode)
	r.Status, r.Reason, r.Message, r.ExitCode = "rejected", "unsupported_environment", message("unsupported_environment"), 3
	r.ScanStatus = "not_started"
	return r
}
