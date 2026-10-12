//go:build linux

// safefs-probe is a ticket 01 laboratory tool, not the hwh product CLI.
// Arguments must refer only to the synthetic fixture environment.
package main

import (
	"context"
	"fmt"
	"os"

	"hacker-was-here/internal/safefs"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "LAB ONLY: safefs-probe ABSOLUTE_ROOT RELATIVE_FILE")
		os.Exit(2)
	}
	root, err := safefs.OpenRoot(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "rejected: %q\n", err.Error())
		os.Exit(1)
	}
	result, err := root.Read(context.Background(), os.Args[2])
	closeErr := root.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unread: %q\n", err.Error())
		os.Exit(1)
	}
	if closeErr != nil {
		fmt.Fprintln(os.Stderr, "descriptor cleanup failed")
		os.Exit(1)
	}
	fmt.Printf("LAB ONLY: bytes=%d sha256=%s\n", len(result.Data), result.SHA256)
}
