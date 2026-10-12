package cli

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestScanTimeouts(t *testing.T) {
	if got := scanTimeout("quick"); got != 30*time.Second {
		t.Fatalf("quick timeout = %s", got)
	}
	if got := scanTimeout("deep"); got != 300*time.Second {
		t.Fatalf("deep timeout = %s", got)
	}
}

func TestScanDefaultJokeOnRejectedRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--root", "relative"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("JOKE[detective]")) {
		t.Fatalf("stderr = %q, want default detective joke", stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("JOKE[fortune]")) {
		t.Fatalf("stderr = %q, want default fortune joke", stderr.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte("JOKE[no-hope]")) {
		t.Fatalf("stderr = %q, did not want hidden joke", stderr.String())
	}
}

func TestScanNoJokeSuppressesDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--root", "relative", "--no-joke"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if bytes.Contains(stderr.Bytes(), []byte("JOKE")) {
		t.Fatalf("stderr contains joke: %q", stderr.String())
	}
}

func TestScanNoJokeConflictsWithJokeFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--root", "relative", "--no-joke", "--detective", "--json"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if bytes.Contains(stdout.Bytes(), []byte("JOKE")) {
		t.Fatalf("stdout contains joke: %q", stdout.String())
	}
}

func TestCheckRejectsNoJoke(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"check", "--root", "/synthetic", "--no-joke", "--json"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if bytes.Contains(stdout.Bytes(), []byte("JOKE")) {
		t.Fatalf("stdout contains joke: %q", stdout.String())
	}
}

func TestQuietSuppressesJokeForInterruptedScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer

	code := Run(ctx, []string{"scan", "--root", "/synthetic", "--quiet", "--detective"}, &stdout, &stderr)

	if code != 130 {
		t.Fatalf("exit code = %d, want 130", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte("JOKE")) {
		t.Fatalf("stderr contains joke: %q", stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("interrupted:")) {
		t.Fatalf("stderr = %q, want interruption report", stderr.String())
	}
}
