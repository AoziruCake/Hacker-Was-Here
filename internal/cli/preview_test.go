package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPreviewShowsSampleWithoutMount(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"preview"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{previewBanner, "[要約]", "[候補]", "[除外]", "candidates=1", "name.blacksuit-readme", "JOKE[detective]", "JOKE[fortune]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stdout missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "JOKE[no-hope]") || strings.Contains(text, "\x1b") || strings.Contains(text, "unsupported") {
		t.Fatalf("stdout = %q", text)
	}
}

func TestPreviewJSONIsNotAScanResult(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"preview", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Command != "preview" || report.Reason != "preview_sample" || report.ExitCode != 0 || report.ScanStatus != "not_started" {
		t.Fatalf("report = %+v", report)
	}
	if report.Message != "合成表示です。実対象の探索結果ではありません。" || len(report.Findings) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if bytes.Contains(stdout.Bytes(), []byte("JOKE")) {
		t.Fatalf("stdout contains joke: %s", stdout.String())
	}
}

func TestPreviewNoJokeAndRejectsRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"preview", "--no-joke"}, &stdout, &stderr)
	if code != 0 || bytes.Contains(stdout.Bytes(), []byte("JOKE")) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"preview", "--root", "/tmp"}, &stdout, &stderr)
	if code != 3 || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("invalid_arguments:")) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"preview", "--no-joke", "--detective", "--json"}, &stdout, &stderr)
	if code != 3 || bytes.Contains(stdout.Bytes(), []byte("JOKE")) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Command != "preview" || report.Reason != "invalid_arguments" {
		t.Fatalf("report = %+v", report)
	}
}

func TestScanTextKeepsStableTokens(t *testing.T) {
	report := scanReport("/synthetic/evidence", "quick")
	report.Status = "partial"
	report.Reason = "entry_errors"
	report.Message = message("entry_errors")
	report.ExitCode = 2
	report.Summary.CandidateCount = 6
	text := renderText(report, true, jokeSet{detective: true}, true)
	if !strings.Contains(text, "entry_errors:") || !strings.Contains(text, "candidates=6") {
		t.Fatalf("text = %q", text)
	}
	if !strings.Contains(text, "\x1b[1;36m[要約]\x1b[0m") {
		t.Fatalf("text = %q", text)
	}
	plain := renderText(report, true, jokeSet{}, false)
	if strings.Contains(plain, "\x1b") || strings.Contains(plain, "JOKE") {
		t.Fatalf("plain = %q", plain)
	}
}

func TestHelpMentionsPreviewWithoutHiddenJoke(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"preview", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "hwh preview") || !strings.Contains(text, "--no-joke") || strings.Contains(text, "--no-hope") {
		t.Fatalf("help = %q", text)
	}
}
