package cli

import (
	"io"
	"strings"
)

func previewReport() Report {
	r := scanReport("/synthetic/preview", "quick")
	r.Command = "preview"
	r.Status = "completed"
	r.Reason = "preview_sample"
	r.Message = "合成表示です。実対象の探索結果ではありません。"
	r.ExitCode = 0
	r.ScanStatus = "not_started"
	r.Scope.ContentScanned = true
	size := uint64(48)
	mtime := "2026-01-01T00:00:00Z"
	hash := "0000000000000000000000000000000000000000000000000000000000000000"
	textStatus := "utf8"
	path := pathValue("README.blacksuit.txt")
	r.Findings = []Finding{{
		RepresentativePath: path,
		Paths:              []*Path{path},
		CopyCount:          1,
		RuleIDs:            []string{"name.blacksuit-readme"},
		Reasons:            []string{"報告例のファイル名に一致。この理由は名前の一致に基づきます。"},
		SizeBytes:          &size,
		Mtime:              &mtime,
		SHA256:             &hash,
		ContentStatus:      "complete",
		TextStatus:         &textStatus,
		DetectionBasis:     "name_pattern",
	}}
	r.Summary.CandidateCount = 1
	r.Summary.GroupCount = 1
	r.Summary.RetainedGroupCount = 1
	r.Coverage.EnumeratedEntries = 3
	r.Coverage.ReadBytes = 48
	r.Coverage.BodiesRead = 1
	r.Origins = []Origin{{Path: ".", MaxDepth: 1, Status: "completed", EnumeratedEntries: 3, ReadBytes: 48}}
	r.exclude("symlink_excluded")
	return r
}

func runPreview(args []string, stdout, stderr io.Writer) int {
	wantJSON := false
	for _, arg := range args {
		if arg == "--json" {
			wantJSON = true
		}
	}
	jokes := jokeSet{}
	jokeOff, jokeOn := false, false
	reason := ""
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		name, _, assigned := strings.Cut(args[i], "=")
		if seen[name] {
			reason = "invalid_arguments"
			break
		}
		seen[name] = true
		switch name {
		case "--json":
			if assigned {
				reason = "invalid_arguments"
			}
		case "--detective", "--fortune", "--no-hope", "--no-joke":
			if assigned {
				reason = "invalid_arguments"
				break
			}
			switch name {
			case "--detective":
				jokes.detective = true
				jokeOn = true
			case "--fortune":
				jokes.fortune = true
				jokeOn = true
			case "--no-hope":
				jokes.noHope = true
				jokeOn = true
			case "--no-joke":
				jokeOff = true
			}
		default:
			reason = "invalid_arguments"
		}
		if reason != "" {
			break
		}
	}
	if jokeOff && jokeOn {
		reason = "invalid_arguments"
	}
	if reason != "" {
		report := result("", "rejected", reason, 3)
		report.Command = "preview"
		return emit(report, wantJSON, false, jokeSet{}, stdout, stderr)
	}
	if !jokeOff {
		jokes.detective = true
		jokes.fortune = true
	} else {
		jokes = jokeSet{}
	}
	return emit(previewReport(), wantJSON, false, jokes, stdout, stderr)
}
