//go:build linux

package cli

import (
	"context"
	"errors"
	"hacker-was-here/internal/safefs"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

func scan(parent context.Context, root, mode string) (report Report) {
	report = scanReport(root, mode)
	report.ScanStatus = "not_started"
	defer func() {
		if recover() != nil {
			report.fail(result(root, "failed", "internal_error", 4))
		}
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}()
	ctx, cancel := context.WithTimeout(parent, scanTimeout(mode))
	defer cancel()
	if ctx.Err() != nil {
		report.fail(interruption(parent, root))
		return
	}
	if runtime.GOARCH != "amd64" {
		report.fail(result(root, "rejected", "unsupported_environment", 3))
		return
	}
	r, err := safefs.OpenRoot(root)
	if err != nil {
		report.fail(preflightError(root, err))
		return
	}
	defer func() {
		if r.Close() != nil {
			report.fail(result(root, "failed", "internal_error", 4))
		}
	}()
	report.ScanStatus = "completed"
	report.Scope.ContentScanned = true
	errorBytes := 0
	collector := newFindingCollector(&report)
	recordPermission := func(name string) {
		report.partial("entry_errors")
		if len(*report.Errors) >= 200 {
			*report.ErrorsTruncated = true
			report.limit("error_paths")
		} else if errorBytes+len(name) > 256<<10 {
			*report.ErrorsTruncated = true
			report.limit("error_bytes")
		} else {
			*report.Errors = append(*report.Errors, ScanError{"permission_denied", pathValue(name)})
			errorBytes += len(name)
		}
	}
	budget := &safefs.ReadBudget{}
	if mode == "deep" {
		budget.Limit = safefs.MaxDeepTotalRead
	}
	defer func() { report.Coverage.ReadBytes = budget.Used }()
	var origins []safefs.Origin
	selectBody := func(e safefs.Entry) bool {
		return true // safefs enforces type, link, size and read budgets before IO.
	}
	visit := func(e safefs.Entry) error {
		if strings.HasPrefix(e.Reason, "budget:") {
			report.limit(strings.TrimPrefix(e.Reason, "budget:"))
			return nil
		}
		if errors.Is(e.BodyError, safefs.ErrPermission) {
			recordPermission(e.Name)
		}
		if errors.Is(e.BodyError, safefs.ErrLimit) {
			report.exclude("file_size_limit")
		}
		if e.Body.SHA256 != "" {
			report.Coverage.BodiesRead++
		}
		if e.Reason == "permission_denied" {
			recordPermission(e.Name)
			return nil
		}
		if e.Reason != "" {
			report.exclude(e.Reason)
		}
		if e.Kind != "regular" {
			return nil
		}
		id, reason := nameRule(e.Name)
		ids, reasons := []string{}, []string{}
		basis := "name_pattern"
		if id != "" {
			ids, reasons = append(ids, id), append(reasons, reason)
		}
		if e.Body.SHA256 != "" && textStatus(e.Body.Data) == "utf8" {
			contentIDs, contentReasons := contentRules(e.Body.Data)
			if len(contentIDs) > 0 {
				ids, reasons = append(ids, contentIDs...), append(reasons, contentReasons...)
				basis = "content_pattern"
			}
		}
		if len(ids) == 0 {
			return nil
		}
		path := pathValue(e.Name)
		var mtime *string
		if e.Mtime != nil {
			s := e.Mtime.Format(time.RFC3339Nano)
			mtime = &s
		}
		finding := Finding{RepresentativePath: path, Paths: []*Path{path}, CopyCount: 1, RuleIDs: ids, Reasons: reasons, DetectionBasis: basis, SizeBytes: &e.Size, Mtime: mtime, ContentStatus: "name_only"}
		if e.Reason != "" {
			s := e.Reason
			finding.ContentReason = &s
		}
		if e.BodyError != nil {
			s := "read_failed"
			switch {
			case errors.Is(e.BodyError, safefs.ErrLimit):
				s = "file_size_limit"
			case errors.Is(e.BodyError, safefs.ErrPermission):
				s = "permission_denied"
			case errors.Is(e.BodyError, safefs.ErrReadBudget):
				s = "total_read_bytes"
			case errors.Is(e.BodyError, safefs.ErrOriginReadBudget):
				s = "origin_read_bytes"
			case errors.Is(e.BodyError, safefs.ErrTargetChanged):
				s = "target_changed"
			case errors.Is(e.BodyError, safefs.ErrEnvironmentChanged):
				s = "environment_changed"
			case errors.Is(e.BodyError, context.Canceled), errors.Is(e.BodyError, context.DeadlineExceeded):
				s = "interrupted"
			}
			finding.ContentReason = &s
		}
		if e.Body.SHA256 != "" {
			finding.SHA256 = &e.Body.SHA256
			finding.ContentStatus = "complete"
			s := textStatus(e.Body.Data)
			finding.TextStatus = &s
		}
		if err := collector.add(finding, e.Name); err != nil {
			return safefs.ErrInvariant
		}
		return nil
	}
	if mode == "deep" {
		report.Coverage.EnumeratedEntries, origins, err = r.VisitDeep(ctx, budget, selectBody, visit)
	} else {
		report.Coverage.EnumeratedEntries, origins, err = r.VisitQuick(ctx, budget, selectBody, visit)
	}
	for _, o := range origins {
		report.Origins = append(report.Origins, Origin(o))
	}
	report.Coverage.ReadBytes = budget.Used
	switch {
	case errors.Is(err, safefs.ErrReadBudget):
		report.limit("total_read_bytes")
	case errors.Is(err, safefs.ErrEntryLimit):
		report.limit("enumeration_entries")
	case errors.Is(err, context.DeadlineExceeded):
		report.limit("deadline")
	case errors.Is(err, context.Canceled):
		report.fail(interruption(parent, root))
	case err != nil:
		report.fail(scanRuntimeFailure(root, err))
	}
	if parent.Err() != nil {
		report.fail(interruption(parent, root))
	}
	if err := collector.finish(); err != nil {
		report.fail(result(root, "failed", "internal_error", 4))
	}
	if report.ExitCode == 0 && report.Summary.CandidateCount > 0 {
		report.ExitCode = 1
	}
	return
}

func scanRuntimeFailure(root string, err error) Report {
	switch {
	case errors.Is(err, safefs.ErrTargetChanged):
		return result(root, "failed", "target_changed", 5)
	case errors.Is(err, safefs.ErrEnvironmentChanged):
		return result(root, "failed", "environment_changed", 5)
	case errors.Is(err, safefs.ErrIO):
		return result(root, "failed", "io_error", 6)
	case errors.Is(err, safefs.ErrInvariant),
		errors.Is(err, safefs.ErrEnvironment),
		errors.Is(err, safefs.ErrMount),
		errors.Is(err, safefs.ErrExcluded),
		errors.Is(err, safefs.ErrPermission):
		return result(root, "failed", "security_invariant_failed", 4)
	default:
		return result(root, "failed", "internal_error", 4)
	}
}

// Classification only: no decoding guesses, markup rendering or content rules.
func textStatus(data []byte) string {
	if !utf8.Valid(data) {
		return "unsupported_encoding_or_binary"
	}
	for _, c := range data {
		if c < 32 && c != '\t' && c != '\r' && c != '\n' || c == 127 {
			return "unsupported_encoding_or_binary"
		}
	}
	return "utf8"
}
