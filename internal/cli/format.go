package cli

import (
	"io"
	"os"
	"strconv"
	"strings"
)

func terminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func header(title string, color bool) string {
	text := "[" + title + "]"
	if !color {
		return text
	}
	return "\x1b[1;36m" + text + "\x1b[0m"
}

func renderText(report Report, quiet bool, jokes jokeSet, color bool) string {
	var b strings.Builder
	if report.Command == "preview" && report.Reason == "preview_sample" {
		b.WriteString(previewBanner)
		b.WriteByte('\n')
	} else {
		b.WriteString(report.Reason)
		b.WriteString(": ")
		b.WriteString(report.Message)
		b.WriteByte('\n')
	}
	if report.Root != nil {
		b.WriteString("root=")
		b.WriteString(report.Root.Display)
		b.WriteByte('\n')
	}
	if report.Command == "scan" || (report.Command == "preview" && report.Scope != nil) {
		writeScanText(&b, report, quiet, color)
	}
	if !quiet {
		b.WriteString(jokes.text())
	}
	return b.String()
}

func writeScanText(b *strings.Builder, report Report, quiet, color bool) {
	kind, depth, rules := "", 0, "not_scanned"
	enumerated, candidates, groups, retained := 0, 0, 0, 0
	if report.Scope != nil {
		kind = report.Scope.Kind
		depth = report.Scope.MaxDepth
		if report.Scope.ContentScanned {
			rules = "scanned"
		}
	}
	if report.Coverage != nil {
		enumerated = report.Coverage.EnumeratedEntries
	}
	if report.Summary != nil {
		candidates = report.Summary.CandidateCount
		groups = report.Summary.GroupCount
		retained = report.Summary.RetainedGroupCount
	}
	b.WriteByte('\n')
	b.WriteString(header("要約", color))
	b.WriteByte('\n')
	b.WriteString("scope=")
	b.WriteString(kind)
	b.WriteString(" depth=")
	b.WriteString(strconv.Itoa(depth))
	b.WriteString(" content_rules=")
	b.WriteString(rules)
	b.WriteString(" enumerated=")
	b.WriteString(strconv.Itoa(enumerated))
	b.WriteString(" candidates=")
	b.WriteString(strconv.Itoa(candidates))
	b.WriteString(" groups=")
	b.WriteString(strconv.Itoa(groups))
	b.WriteString(" retained_groups=")
	b.WriteString(strconv.Itoa(retained))
	b.WriteByte('\n')

	if len(report.Origins) > 0 {
		b.WriteByte('\n')
		b.WriteString(header("起点", color))
		b.WriteByte('\n')
		for _, o := range report.Origins {
			b.WriteString("origin=")
			b.WriteString(strconv.QuoteToASCII(o.Path))
			b.WriteString(" depth=")
			b.WriteString(strconv.Itoa(o.MaxDepth))
			b.WriteString(" status=")
			b.WriteString(o.Status)
			b.WriteString(" enumerated=")
			b.WriteString(strconv.Itoa(o.EnumeratedEntries))
			b.WriteString(" read_bytes=")
			b.WriteString(strconv.Itoa(o.ReadBytes))
			b.WriteByte('\n')
		}
	}
	if !quiet && len(report.Findings) > 0 {
		b.WriteByte('\n')
		b.WriteString(header("候補", color))
		b.WriteByte('\n')
		for _, f := range report.Findings {
			writeFinding(b, f)
		}
	}
	exclusions := []Exclusion{}
	if report.PolicyExclusions != nil {
		exclusions = *report.PolicyExclusions
	}
	if len(exclusions) > 0 {
		b.WriteByte('\n')
		b.WriteString(header("除外", color))
		b.WriteByte('\n')
		for _, x := range exclusions {
			b.WriteString("excluded=")
			b.WriteString(x.Reason)
			b.WriteString(" count=")
			b.WriteString(strconv.Itoa(x.Count))
			b.WriteByte('\n')
		}
	}
	scanErrors := []ScanError{}
	if report.Errors != nil {
		scanErrors = *report.Errors
	}
	limits := []string{}
	if report.Limits != nil {
		limits = *report.Limits
	}
	truncated := false
	if report.ErrorsTruncated != nil {
		truncated = *report.ErrorsTruncated
	}
	if !quiet {
		var details []string
		for _, e := range scanErrors {
			if e.Path == nil {
				continue
			}
			details = append(details, "error="+e.Reason+" path="+e.Path.Display)
		}
		if len(details) > 0 {
			b.WriteByte('\n')
			b.WriteString(header("エラー", color))
			b.WriteByte('\n')
			for _, line := range details {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}
	b.WriteString("errors=")
	b.WriteString(strconv.Itoa(len(scanErrors)))
	b.WriteString(" errors_truncated=")
	b.WriteString(strconv.FormatBool(truncated))
	b.WriteString(" limits=")
	b.WriteString(strings.Join(limits, ","))
	b.WriteByte('\n')
}

func writeFinding(b *strings.Builder, f Finding) {
	display := "未取得"
	if f.RepresentativePath != nil {
		display = f.RepresentativePath.Display
	}
	b.WriteString(display)
	b.WriteByte('\n')
	mtime, hash, contentReason, size := "未取得", "未取得", "", "未取得"
	if f.Mtime != nil {
		mtime = *f.Mtime
	}
	if f.SHA256 != nil {
		hash = *f.SHA256
	}
	if f.ContentReason != nil {
		contentReason = *f.ContentReason
	}
	if f.SizeBytes != nil {
		size = strconv.FormatUint(*f.SizeBytes, 10)
	}
	b.WriteString("  copies=")
	b.WriteString(strconv.Itoa(f.CopyCount))
	b.WriteString(" paths_truncated=")
	b.WriteString(strconv.FormatBool(f.PathsTruncated))
	b.WriteString(" rule=")
	b.WriteString(strings.Join(f.RuleIDs, ","))
	b.WriteString(" size=")
	b.WriteString(size)
	b.WriteString(" mtime=")
	b.WriteString(mtime)
	b.WriteString(" content=")
	b.WriteString(f.ContentStatus)
	b.WriteString(" detection_basis=")
	b.WriteString(f.DetectionBasis)
	b.WriteString(" content_reason=")
	b.WriteString(contentReason)
	b.WriteString(" sha256=")
	b.WriteString(hash)
	b.WriteByte('\n')
	b.WriteString("  reason=")
	b.WriteString(strings.Join(f.Reasons, "; "))
	b.WriteByte('\n')
}
