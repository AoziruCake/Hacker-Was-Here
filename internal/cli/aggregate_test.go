package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func aggregateFinding(name, hash string, ids ...string) Finding {
	path := pathValue(name)
	reasons := make([]string, len(ids))
	for i, id := range ids {
		reasons[i] = "reason:" + id
	}
	f := Finding{
		RepresentativePath: path,
		Paths:              []*Path{path},
		CopyCount:          1,
		RuleIDs:            ids,
		Reasons:            reasons,
		SizeBytes:          new(uint64),
		ContentStatus:      "name_only",
		DetectionBasis:     "name_pattern",
	}
	if hash != "" {
		f.SHA256 = &hash
		f.ContentStatus = "complete"
	}
	for _, id := range ids {
		if len(id) >= len("content.") && id[:len("content.")] == "content." {
			f.DetectionBasis = "content_pattern"
		}
	}
	return f
}

func TestFindingCollectorAggregatesOnlyCompleteHashes(t *testing.T) {
	report := scanReport("/synthetic", "quick")
	collector := newFindingCollector(&report)
	hashA := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	hashB := "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34"

	for _, input := range []struct {
		name string
		hash string
		ids  []string
	}{
		{"first", hashA, []string{"name.play-readme"}},
		{"second", hashA, []string{"content.encryption-recovery-contact"}},
		{"same-name-different-content", hashB, []string{"name.play-readme"}},
		{"no-hash-a", "", []string{"name.play-readme"}},
		{"no-hash-b", "", []string{"name.play-readme"}},
	} {
		if err := collector.add(aggregateFinding(input.name, input.hash, input.ids...), input.name); err != nil {
			t.Fatal(err)
		}
	}

	if report.Summary.CandidateCount != 5 || report.Summary.GroupCount != 4 ||
		report.Summary.RetainedGroupCount != 4 {
		t.Fatalf("summary = %+v", *report.Summary)
	}
	merged := report.Findings[0]
	if merged.RepresentativePath.Display != `"first"` || merged.CopyCount != 2 ||
		len(merged.Paths) != 2 || merged.PathsTruncated {
		t.Fatalf("merged finding = %+v", merged)
	}
	if got := fmt.Sprint(merged.RuleIDs); got != "[name.play-readme content.encryption-recovery-contact]" {
		t.Fatalf("rule IDs = %s", got)
	}
	if merged.DetectionBasis != "content_pattern" {
		t.Fatalf("detection basis = %q", merged.DetectionBasis)
	}
	if merged.Mtime != nil {
		t.Fatalf("missing representative mtime was replaced: %v", *merged.Mtime)
	}
	if report.Findings[2].SHA256 != nil || report.Findings[3].SHA256 != nil {
		t.Fatal("hashless findings were unexpectedly aggregated or hashed")
	}
}

func TestFindingCollectorBoundsRetainedDuplicatePaths(t *testing.T) {
	report := scanReport("/synthetic", "deep")
	collector := newFindingCollector(&report)
	hash := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	for i := 0; i < maxCandidatePaths+1; i++ {
		name := fmt.Sprintf("copy-%04d", i)
		if err := collector.add(aggregateFinding(name, hash, "name.play-readme"), name); err != nil {
			t.Fatal(err)
		}
	}

	if len(report.Findings) != 1 || report.Findings[0].CopyCount != maxCandidatePaths+1 {
		t.Fatalf("finding = %+v", report.Findings)
	}
	if len(report.Findings[0].Paths) != maxCandidatePaths || !report.Findings[0].PathsTruncated {
		t.Fatalf("retained paths=%d truncated=%t", len(report.Findings[0].Paths), report.Findings[0].PathsTruncated)
	}
	if report.ExitCode != 2 || report.ScanStatus != "incomplete" || !report.Summary.FindingsTruncated {
		t.Fatalf("report status = %+v", report)
	}
	if got := fmt.Sprint(*report.Limits); got != "[candidate_paths]" {
		t.Fatalf("limits = %s", got)
	}
}

func TestFindingCollectorBoundsAggregationKeys(t *testing.T) {
	if maxAggregateKeys != 200003 {
		t.Fatalf("aggregate key limit = %d", maxAggregateKeys)
	}
	report := scanReport("/synthetic", "deep")
	collector := newFindingCollector(&report)
	collector.maxKeys = 2
	for i, hash := range []string{strings.Repeat("0", 64), strings.Repeat("1", 64)} {
		name := fmt.Sprintf("candidate-%d", i)
		if err := collector.add(aggregateFinding(name, hash, "name.play-readme"), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := collector.add(aggregateFinding("overflow", strings.Repeat("2", 64), "name.play-readme"), "overflow"); !errors.Is(err, errInvalidAggregateHash) {
		t.Fatalf("overflow error = %v", err)
	}
}
