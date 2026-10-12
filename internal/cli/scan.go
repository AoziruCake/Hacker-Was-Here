package cli

import (
	"strings"
	"time"
)

type Finding struct {
	RepresentativePath *Path    `json:"representative_path"`
	Paths              []*Path  `json:"paths"`
	PathsTruncated     bool     `json:"paths_truncated"`
	CopyCount          int      `json:"copy_count"`
	RuleIDs            []string `json:"rule_ids"`
	Reasons            []string `json:"reasons"`
	SizeBytes          *uint64  `json:"size_bytes"`
	Mtime              *string  `json:"mtime"`
	SHA256             *string  `json:"sha256"`
	ContentStatus      string   `json:"content_status"`
	ContentReason      *string  `json:"content_reason"`
	TextStatus         *string  `json:"text_status"`
	DetectionBasis     string   `json:"detection_basis"`
	Excerpt            *string  `json:"excerpt"`
}

func nameRule(name string) (string, string) {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	s := string(b)
	switch s {
	case "readme.blacksuit.txt":
		return "name.blacksuit-readme", "報告例のファイル名に一致。この理由は名前の一致に基づきます。"
	case "play_readme.txt":
		return "name.play-readme", "報告例のファイル名に一致。この理由は名前の一致に基づきます。"
	}
	const suffix = ".crypted.readme_to_restore"
	if len(s) > len(suffix) && strings.HasSuffix(s, suffix) {
		return "name.crypted-restore", "報告例の接尾辞に一致。この理由は名前の一致に基づきます。"
	}
	return "", ""
}

type Scope struct {
	Kind           string `json:"kind"`
	MaxDepth       int    `json:"max_depth"`
	ContentScanned bool   `json:"content_scanned"`
}
type Summary struct {
	CandidateCount     int  `json:"candidate_count"`
	GroupCount         int  `json:"group_count"`
	RetainedGroupCount int  `json:"retained_group_count"`
	FindingsTruncated  bool `json:"findings_truncated"`
}
type Coverage struct {
	EnumeratedEntries int `json:"enumerated_entries"`
	ReadBytes         int `json:"read_bytes"`
	BodiesRead        int `json:"bodies_read"`
}
type Origin struct {
	Path              string `json:"path"`
	MaxDepth          int    `json:"max_depth"`
	Status            string `json:"status"`
	EnumeratedEntries int    `json:"enumerated_entries"`
	ReadBytes         int    `json:"read_bytes"`
}
type Exclusion struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}
type ScanError struct {
	Reason string `json:"reason"`
	Path   *Path  `json:"path"`
}

func scanTimeout(mode string) time.Duration {
	if mode == "deep" {
		return 300 * time.Second
	}
	return 30 * time.Second
}

func scanReport(root, mode string) Report {
	r := result(root, "completed", "scope_completed", 0)
	r.Command = "scan"
	r.ScanStatus = "completed"
	depth := 4
	if mode == "deep" {
		depth = 64
	}
	r.Scope = &Scope{mode, depth, false}
	r.Origins = []Origin{}
	r.Summary = &Summary{}
	r.Coverage = &Coverage{}
	exclusions, scanErrors, limits := []Exclusion{}, []ScanError{}, []string{}
	truncated := false
	r.PolicyExclusions, r.Errors, r.Limits, r.ErrorsTruncated = &exclusions, &scanErrors, &limits, &truncated
	return r
}

func (r *Report) exclude(reason string) {
	for i := range *r.PolicyExclusions {
		if (*r.PolicyExclusions)[i].Reason == reason {
			(*r.PolicyExclusions)[i].Count++
			return
		}
	}
	*r.PolicyExclusions = append(*r.PolicyExclusions, Exclusion{reason, 1})
}

// Failure priority follows the public CLI contract, not numeric exit codes.
func priority(code int) int {
	switch code {
	case 7:
		return 9
	case 4:
		return 8
	case 5:
		return 7
	case 6:
		return 6
	case 130, 143:
		return 5
	case 3:
		return 4
	case 2:
		return 3
	case 1:
		return 2
	default:
		return 1
	}
}
func (r *Report) fail(f Report) {
	if priority(f.ExitCode) < priority(r.ExitCode) {
		return
	}
	r.Status, r.Reason, r.Message, r.ExitCode = f.Status, f.Reason, f.Message, f.ExitCode
	if r.ScanStatus != "not_started" {
		r.ScanStatus = "incomplete"
	}
}
func (r *Report) partial(reason string) { r.fail(result("", "partial", reason, 2)) }
func (r *Report) limit(id string) {
	for _, existing := range *r.Limits {
		if existing == id {
			return
		}
	}
	*r.Limits = append(*r.Limits, id)
	r.partial("budget_exceeded")
}
func scanFailure(root string, failure Report, mode string) Report {
	r := scanReport(root, mode)
	r.ScanStatus = "not_started"
	r.fail(failure)
	return r
}
