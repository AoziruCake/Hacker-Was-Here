package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	maxCandidatePaths = 2000
	maxCandidateBytes = 2 << 20
	maxAggregateKeys  = 200003 // deep entries, plus quick's three fixed files
	maxFindingsBytes  = 6 << 20
)

var errInvalidAggregateHash = errors.New("invalid complete hash for aggregation")

type aggregateGroup struct {
	retainedIndex int
}

type findingCollector struct {
	report        *Report
	byHash        map[[32]byte]aggregateGroup
	maxKeys       int
	retainedPaths int
	retainedBytes int
}

func newFindingCollector(report *Report) *findingCollector {
	return &findingCollector{report: report, byHash: make(map[[32]byte]aggregateGroup), maxKeys: maxAggregateKeys}
}

func (c *findingCollector) add(finding Finding, rawPath string) error {
	c.report.Summary.CandidateCount++

	var (
		key       [32]byte
		hasHash   = finding.SHA256 != nil
		group     aggregateGroup
		groupSeen bool
	)
	if hasHash {
		decoded, err := hex.DecodeString(*finding.SHA256)
		if err != nil || len(decoded) != len(key) {
			return errInvalidAggregateHash
		}
		copy(key[:], decoded)
		group, groupSeen = c.byHash[key]
		if groupSeen {
			if group.retainedIndex >= 0 {
				existing := &c.report.Findings[group.retainedIndex]
				existing.CopyCount++
				mergeFindingReasons(existing, finding)
				c.retainAdditionalPath(existing, finding.RepresentativePath, rawPath)
			}
			return nil
		}
		if len(c.byHash) >= c.maxKeys {
			return errInvalidAggregateHash
		}
	}

	c.report.Summary.GroupCount++
	retainedIndex := -1
	if c.canRetainPath(rawPath) {
		retainedIndex = len(c.report.Findings)
		c.report.Findings = append(c.report.Findings, finding)
		c.retainedPaths++
		c.retainedBytes += len(rawPath)
		c.report.Summary.RetainedGroupCount++
	} else {
		c.report.Summary.FindingsTruncated = true
	}
	if hasHash {
		c.byHash[key] = aggregateGroup{retainedIndex: retainedIndex}
	}
	return nil
}

func (c *findingCollector) canRetainPath(rawPath string) bool {
	switch {
	case c.retainedPaths >= maxCandidatePaths:
		c.report.limit("candidate_paths")
	case c.retainedBytes+len(rawPath) > maxCandidateBytes:
		c.report.limit("candidate_bytes")
	default:
		return true
	}
	return false
}

func (c *findingCollector) retainAdditionalPath(finding *Finding, path *Path, rawPath string) {
	if !c.canRetainPath(rawPath) {
		finding.PathsTruncated = true
		c.report.Summary.FindingsTruncated = true
		return
	}
	finding.Paths = append(finding.Paths, path)
	c.retainedPaths++
	c.retainedBytes += len(rawPath)
}

func mergeFindingReasons(dst *Finding, src Finding) {
	for _, id := range src.RuleIDs {
		if !contains(dst.RuleIDs, id) {
			dst.RuleIDs = append(dst.RuleIDs, id)
		}
	}
	for _, reason := range src.Reasons {
		if !contains(dst.Reasons, reason) {
			dst.Reasons = append(dst.Reasons, reason)
		}
	}
	if src.DetectionBasis == "content_pattern" {
		dst.DetectionBasis = "content_pattern"
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// finish enforces the findings portion of the output budget without losing a
// representative. It first drops non-representative paths, then whole trailing
// groups. Counts continue to describe all candidates observed within scan scope.
func (c *findingCollector) finish() error {
	sizes := make([]int, len(c.report.Findings))
	total := 2 // JSON array brackets
	for i := range c.report.Findings {
		encoded, err := json.Marshal(c.report.Findings[i])
		if err != nil {
			return err
		}
		sizes[i] = len(encoded)
		total += sizes[i]
		if i > 0 {
			total++
		}
	}
	if total <= maxFindingsBytes {
		return nil
	}
	c.report.limit("output_bytes")
	c.report.Summary.FindingsTruncated = true

	for i := len(c.report.Findings) - 1; i >= 0 && total > maxFindingsBytes; i-- {
		finding := &c.report.Findings[i]
		if len(finding.Paths) <= 1 {
			continue
		}
		oldSize := sizes[i]
		finding.Paths = finding.Paths[:1]
		finding.PathsTruncated = true
		encoded, err := json.Marshal(*finding)
		if err != nil {
			return err
		}
		sizes[i] = len(encoded)
		total += sizes[i] - oldSize
	}
	for total > maxFindingsBytes && len(c.report.Findings) > 0 {
		last := len(c.report.Findings) - 1
		total -= sizes[last]
		if last > 0 {
			total--
		}
		c.report.Findings = c.report.Findings[:last]
		sizes = sizes[:last]
	}
	c.report.Summary.RetainedGroupCount = len(c.report.Findings)
	return nil
}
