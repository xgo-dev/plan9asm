// Package diffreport describes the execution evidence shared by conformance tests and the corpus scanner.
package diffreport

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Report struct {
	SchemaVersion   int    `json:"schema_version"`
	Goarch          string `json:"goarch"`
	Goos            string `json:"goos"`
	GoVersion       string `json:"go_version"`
	LLVMVersion     string `json:"llvm_version,omitempty"`
	NativeOracleRan bool   `json:"native_oracle_ran"`
	TotalInputs     int    `json:"total_inputs"`
	ComparedInputs  int    `json:"compared_inputs"`
	FailedInputs    int    `json:"failed_inputs"`
	Cases           []Case `json:"cases"`
}

type Case struct {
	ID                string   `json:"id"`
	Asm               string   `json:"asm"`
	Status            string   `json:"status"` // "passed", "hw_pending", "failed", "expected_value_only", "portable_only"
	VerificationMode  string   `json:"verification_mode,omitempty"`
	ExecutedInputs    int      `json:"executed_inputs"`
	ComparedInputs    int      `json:"compared_inputs"`
	FailedInputs      int      `json:"failed_inputs"`
	MissingHWFeatures []string `json:"missing_hw_features,omitempty"`
	Forms             []string `json:"forms"`
}

var versionLine = regexp.MustCompile(`(?im)\bLLVM version (22(?:\.[0-9]+){0,2}(?:(?:rc[0-9]+|git))?(?:[-+][0-9A-Za-z._+-]+)?)(?:[[:space:]]|$)`)

// LLVM22 extracts the exact LLVM 22 version token from llc's version banner.
func LLVM22(banner string) string {
	if m := versionLine.FindStringSubmatch(banner); m != nil {
		return m[1]
	}
	return ""
}

func (r *Report) Validate() error {
	if r.SchemaVersion != 1 || r.Goarch == "" || r.Goos == "" || r.GoVersion == "" || r.GoVersion == "unknown" || LLVM22(r.LLVMVersion) == "" {
		return fmt.Errorf("incomplete or unsupported diff report provenance: schema %d, %s/%s, Go %q, LLVM %q", r.SchemaVersion, r.Goos, r.Goarch, r.GoVersion, r.LLVMVersion)
	}
	if len(r.Cases) == 0 {
		return fmt.Errorf("diff report contains no cases")
	}
	seen := make(map[string]bool, len(r.Cases))
	exec, comp, fail := r.TotalInputs, r.ComparedInputs, r.FailedInputs
	for _, c := range r.Cases {
		if strings.TrimSpace(c.ID) == "" || seen[c.ID] {
			return fmt.Errorf("empty or duplicate diff case ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.ExecutedInputs < 0 || c.ComparedInputs < 0 || c.FailedInputs < 0 || c.ComparedInputs > c.ExecutedInputs || c.FailedInputs > c.ComparedInputs || c.ExecutedInputs > exec || c.ComparedInputs > comp || c.FailedInputs > fail {
			return fmt.Errorf("invalid diff input counts in %s", c.ID)
		}
		exec -= c.ExecutedInputs
		comp -= c.ComparedInputs
		fail -= c.FailedInputs
		native := c.VerificationMode == "native_diff" && r.NativeOracleRan
		valid := false
		switch c.Status {
		case "passed":
			valid = native && c.ExecutedInputs > 0 && c.ComparedInputs == c.ExecutedInputs && c.FailedInputs == 0
		case "failed":
			valid = native && (c.FailedInputs > 0 || c.ComparedInputs == 0)
		case "hw_pending":
			valid = native && len(c.MissingHWFeatures) > 0 && c.FailedInputs == 0 && (c.ComparedInputs < c.ExecutedInputs || c.ExecutedInputs == 0)
		case "expected_value_only", "portable_only":
			valid = c.VerificationMode == "expected_value_only" && c.ComparedInputs == 0 && c.ExecutedInputs > 0
		}
		if !valid {
			return fmt.Errorf("inconsistent status %q mode %q and counts for %s", c.Status, c.VerificationMode, c.ID)
		}
	}
	if exec != 0 || comp != 0 || fail != 0 {
		return fmt.Errorf("diff report totals disagree with case counts")
	}
	return nil
}

// Merge combines two validated batches from one execution environment. A case
// may be reported only once, so repeating a test cannot inflate the totals.
func (r *Report) Merge(other Report) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := other.Validate(); err != nil {
		return err
	}
	if r.Goarch != other.Goarch || r.Goos != other.Goos || r.GoVersion != other.GoVersion ||
		strings.TrimSpace(r.LLVMVersion) != strings.TrimSpace(other.LLVMVersion) {
		return fmt.Errorf("cannot merge differential evidence from different targets or toolchains")
	}
	merged := *r
	merged.NativeOracleRan = r.NativeOracleRan || other.NativeOracleRan
	merged.Cases = append(append(make([]Case, 0, len(r.Cases)+len(other.Cases)), r.Cases...), other.Cases...)
	merged.TotalInputs += other.TotalInputs
	merged.ComparedInputs += other.ComparedInputs
	merged.FailedInputs += other.FailedInputs
	if err := merged.Validate(); err != nil {
		return err
	}
	sort.Slice(merged.Cases, func(i, j int) bool { return merged.Cases[i].ID < merged.Cases[j].ID })
	*r = merged
	return nil
}
