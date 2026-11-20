package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Run the actual CI checker, not a duplicate fingerprint comparison. These
// synthetic reports prove drift detection only, never instruction coverage.
func TestOfficialCoverageCIChecksCompleteEncodingRuleAttributes(t *testing.T) {
	script, err := os.ReadFile("../../scripts/check-go-asm-coverage.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, python, ok := strings.Cut(string(script), "<<'PY'\n")
	if !ok {
		t.Fatal("official coverage checker is not bound to its script")
	}
	python, _, ok = strings.Cut(python, "\nPY\n")
	if !ok {
		t.Fatal("official coverage checker has no complete heredoc")
	}
	tool, err := exec.LookPath("python3")
	if err != nil {
		tool, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("Python 3 is required by the actual official CI checker", err)
	}
	original, err := os.ReadFile("../../testdata/coverage/go-asm-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		"unchanged", "changed-fingerprint", "changed-count", "missing-report",
		"missing-baseline", "both-missing", "386-fingerprint", "count-zero",
		"count-bool", "count-string", "malformed-fingerprint", "missing-count", "missing-fingerprint",
	} {
		t.Run(mutation, func(t *testing.T) {
			var baseline map[string]interface{}
			if err := json.Unmarshal(original, &baseline); err != nil {
				t.Fatal(err)
			}
			versions := baseline["versions"].(map[string]interface{})
			// Every minor and architecture remains present in the real checker.
			// Add isolated synthetic attributes without changing class buckets.
			for _, release := range versions {
				arches := release.(map[string]interface{})
				for _, arch := range []string{"386", "amd64"} {
					entry := arches[arch].(map[string]interface{})
					entry["encoder_rules"] = float64(3)
					entry["encoder_rule_fingerprint"] = strings.Repeat("a", 64)
				}
			}
			arches := versions["go1.27"].(map[string]interface{})
			reports := make(map[string]map[string]interface{})
			for arch, value := range arches {
				bytes, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				var report map[string]interface{}
				if err := json.Unmarshal(bytes, &report); err != nil {
					t.Fatal(err)
				}
				report["go_version"] = "go1.27.1"
				report["goarch"] = arch
				reports[arch] = report
			}
			families, err := os.ReadFile("../../testdata/coverage/arm64-go-assembler-families.txt")
			if err != nil {
				t.Fatal(err)
			}
			var catalog []map[string]interface{}
			for _, line := range strings.Split(string(families), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					catalog = append(catalog, map[string]interface{}{
						"opcode": line, "encoder_forms": 1, "observed_in_corpus": true,
					})
				}
			}
			reports["arm64"]["opcode_catalog"] = catalog
			entry := arches["amd64"].(map[string]interface{})
			switch mutation {
			case "changed-fingerprint":
				reports["amd64"]["encoder_rule_fingerprint"] = strings.Repeat("b", 64)
			case "changed-count":
				reports["amd64"]["encoder_rules"] = float64(4)
			case "386-fingerprint":
				reports["386"]["encoder_rule_fingerprint"] = strings.Repeat("b", 64)
			case "count-zero":
				reports["amd64"]["encoder_rules"] = 0
			case "count-bool":
				reports["amd64"]["encoder_rules"] = true
			case "count-string":
				reports["amd64"]["encoder_rules"] = "3"
			case "malformed-fingerprint":
				reports["amd64"]["encoder_rule_fingerprint"] = "not-a-rule-hash"
			case "missing-count":
				delete(reports["amd64"], "encoder_rules")
			case "missing-fingerprint":
				delete(reports["amd64"], "encoder_rule_fingerprint")
			case "missing-report", "both-missing":
				delete(reports["amd64"], "encoder_rules")
				delete(reports["amd64"], "encoder_rule_fingerprint")
			}
			if mutation == "missing-baseline" || mutation == "both-missing" {
				delete(entry, "encoder_rules")
				delete(entry, "encoder_rule_fingerprint")
			}
			dir := t.TempDir()
			write := func(name string, value interface{}) {
				bytes, err := json.Marshal(value)
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, name), bytes, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			write("baseline.json", baseline)
			reportDir := filepath.Join(dir, "reports")
			if err := os.Mkdir(reportDir, 0700); err != nil {
				t.Fatal(err)
			}
			for arch, report := range reports {
				write(filepath.Join("reports", arch+".json"), report)
			}
			familyPath, err := filepath.Abs("../../testdata/coverage/arm64-go-assembler-families.txt")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, tool, "-", filepath.Join(dir, "baseline.json"), familyPath, reportDir)
			command.Stdin = strings.NewReader(python)
			output, err := command.CombinedOutput()
			if mutation == "unchanged" {
				if err != nil {
					t.Fatalf("unchanged complete synthetic inventory rejected: %v\n%s", err, output)
				}
			} else if err == nil {
				t.Fatalf("CI accepted %s with identical historical operand-class fingerprint:\n%s", mutation, output)
			} else if ctx.Err() != nil || !strings.Contains(string(output), "encoder_rule") {
				t.Fatalf("CI failure was not an encoding-rule diagnosis: %v\n%s", err, output)
			}
		})
	}
}

type encodingRuleBaselineEntry struct {
	EncoderForms           int    `json:"encoder_forms"`
	EncoderFingerprint     string `json:"encoder_fingerprint"`
	EncoderRules           int    `json:"encoder_rules"`
	EncoderRuleFingerprint string `json:"encoder_rule_fingerprint"`
}

// The optional source roots let maintainers query several installed SDKs in
// one process. This is table inventory, not an assembler/runtime certificate.
func TestOfficialCoverageRuleBaselineMatchesSelectedGoTables(t *testing.T) {
	roots := []string{runtime.GOROOT()}
	if configured := os.Getenv("PLAN9ASM_ENCODER_RULE_SOURCE_ROOTS"); configured != "" {
		if err := json.Unmarshal([]byte(configured), &roots); err != nil || len(roots) == 0 || len(roots) > 16 {
			t.Fatal("invalid bounded SDK-source query", err)
		}
	}
	data, err := os.ReadFile("../../testdata/coverage/go-asm-baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Versions map[string]map[string]encodingRuleBaselineEntry `json:"versions"`
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}
	for _, root := range roots {
		version := regexp.MustCompile(`^go[0-9]+\.[0-9]+`).FindString(goVersion(root))
		if baseline.Versions[version] == nil {
			t.Fatal("SDK has no versioned table baseline", version)
		}
		for _, arch := range []string{"386", "amd64"} {
			t.Run(version+"/"+arch, func(t *testing.T) {
				catalog, err := loadEncoderForms(root, arch)
				if err != nil {
					t.Fatal(err)
				}
				var report report
				attachEncoderCatalog(&report, nil, catalog)
				want := baseline.Versions[version][arch]
				// An attribute update may not bless a changed old class surface.
				if report.EncoderForms != want.EncoderForms || report.EncoderFingerprint != want.EncoderFingerprint {
					t.Fatalf("unreviewed historical class inventory change: forms=%d/%d fingerprint=%s/%s",
						report.EncoderForms, want.EncoderForms, report.EncoderFingerprint, want.EncoderFingerprint)
				}
				source, err := os.ReadFile(filepath.Join(root, "src/cmd/internal/obj/x86/avx_optabs.go"))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("ENCODER_RULE_TABLE_ONLY version=%s arch=%s rules=%d fingerprint=%s source_sha=%x",
					version, arch, report.EncoderRules, report.EncoderRuleFingerprint, sha256.Sum256(source))
				if report.EncoderRules <= 0 || report.EncoderRules != want.EncoderRules ||
					report.EncoderRuleFingerprint != want.EncoderRuleFingerprint {
					t.Fatalf("AVX source-rule inventory differs from baseline: rules=%d/%d fingerprint=%s/%s",
						report.EncoderRules, want.EncoderRules, report.EncoderRuleFingerprint, want.EncoderRuleFingerprint)
				}
			})
		}
	}
}
