package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Build a real VCS-stamped Go executable so the collector, not a claimed
// fixture struct, proves which compiler/source produced it. Its --version
// protocol is controllable to test fail-closed LLVM/Go preflight errors.
func TestCollectDiscoveryProvenanceRealBuildMetadata(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + filepath.Join(root, "no-hooks")}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, output)
		}
	}
	git("init", "-q")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module github.com/xgo-dev/plan9asm/cmd/plan9asmll\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "_out/\n")
	evidenceDir := filepath.Join(root, "testdata", "discovery", "assembly-ledger")
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatal(err)
	}
	evidenceManifest := filepath.Join(evidenceDir, "manifest.json")
	writeTestFile(t, evidenceManifest, "{}\n")
	writeTestFile(t, filepath.Join(root, "main.go"), `package main
import ("fmt"; "os")
func main() {
 if len(os.Args)>1 && os.Args[1]=="env" {
  if os.Getenv("PROVENANCE_FIXTURE_GO_FAIL")!="" {os.Exit(1)}
  fmt.Println(os.Getenv("PROVENANCE_FIXTURE_GO_VERSION")); return
 }
 if os.Getenv("PROVENANCE_FIXTURE_LLVM_FAIL")!="" {os.Exit(1)}
 fmt.Println(os.Getenv("PROVENANCE_FIXTURE_LLVM_VERSION"))
}
`)
	git("add", ".")
	git("commit", "-qm", "fixture")
	outputDir := filepath.Join(root, "_out")
	if err := os.Mkdir(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	tool := filepath.Join(outputDir, "translator"+suffix)
	build := func() {
		t.Helper()
		cmd := exec.Command("go", "build", "-buildvcs=true", "-o", tool, ".")
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build VCS fixture: %v %s", err, output)
		}
	}
	build()
	ledger := filepath.Join(outputDir, "ledger.jsonl")
	writeTestFile(t, ledger, "{}\n")
	cfg := discoveryCorpusConfig{RepoRoot: root, LedgerPath: ledger, Translator: tool, LLC: tool}
	t.Setenv("PROVENANCE_FIXTURE_LLVM_VERSION", "LLVM version 22.1.8")
	p, err := collectDiscoveryProvenance(cfg)
	if !discoveryGoVersionPattern.MatchString(runtime.Version()) {
		// Compatibility jobs must prove old Go is rejected, not skip the
		// preflight or run the external corpus with an obsolete compiler.
		if err == nil || !strings.Contains(err.Error(), "matching Go 1.27") {
			t.Fatalf("old Go accepted: %+v %v", p, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryProvenance(p, p.Source, p.LedgerSHA256); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, evidenceManifest, "{\"passed\":1}\n")
	evidenceOnly, err := collectDiscoveryProvenance(cfg)
	if err != nil || evidenceOnly != p {
		t.Fatalf("evidence-only update invalidated frozen translator: %+v %v", evidenceOnly, err)
	}
	writeTestFile(t, evidenceManifest, "{}\n")

	for _, tc := range []struct{ name, variable, value, want string }{
		{"LLVM failure", "PROVENANCE_FIXTURE_LLVM_FAIL", "1", "read LLVM toolchain"},
		{"LLVM 23", "PROVENANCE_FIXTURE_LLVM_VERSION", "LLVM version 23.1.0", "requires LLVM 22"},
		{"unknown LLVM", "PROVENANCE_FIXTURE_LLVM_VERSION", "unversioned", "requires LLVM 22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.variable, tc.value)
			if _, err := collectDiscoveryProvenance(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("preflight error = %v", err)
			}
		})
	}
	goTool := filepath.Join(outputDir, "go"+suffix)
	bytes, err := os.ReadFile(tool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goTool, bytes, 0755); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []bool{false, true} {
		t.Run("Go protocol "+map[bool]string{false: "mismatch", true: "failure"}[failure], func(t *testing.T) {
			t.Setenv("PATH", outputDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PROVENANCE_FIXTURE_GO_VERSION", "go1.27.999")
			want := "matching Go 1.27"
			if failure {
				t.Setenv("PROVENANCE_FIXTURE_GO_FAIL", "1")
				want = "read Go toolchain"
			}
			if _, err := collectDiscoveryProvenance(cfg); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("preflight error = %v", err)
			}
		})
	}
	for _, which := range []string{"source", "ledger", "translator", "llc", "not Go"} {
		t.Run(which, func(t *testing.T) {
			bad := cfg
			missing := filepath.Join(outputDir, "missing")
			switch which {
			case "source":
				bad.RepoRoot = missing
			case "ledger":
				bad.LedgerPath = missing
			case "translator":
				bad.Translator = missing
			case "llc":
				bad.LLC = missing
			case "not Go":
				bad.Translator = ledger
			}
			if _, err := collectDiscoveryProvenance(bad); err == nil {
				t.Fatalf("accepted bad %s", which)
			}
		})
	}
	changed := filepath.Join(root, "changed.go")
	writeTestFile(t, changed, "package main\n")
	if _, err := collectDiscoveryProvenance(cfg); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("accepted stale clean binary: %v", err)
	}
	build()
	dirty, err := collectDiscoveryProvenance(cfg)
	if err != nil || !dirty.Source.Dirty || !dirty.TranslatorModified {
		t.Fatalf("dirty diagnostic provenance: %+v %v", dirty, err)
	}
	if err := validateDiscoveryProvenance(dirty, dirty.Source, dirty.LedgerSHA256); err == nil {
		t.Fatal("dirty diagnostic qualified for aggregate")
	}
	if err := os.Remove(changed); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDiscoveryProvenance(cfg); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("accepted dirty binary for clean source: %v", err)
	}
	build()
	git("commit", "--allow-empty", "-qm", "next revision")
	if _, err := collectDiscoveryProvenance(cfg); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("accepted binary from old revision: %v", err)
	}
}
