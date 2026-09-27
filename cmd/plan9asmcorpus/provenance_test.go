package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureDiscoveryProvenance(t *testing.T, ledger string) discoveryCorpusProvenance {
	t.Helper()
	sha, err := discoveryLedgerFingerprint(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return discoveryCorpusProvenance{
		Source:       discoverySourceIdentity{Revision: strings.Repeat("a", 40), SHA256: strings.Repeat("b", 64)},
		LedgerSHA256: sha, TranslatorSHA256: strings.Repeat("c", 64), TranslatorRevision: strings.Repeat("a", 40),
		TranslatorGo: "go1.27.1", GoVersion: "go1.27.1", LLVMVersion: "22.1.8", LLCBinarySHA256: strings.Repeat("d", 64),
	}
}

func TestDiscoveryGoVersionCannotAutoSwitch(t *testing.T) {
	dir := t.TempDir()
	goCommand := filepath.Join(dir, "go")
	if runtime.GOOS == "windows" {
		goCommand += ".exe"
	}
	source := filepath.Join(dir, "fake_go.go")
	writeTestFile(t, source, `package main
import (
	"fmt"
	"os"
)
func main() {
	if os.Getenv("GOTOOLCHAIN") == "local" {
		fmt.Println("go1.27.0")
	} else {
		fmt.Println("go1.27.1")
	}
}
`)
	build := exec.Command("go", "build", "-o", goCommand, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native Go version fixture: %v\n%s", err, output)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOTOOLCHAIN", "go1.27.1")
	resolved, err := exec.LookPath("go")
	if err != nil || !strings.EqualFold(resolved, goCommand) {
		t.Fatalf("version fixture not selected: got %q, %v; want %q", resolved, err, goCommand)
	}
	auto := exec.Command("go", "env", "GOVERSION")
	if output, err := auto.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "go1.27.1" {
		t.Fatalf("fixture did not expose auto-switching: %q, %v", output, err)
	}
	version, err := readDiscoveryGoVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != "go1.27.0" {
		t.Fatalf("local child Go version = %q, want go1.27.0", version)
	}
}

func TestDiscoveryProvenanceAcceptsEquivalentPRMergeTree(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "records.jsonl")
	writeTestFile(t, ledger, "{}\n")
	provenance := fixtureDiscoveryProvenance(t, ledger)
	branchSource := provenance.Source
	provenance.Source.Revision = strings.Repeat("c", 40)
	provenance.TranslatorRevision = provenance.Source.Revision
	if err := validateDiscoveryProvenance(provenance, branchSource, provenance.LedgerSHA256); err != nil {
		t.Fatalf("identical source tree with PR merge revision was rejected: %v", err)
	}
	provenance.Source.SHA256 = strings.Repeat("d", 64)
	if err := validateDiscoveryProvenance(provenance, branchSource, provenance.LedgerSHA256); err == nil {
		t.Fatal("different source tree accepted")
	}
}

func TestVerifyDiscoveryCorpusReportsRejectsMixedOrStaleProvenance(t *testing.T) {
	for name, mutate := range map[string]func(*discoveryCorpusProvenance){
		"source revision": func(p *discoveryCorpusProvenance) {
			p.Source.Revision = strings.Repeat("d", 40)
			p.TranslatorRevision = p.Source.Revision
		},
		"source contents":     func(p *discoveryCorpusProvenance) { p.Source.SHA256 = strings.Repeat("d", 64) },
		"ledger":              func(p *discoveryCorpusProvenance) { p.LedgerSHA256 = strings.Repeat("d", 64) },
		"translator bytes":    func(p *discoveryCorpusProvenance) { p.TranslatorSHA256 = strings.Repeat("d", 64) },
		"translator revision": func(p *discoveryCorpusProvenance) { p.TranslatorRevision = strings.Repeat("d", 40) },
		"toolchain":           func(p *discoveryCorpusProvenance) { p.GoVersion = "go1.27.2"; p.TranslatorGo = p.GoVersion },
		"old Go":              func(p *discoveryCorpusProvenance) { p.GoVersion = "go1.26.1"; p.TranslatorGo = p.GoVersion },
		"compiler build Go":   func(p *discoveryCorpusProvenance) { p.TranslatorGo = "go1.27.2" },
		"LLVM patch":          func(p *discoveryCorpusProvenance) { p.LLVMVersion = "22.1.9" },
		"LLVM driver bytes":   func(p *discoveryCorpusProvenance) { p.LLCBinarySHA256 = strings.Repeat("e", 64) },
		"LLVM fallback":       func(p *discoveryCorpusProvenance) { p.LLVMVersion = "23.1.0" },
		"dirty source":        func(p *discoveryCorpusProvenance) { p.Source.Dirty = true },
		"dirty translator":    func(p *discoveryCorpusProvenance) { p.TranslatorModified = true },
		"changed during run":  func(p *discoveryCorpusProvenance) { p.Invalidated = "inputs changed" },
	} {
		t.Run(name, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			path := filepath.Join(reports, "shard-1.json")
			report, err := readDiscoveryCorpusReport(path)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&report.Provenance)
			if err := writeDiscoveryCorpusReport(path, report); err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil || !strings.Contains(err.Error(), "provenance") {
				t.Fatalf("accepted %s: %v", name, err)
			}
		})
	}
}

func TestDiscoveryFingerprintsBindContentsNotAbsolutePaths(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, root := range []string{first, second} {
		writeTestFile(t, filepath.Join(root, "a.go"), "package test\n")
		writeTestFile(t, filepath.Join(root, "b.go"), "package test\n// b\n")
	}
	a, err := discoveryFilesFingerprint(first, []string{"b.go", "a.go", "a.go"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := discoveryFilesFingerprint(second, []string{"a.go", "b.go"})
	if err != nil || a != b {
		t.Fatalf("path/order/duplicate-dependent fingerprint: %s %s %v", a, b, err)
	}
	writeTestFile(t, filepath.Join(second, "b.go"), "package test\n// c\n")
	b, err = discoveryFilesFingerprint(second, []string{"a.go", "b.go"})
	if err != nil || a == b {
		t.Fatalf("same-size edit not detected: %s %s %v", a, b, err)
	}
	writeTestFile(t, filepath.Join(first, "manifest.json"), "{\"index_entries\":1}\n")
	if err := os.Mkdir(filepath.Join(first, "records"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(first, "records", "00.jsonl"), "{}\n")
	a, err = discoveryLedgerFingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(first, "manifest.json"), "{\"index_entries\":2}\n")
	b, err = discoveryLedgerFingerprint(first)
	if err != nil || a == b {
		t.Fatalf("cursor manifest change not detected: %v", err)
	}
}

func TestDiscoverySourceIdentityIncludesDirtyAndUntrackedInputs(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, output)
		}
	}
	git("init", "-q")
	writeTestFile(t, filepath.Join(root, "source.go"), "package fixture\n")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "_out/\n")
	evidenceDir := filepath.Join(root, "testdata", "discovery", "assembly-ledger")
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatal(err)
	}
	evidenceManifest := filepath.Join(evidenceDir, "manifest.json")
	writeTestFile(t, evidenceManifest, "{\"passed\":0}\n")
	git("add", ".")
	git("commit", "-qm", "fixture")
	before, err := collectDiscoverySource(root)
	if err != nil || before.Dirty || !discoverySHA256Pattern.MatchString(before.SHA256) {
		t.Fatalf("clean identity: %+v %v", before, err)
	}
	if err := os.Mkdir(filepath.Join(root, "_out"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "_out", "report.json"), "{}\n")
	after, err := collectDiscoverySource(root)
	if err != nil || before != after {
		t.Fatalf("ignored output changed source identity: %+v %v", after, err)
	}
	writeTestFile(t, evidenceManifest, "{\"passed\":1}\n")
	writeTestFile(t, filepath.Join(evidenceDir, "new.jsonl"), "{\"status\":\"passed\"}\n")
	after, err = collectDiscoverySource(root)
	if err != nil || before != after {
		t.Fatalf("assembly evidence changed source identity: %+v %v", after, err)
	}
	writeTestFile(t, filepath.Join(root, "new.go"), "package fixture\n")
	after, err = collectDiscoverySource(root)
	if err != nil || !after.Dirty || after.SHA256 == before.SHA256 {
		t.Fatalf("untracked source ignored: %+v %v", after, err)
	}
	if err := os.Remove(filepath.Join(root, "new.go")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "source.go"), "package changed\n")
	after, err = collectDiscoverySource(root)
	if err != nil || !after.Dirty || after.SHA256 == before.SHA256 {
		t.Fatalf("dirty source ignored: %+v %v", after, err)
	}
	git("add", "source.go")
	git("commit", "-qm", "update")
	final, err := collectDiscoverySource(root)
	if err != nil || final.Dirty || final.SHA256 != after.SHA256 || final.Revision == before.Revision {
		t.Fatalf("new commit identity: %+v %v", final, err)
	}
}

func TestDiscoveryCorpusRetainsInvalidatedRunEvidence(t *testing.T) {
	root := t.TempDir()
	ledger := filepath.Join(root, "ledger.jsonl")
	writeTestFile(t, ledger, "{\"kind\":\"scanned\",\"module\":\"example.com/noasm\",\"version\":\"v1.0.0\"}\n")
	for _, captureFailure := range []bool{false, true} {
		calls := 0
		reportPath := filepath.Join(root, fmt.Sprintf("report-%v.json", captureFailure))
		err := runDiscoveryCorpus(discoveryCorpusConfig{LedgerPath: ledger, ShardCount: 1, CandidateTimeout: time.Minute, ReportPath: reportPath,
			captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
				calls++
				p := fixtureDiscoveryProvenance(t, ledger)
				if calls == 2 {
					if captureFailure {
						return p, fmt.Errorf("tool removed")
					}
					p.Source.SHA256 = strings.Repeat("d", 64)
				}
				return p, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "invalidated") {
			t.Fatalf("changed run succeeded: %v", err)
		}
		report, err := readDiscoveryCorpusReport(reportPath)
		if err != nil || report.Provenance.Invalidated == "" {
			t.Fatalf("lost invalidation evidence: %+v %v", report, err)
		}
	}
}

func TestDiscoveryBinaryFingerprintIgnoresFilename(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("binary fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := discoveryBinaryFingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := discoveryBinaryFingerprint(second)
	if err != nil || a != b {
		t.Fatalf("binary filename influenced digest: %v", err)
	}
}

func TestDiscoveryCorpusPinsRelativeToolPathsBeforeCandidateChdir(t *testing.T) {
	root := t.TempDir()
	ledger := filepath.Join(root, "ledger.jsonl")
	writeTestFile(t, ledger, "{\"kind\":\"scanned\",\"module\":\"example.com/noasm\",\"version\":\"v1.0.0\"}\n")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join("tools", "translator")
	llc := filepath.Join("tools", "llc-22")
	calls := 0
	err = runDiscoveryCorpus(discoveryCorpusConfig{
		RepoRoot: ".", Translator: translator, LLC: llc,
		LedgerPath: ledger, ReportPath: filepath.Join(root, "report.json"),
		ShardCount: 1, CandidateTimeout: time.Minute,
		captureProvenance: func(cfg discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			calls++
			if cfg.RepoRoot != cwd || cfg.Translator != filepath.Join(cwd, translator) || cfg.LLC != filepath.Join(cwd, llc) {
				return discoveryCorpusProvenance{}, fmt.Errorf("relative paths would break after candidate chdir: root=%q translator=%q llc=%q", cfg.RepoRoot, cfg.Translator, cfg.LLC)
			}
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
	})
	if err != nil || calls != 2 {
		t.Fatalf("pinned-path run: captures=%d err=%v", calls, err)
	}
}

func TestResolveDiscoveryExecutable(t *testing.T) {
	want, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	want, err = filepath.Abs(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveDiscoveryExecutable("go")
	if err != nil || got != want {
		t.Fatalf("PATH executable=%q, want %q: %v", got, want, err)
	}
	got, err = resolveDiscoveryExecutable(want)
	if err != nil || got != want {
		t.Fatalf("absolute executable=%q, want %q: %v", got, want, err)
	}
	if _, err := resolveDiscoveryExecutable("plan9asm-deliberately-nonexistent-tool-8bfc7c4"); err == nil {
		t.Fatal("missing PATH executable accepted")
	}
}
