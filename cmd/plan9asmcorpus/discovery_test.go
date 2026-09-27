package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryCandidateRemovesWorkspaceAfterDownloadFailure(t *testing.T) {
	shared := t.TempDir()
	marker := filepath.Join(shared, "user-owned.txt")
	writeTestFile(t, marker, "keep shared cache untouched")
	t.Setenv("GOMODCACHE", shared)
	t.Setenv("GOPROXY", "off")
	work := filepath.Join(t.TempDir(), "candidate")
	_, _, _, err := runDiscoveryCandidate(discoveryCorpusConfig{CandidateTimeout: 15 * time.Second}, discoveryCandidate{Module: "example.invalid/plan9asm-cleanup-test", Version: "v1.0.0"}, work)
	if err == nil {
		t.Fatal("offline nonexistent module unexpectedly succeeded")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("finished candidate left its workspace: %v", err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "keep shared cache untouched" {
		t.Fatalf("shared cache changed: %q %v", contents, err)
	}
}

func TestInvalidMachineCodeSkipRequiresPinnedSourceAndDecoderRejection(t *testing.T) {
	moduleDir := t.TempDir()
	const asmFile = "pkg/raw_arm64.s"
	const source = "TEXT ·Bad(SB), $0-0\nWORD $0x09c961ce\n"
	if err := os.MkdirAll(filepath.Join(moduleDir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(moduleDir, asmFile), source)
	checksum := sha256.Sum256([]byte(source))
	candidate := discoveryCandidate{
		Module: "example.com/raw", Version: "v1.0.0",
		AsmFiles: []string{asmFile},
	}
	skip := discoveryInvalidMachineCodeSkip{
		Module: candidate.Module, Version: candidate.Version,
		Reason: "raw SM4EKEY word has an invalid ARM64 encoding",
		Evidence: []discoveryInvalidMachineCodeEvidence{{
			AsmFile: asmFile, SHA256: fmt.Sprintf("%x", checksum),
			SourceExpression: "WORD $0x09c961ce", Word: "0x09c961ce",
			Architecture: "arm64",
		}},
	}
	reject := func(arch string, word uint32) error {
		if arch != "arm64" || word != 0x09c961ce {
			return fmt.Errorf("unexpected decode request %s %#x", arch, word)
		}
		return nil
	}
	if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, skip, reject); err != nil {
		t.Fatalf("valid skip rejected: %v", err)
	}
	for _, change := range []struct {
		name string
		edit func(*discoveryInvalidMachineCodeSkip)
	}{
		{"wrong version", func(s *discoveryInvalidMachineCodeSkip) { s.Version = "v1.0.1" }},
		{"wrong checksum", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].SHA256 = strings.Repeat("0", 64) }},
		{"absent expression", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].SourceExpression = "WORD $0x00000000" }},
		{"unlisted file", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].AsmFile = "pkg/other_arm64.s" }},
		{"missing reason", func(s *discoveryInvalidMachineCodeSkip) { s.Reason = "" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := skip
			changed.Evidence = append([]discoveryInvalidMachineCodeEvidence(nil), skip.Evidence...)
			change.edit(&changed)
			if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, changed, reject); err == nil {
				t.Fatal("invalid skip was accepted")
			}
		})
	}
	if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, skip, func(string, uint32) error {
		return errors.New("decodes as a valid instruction")
	}); err == nil {
		t.Fatal("decodable word was skipped")
	}
}

func TestInvalidSourceSkipRejectsMissingAMD64RawRIPConstant(t *testing.T) {
	moduleDir := t.TempDir()
	const asmFile = "pkg/raw_amd64.s"
	const source = "DATA CPI0_0<>+0(SB)/4, $1\n" +
		"GLOBL CPI0_0<>(SB), RODATA, $4\n" +
		"TEXT ·Bad(SB), $0-0\n" +
		"QUAD $0x00001592256ffdc5 // vmovdqa LCPI0_4(%rip), %ymm4\n"
	if err := os.MkdirAll(filepath.Join(moduleDir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(moduleDir, asmFile), source)
	checksum := sha256.Sum256([]byte(source))
	candidate := discoveryCandidate{
		Module: "example.com/raw", Version: "v1.0.0",
		AsmFiles: []string{asmFile},
	}
	skip := discoveryInvalidMachineCodeSkip{
		Module: candidate.Module, Version: candidate.Version,
		Reason: "raw RIP reference has no corresponding constant",
		Evidence: []discoveryInvalidMachineCodeEvidence{{
			Kind:    "amd64_missing_rip_constant",
			AsmFile: asmFile, SHA256: fmt.Sprintf("%x", checksum),
			SourceExpression: "QUAD $0x00001592256ffdc5 // vmovdqa LCPI0_4(%rip), %ymm4",
			MissingSymbol:    "CPI0_4", Architecture: "amd64",
		}},
	}
	if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, skip, nil); err != nil {
		t.Fatalf("missing raw RIP constant was not proved: %v", err)
	}
	declaredSource := "DATA CPI0_4<>+0(SB)/4, $1\n" + source
	writeTestFile(t, filepath.Join(moduleDir, asmFile), declaredSource)
	declared := skip
	declared.Evidence = append([]discoveryInvalidMachineCodeEvidence(nil), skip.Evidence...)
	declaredChecksum := sha256.Sum256([]byte(declaredSource))
	declared.Evidence[0].SHA256 = fmt.Sprintf("%x", declaredChecksum)
	if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, declared, nil); err == nil {
		t.Fatal("declared constant was misclassified as absent")
	}
	writeTestFile(t, filepath.Join(moduleDir, asmFile), source)
	for _, change := range []struct {
		name string
		edit func(*discoveryInvalidMachineCodeSkip)
	}{
		{"wrong checksum", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].SHA256 = strings.Repeat("0", 64) }},
		{"wrong constant", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].MissingSymbol = "CPI0_0" }},
		{"wrong expression", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].SourceExpression = "QUAD $0x0000000000000000" }},
		{"wrong architecture", func(s *discoveryInvalidMachineCodeSkip) { s.Evidence[0].Architecture = "arm64" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := skip
			changed.Evidence = append([]discoveryInvalidMachineCodeEvidence(nil), skip.Evidence...)
			change.edit(&changed)
			if err := verifyInvalidMachineCodeSkip(moduleDir, candidate, changed, nil); err == nil {
				t.Fatal("unproved raw RIP constant was skipped")
			}
		})
	}
}

func TestAMD64MissingRIPConstantRequiresGoObjectOutsideText(t *testing.T) {
	moduleDir := t.TempDir()
	workDir := t.TempDir()
	const asmFile = "raw_amd64.s"
	for _, tc := range []struct {
		name      string
		quad      string
		wantError bool
	}{
		{name: "outside all text", quad: "0x00001592256ffdc5"},
		{name: "inside text", quad: "0x00000000256ffdc5", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expression := "QUAD $" + tc.quad + " // vmovdqa LCPI0_4(%rip), %ymm4"
			writeTestFile(t, filepath.Join(moduleDir, asmFile),
				"#include \"textflag.h\"\nTEXT ·Bad(SB), NOSPLIT, $0-0\n"+
					expression+"\nRET\n")
			item := discoveryInvalidMachineCodeEvidence{
				Kind: "amd64_missing_rip_constant", AsmFile: asmFile,
				SourceExpression: expression, MissingSymbol: "CPI0_4",
				Architecture: "amd64",
			}
			err := verifyAMD64MissingRIPConstantObject(context.Background(), moduleDir, workDir, item)
			if (err != nil) != tc.wantError {
				t.Fatalf("Go object proof error = %v, wantError = %t", err, tc.wantError)
			}
		})
	}
}

func TestDiscoveryCorpusAccountsForInvalidMachineCodeSkipSeparately(t *testing.T) {
	report := discoveryCorpusReport{
		Selected: 1, SkippedInvalidSource: 1,
		Results: []discoveryCorpusResult{{
			Module: "example.com/raw", Version: "v1.0.0",
			Status:              discoveryStatusSkippedInvalidSource,
			InvalidSourceReason: "verified invalid ARM64 word",
			InvalidSourceEvidence: []discoveryInvalidMachineCodeEvidence{{
				AsmFile: "pkg/raw_arm64.s", SHA256: strings.Repeat("a", 64),
				SourceExpression: "WORD $0x09c961ce", Word: "0x09c961ce",
				Architecture: "arm64",
			}},
			DiscoveredAsmFiles: []string{"pkg/raw_arm64.s"},
		}},
	}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	report.Results[0].Translations = 1
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("skipped source counted as a translation")
	}
}

func TestDiscoveryCorpusAccountsForMissingAMD64RIPConstantSkip(t *testing.T) {
	evidence := discoveryInvalidMachineCodeEvidence{
		Kind: "amd64_missing_rip_constant", AsmFile: "pkg/raw_amd64.s",
		SHA256:           strings.Repeat("a", 64),
		SourceExpression: "QUAD $0x00001592256ffdc5 // vmovdqa LCPI0_4(%rip), %ymm4",
		Architecture:     "amd64", MissingSymbol: "CPI0_4",
	}
	report := discoveryCorpusReport{
		Selected: 1, SkippedInvalidSource: 1,
		Results: []discoveryCorpusResult{{
			Module: "example.com/raw", Version: "v1.0.0",
			Status:                discoveryStatusSkippedInvalidSource,
			InvalidSourceReason:   "Go object lacks the referenced constant",
			InvalidSourceEvidence: []discoveryInvalidMachineCodeEvidence{evidence},
			DiscoveredAsmFiles:    []string{evidence.AsmFile},
		}},
	}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	report.Results[0].InvalidSourceEvidence[0].MissingSymbol = "CPI0_0"
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("unrelated constant name was accepted as evidence")
	}
}

func TestInvalidMachineCodeManifestExpressionsEmitClaimedWords(t *testing.T) {
	skips, err := loadInvalidMachineCodeSkips(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(skips) != 6 {
		t.Fatalf("got %d independently reviewed exact-version skips, want 6", len(skips))
	}
	if _, ok := skips["github.com/janpfeifer/go-highway@v0.0.0-dev9"]; !ok {
		t.Fatal("missing independently reviewed go-highway dev9 source evidence")
	}
	for key, skip := range skips {
		for _, item := range skip.Evidence {
			if item.Kind == "amd64_missing_rip_constant" {
				if err := verifyAMD64MissingRIPConstant(item, nil); err != nil {
					t.Fatalf("%s %s: %v", key, item.AsmFile, err)
				}
				continue
			}
			word, err := strconv.ParseUint(item.Word, 0, 32)
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			emitted, err := rawWordFromEvidence(item)
			if err != nil || emitted != uint32(word) {
				t.Fatalf("%s %s: emitted %#x, claimed %#x: %v", key, item.AsmFile, emitted, word, err)
			}
		}
	}
}

func TestDiscoveryCandidateRejectsPreexistingWorkspace(t *testing.T) {
	work := t.TempDir()
	marker := filepath.Join(work, "keep.txt")
	writeTestFile(t, marker, "user data")
	_, _, _, err := runDiscoveryCandidate(discoveryCorpusConfig{}, discoveryCandidate{}, work)
	if err == nil {
		t.Fatal("accepted a preexisting workspace")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("removed preexisting workspace: %v", err)
	}
}

func TestDiscoveryCandidateTimeoutIsFreshForEachConfiguration(t *testing.T) {
	const timeout = 80 * time.Millisecond
	for configuration := 0; configuration < 3; configuration++ {
		err := runDiscoveryOperation(timeout, func(ctx context.Context) error {
			select {
			case <-time.After(50 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err != nil {
			t.Fatalf("configuration %d inherited an earlier deadline: %v", configuration, err)
		}
	}
}

func TestDiscoveryTranslationUnitsKeepPackagesSeparate(t *testing.T) {
	groups := []discoveryPackageGroup{
		{Pattern: "example.com/large/p0", AsmFiles: []string{"p0/first_amd64.s", "p0/second_amd64.s"}},
		{Pattern: "example.com/large/p1", AsmFiles: []string{"p1/first_amd64.s"}},
	}
	units := discoveryTranslationUnits(groups)
	if len(units) != 2 ||
		!reflect.DeepEqual(units[0].Patterns, []string{"example.com/large/p0"}) ||
		!reflect.DeepEqual(units[0].AsmFiles, groups[0].AsmFiles) ||
		!reflect.DeepEqual(units[1].Patterns, []string{"example.com/large/p1"}) ||
		!reflect.DeepEqual(units[1].AsmFiles, groups[1].AsmFiles) {
		t.Fatalf("translation units did not isolate package resources: %+v", units)
	}
	all := []string{"p0/first_amd64.s", "p0/second_amd64.s", "p1/first_amd64.s"}
	if err := validateDiscoveryTranslationUnits(units, all); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryTranslationUnits(units[:1], all); err == nil {
		t.Fatal("missing package unit silently dropped assembly")
	}
	duplicated := append(append([]discoveryTranslationUnit(nil), units...), units[0])
	if err := validateDiscoveryTranslationUnits(duplicated, all); err == nil {
		t.Fatal("duplicate package unit silently inflated translations")
	}
}

func TestDiscoveryOperationReportsItsOwnTimeout(t *testing.T) {
	err := runDiscoveryOperation(10*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runDiscoveryOperation() error = %v, want deadline exceeded", err)
	}
}

func TestDiscoveryCandidateModuleCacheIsPrivateWithReadOnlySharedProxy(t *testing.T) {
	work := filepath.Join(t.TempDir(), "candidate")
	shared := filepath.Join(t.TempDir(), "shared cache")
	env := isolatedDiscoveryModuleEnvironment([]string{"KEEP=yes", "GOMODCACHE=wrong", "GOPROXY=wrong"}, work, shared, "https://proxy.golang.org,direct")
	values := map[string]string{}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	if values["GOMODCACHE"] != filepath.Join(work, "module-cache") {
		t.Fatalf("shared writable cache: %v", env)
	}
	if values["GOCACHE"] != filepath.Join(work, "build-cache") || values["GOCACHEPROG"] != "" {
		t.Fatalf("shared writable build cache: %v", env)
	}
	for _, key := range []string{"GOTMPDIR", "TMPDIR", "TMP", "TEMP"} {
		if values[key] != filepath.Join(work, "tmp") {
			t.Fatalf("%s is outside owned workspace: %v", key, env)
		}
	}
	if !strings.HasPrefix(values["GOPROXY"], "file:///") || !strings.Contains(values["GOPROXY"], "shared%20cache/cache/download,https://proxy.golang.org,direct") {
		t.Fatalf("bad read-through proxy: %s", values["GOPROXY"])
	}
	if values["GOFLAGS"] != "-mod=mod -modcacherw" || values["KEEP"] != "yes" {
		t.Fatalf("bad environment: %v", env)
	}
}

func TestDiscoveryCandidateCleanupRemovesReadOnlyModuleDirectories(t *testing.T) {
	work := filepath.Join(t.TempDir(), "candidate")
	module := filepath.Join(work, "module-cache", "example.com", "lib@v1.0.0")
	if err := os.MkdirAll(module, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(module, "x.go"), "package lib\n")
	if err := os.Chmod(module, 0555); err != nil {
		t.Fatal(err)
	}
	if err := removeDiscoveryCandidateWorkspace(work); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("workspace retained: %v", err)
	}
}

func TestDiscoveryTargetOutputCleanupKeepsOtherConfigurations(t *testing.T) {
	work := t.TempDir()
	first := filepath.Join(work, "out", "config-0000")
	second := filepath.Join(work, "out", "config-0001")
	for _, dir := range []string{first, second} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(first, "large.ll"), "generated IR")
	writeTestFile(t, filepath.Join(second, "large.o"), "generated object")
	writeTestFile(t, filepath.Join(work, "matrix-report-0000.json"), "report evidence")
	if err := removeDiscoveryTargetOutput(work, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("finished target output remains: %v", err)
	}
	for _, path := range []string{filepath.Join(second, "large.o"), filepath.Join(work, "matrix-report-0000.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("cleanup removed other configuration or report %s: %v", path, err)
		}
	}
}

func TestDiscoveryShardRemovesWorkspaceAndKeepsFailureReport(t *testing.T) {
	root := t.TempDir()
	temporary := filepath.Join(root, "temporary")
	if err := os.Mkdir(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, temporary)
	}
	t.Setenv("GOMODCACHE", filepath.Join(root, "shared-cache"))
	t.Setenv("GOPROXY", "off")
	ledger := filepath.Join(root, "records.jsonl")
	writeTestFile(t, ledger, `{"kind":"matched","module":"example.invalid/plan9asm-cleanup-test","version":"v1.0.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}`+"\n")
	reportPath := filepath.Join(root, "report.json")
	err := runDiscoveryCorpus(discoveryCorpusConfig{
		LedgerPath: ledger, ShardCount: 1, CandidateTimeout: 15 * time.Second,
		Targets: []string{"linux/amd64"}, ReportPath: reportPath,
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
	})
	if err == nil {
		t.Fatal("offline nonexistent module unexpectedly succeeded")
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("shard left temporary workspaces: %v, %v", entries, err)
	}
	report, err := readDiscoveryCorpusReport(reportPath)
	if err != nil || report.Failed != 1 || len(report.Results) != 1 || report.Results[0].Error == "" {
		t.Fatalf("lost failure evidence: %+v, %v", report, err)
	}
}

func TestDiscoveryShardKeepsCallerOwnedBuildCache(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "shared-build-cache")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(root, "records.jsonl")
	writeTestFile(t, ledger, `{"kind":"matched","module":"example.com/shared-cache","version":"v1.0.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}`+"\n")

	err := runDiscoveryCorpus(discoveryCorpusConfig{
		LedgerPath: ledger, ShardCount: 1, CandidateTimeout: time.Minute,
		Targets: []string{"linux/amd64"}, buildCache: cache,
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
		runCandidate: func(cfg discoveryCorpusConfig, _ discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			if cfg.buildCache != cache {
				t.Errorf("build cache = %q, want %q", cfg.buildCache, cache)
			}
			writeTestFile(t, filepath.Join(cache, "marker"), "reusable build cache")
			return matrixReport{Success: 1, TotalTargets: 1}, nil,
				[]discoveryBuildConfiguration{{AsmFiles: []string{"f_amd64.s"}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, "marker")); err != nil {
		t.Fatalf("caller-owned build cache was removed: %v", err)
	}
}

func TestDiscoveryShardRejectsInvalidCallerBuildCache(t *testing.T) {
	root := t.TempDir()
	ledger := filepath.Join(root, "records.jsonl")
	writeTestFile(t, ledger, `{"kind":"matched","module":"example.com/shared-cache","version":"v1.0.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}`+"\n")
	regularFile := filepath.Join(root, "not-a-directory")
	writeTestFile(t, regularFile, "not a cache")

	for _, test := range []struct {
		name  string
		cache string
		want  string
	}{
		{name: "relative", cache: "relative-cache", want: "absolute path"},
		{name: "missing", cache: filepath.Join(root, "missing"), want: "stat discovery build cache"},
		{name: "regular file", cache: regularFile, want: "not a directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := runDiscoveryCorpus(discoveryCorpusConfig{
				LedgerPath: ledger, ShardCount: 1, CandidateTimeout: time.Minute,
				Targets: []string{"linux/amd64"}, buildCache: test.cache,
				captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
					return fixtureDiscoveryProvenance(t, ledger), nil
				},
				runCandidate: func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
					t.Fatal("candidate ran with an invalid build cache")
					return matrixReport{}, nil, nil, nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDiscoveryShardPublishesAuditableCheckpoints(t *testing.T) {
	root := t.TempDir()
	ledger := filepath.Join(root, "records.jsonl")
	var records strings.Builder
	for index := 0; index < 9; index++ {
		fmt.Fprintf(&records, `{"kind":"matched","module":"example.com/checkpoint/%02d","version":"v1.0.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}`+"\n", index)
	}
	writeTestFile(t, ledger, records.String())
	reportPath := filepath.Join(root, "shard-0.json")
	calls := 0
	err := runDiscoveryCorpus(discoveryCorpusConfig{
		LedgerPath: ledger, RepoRoot: ".", ShardCount: 1,
		CandidateTimeout: time.Minute, Targets: []string{"linux/amd64"}, ReportPath: reportPath,
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
		runCandidate: func(_ discoveryCorpusConfig, _ discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			if calls == 0 || calls == 8 {
				report, err := readDiscoveryCorpusReport(reportPath)
				if err != nil {
					t.Fatal(err)
				}
				if !report.Partial || report.Selected != calls || report.Passed != calls {
					t.Fatalf("checkpoint at candidate %d = %+v", calls, report)
				}
			}
			calls++
			return matrixReport{Success: 1, TotalTargets: 1}, nil,
				[]discoveryBuildConfiguration{{AsmFiles: []string{"f_amd64.s"}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	final, err := readDiscoveryCorpusReport(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 9 || final.Partial || final.Selected != 9 || final.Passed != 9 {
		t.Fatalf("final shard report = %+v; calls=%d", final, calls)
	}
}

func TestResolveModuleDownloadUsesCachedZipAfterToolchainVersionRejection(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "module.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(zipFile)
	for name, contents := range map[string]string{
		"example.com/Upper/Lib@v1.0.0/go.mod":      "module example.com/Upper/Lib\n\ngo 1.27.1\n",
		"example.com/Upper/Lib@v1.0.0/asm_amd64.s": "TEXT ·f(SB),NOSPLIT,$0-0\nRET\n",
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipFile.Close(); err != nil {
		t.Fatal(err)
	}
	downloadJSON, err := json.Marshal(moduleDownloadInfo{
		Path:    "example.com/Upper/Lib",
		Version: "v1.0.0",
		GoMod:   filepath.Join(root, "cache.mod"),
		Zip:     zipPath,
		Error:   "example.com/lib@v1.0.0 requires go >= 1.27.1 (running go 1.27.0; GOTOOLCHAIN=local)",
	})
	if err != nil {
		t.Fatal(err)
	}
	download, err := resolveModuleDownload(downloadJSON, errors.New("exit status 1"), filepath.Join(root, "work"))
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(download.Dir, "asm_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "TEXT ·f") {
		t.Fatalf("extracted assembly = %q", contents)
	}
}

func TestRunDiscoveryAsmDeclUsesCurrentGoTargetABI(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/asmdecl\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package asmdecl\n\nfunc f(x int64)\n")
	asm := filepath.Join(dir, "decl_amd64.s")
	writeTestFile(t, asm, "TEXT ·f(SB), $0-1\nRET\n")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	if err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/asmdecl"}); err == nil {
		t.Fatal("runDiscoveryAsmDecl() succeeded for a wrong TEXT argument size")
	}
	writeTestFile(t, asm, "TEXT ·f(SB), $0-8\nRET\n")
	if err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/asmdecl"}); err != nil {
		t.Fatalf("runDiscoveryAsmDecl() valid source error = %v", err)
	}
}

func TestRunDiscoveryAsmDeclStillFindsABIMismatchWhenTestsDoNotCompile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "work")
	dependency := filepath.Join(root, "dependency")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dependency, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module plan9asm.local/probe\n\ngo 1.20\n\nrequire example.com/asmdeclbroken v0.0.0\nreplace example.com/asmdeclbroken => ../dependency\n")
	writeTestFile(t, filepath.Join(dependency, "go.mod"), "module example.com/asmdeclbroken\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dependency, "decl.go"), "package asmdeclbroken\n\nfunc f() uint32\n")
	writeTestFile(t, filepath.Join(dependency, "decl_386.s"), "TEXT ·f(SB), $0-4\nMOVL AX, ret+4(FP)\nRET\n")
	writeTestFile(t, filepath.Join(dependency, "decl_test.go"), "package asmdeclbroken\n\nvar _ uint32 = int64(1)\n")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/386", nil, []string{"example.com/asmdeclbroken"})
	if err == nil || !isDiscoveryAsmDeclABIMismatch(err.Error()) {
		t.Fatalf("runDiscoveryAsmDecl() error = %v, want assembly ABI mismatch despite broken tests", err)
	}
}

func TestRunDiscoveryAsmDeclPropagatesExpiredContext(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/asmdecltimeout\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package asmdecltimeout\n\nfunc f()\n")
	writeTestFile(t, filepath.Join(dir, "decl_386.s"), "TEXT ·f(SB), $0-0\nRET\n")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runDiscoveryAsmDecl(ctx, dir, env, "linux/386", nil, []string{"example.com/asmdecltimeout"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runDiscoveryAsmDecl() error = %v, want context.Canceled", err)
	}
}

func TestRunDiscoveryGoBuildChecksExactCurrentPackage(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/buildable\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package buildable\n\nfunc f()\n")
	writeTestFile(t, filepath.Join(dir, "decl_amd64.s"), "TEXT ·f(SB), $0-0\nRET\n")
	env := replaceEnv(os.Environ(), map[string]string{"GOFLAGS": "-mod=mod", "GOWORK": "off"})
	if err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/amd64", nil, "example.com/buildable"); err != nil {
		t.Fatalf("runDiscoveryGoBuild() valid package error = %v", err)
	}
	writeTestFile(t, filepath.Join(dir, "decl.go"), "package buildable\n\nvar broken = missingIdentifier\n")
	if err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/amd64", nil, "example.com/buildable"); err == nil {
		t.Fatal("runDiscoveryGoBuild() accepted source rejected by the current Go compiler")
	}
}

func TestDiscoveryGoBuildInfrastructureFailuresAreNotSourceNotApplicable(t *testing.T) {
	for _, diagnostic := range []string{
		"go build example.com/pkg: context deadline exceeded",
		"go build example.com/pkg: captured output exceeds 8388608 bytes",
		"dial tcp: lookup proxy.golang.org: no such host",
		"Get https://proxy.golang.org: net/http: TLS handshake timeout",
		"git ls-remote https://github.com/example/repo: Connection closed by 192.0.2.10 port 22",
		"fatal: Could not read from remote repository.",
		"write /tmp/go-build/object.o: no space left on device",
		"go build example.com/pkg: signal: killed",
		"compile: version \"go1.27.1\" does not match go tool version \"go1.27.0\"",
		"reading https://gvisor.googlesource.com/gvisor/pkg/abi/linux?go-get=1: 429 Too Many Requests",
	} {
		if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
			t.Fatalf("infrastructure diagnostic was classified as source incompatibility: %q", diagnostic)
		}
	}
	for _, diagnostic := range []string{
		"pkg/file.go:12:2: undefined: removedSymbol",
		"use of internal package runtime/internal/sys not allowed",
		"package example.com/old imports C: build constraints exclude all Go files",
		"pkg/goid_386.s:13: unexpected EOF\nasm: assembly of pkg/goid_386.s failed",
	} {
		if isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
			t.Fatalf("source diagnostic was classified as infrastructure failure: %q", diagnostic)
		}
	}
}

func TestRetryDiscoveryGoBuildOnlyRetriesTransientNetworkFailures(t *testing.T) {
	transient := errors.New("reading https://example.com/pkg?go-get=1: 503 Service Unavailable")
	source := errors.New("pkg/file.go:12:2: undefined: removedSymbol")

	attempts := 0
	err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		if attempts < 3 {
			return transient
		}
		return source
	})
	if !errors.Is(err, source) || attempts != 3 {
		t.Fatalf("retry after network failure: attempts=%d error=%v", attempts, err)
	}

	attempts = 0
	err = retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return source
	})
	if !errors.Is(err, source) || attempts != 1 {
		t.Fatalf("source failure was retried: attempts=%d error=%v", attempts, err)
	}

	attempts = 0
	err = retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return errors.New("go build: signal: killed")
	})
	if err == nil || attempts != 1 {
		t.Fatalf("resource failure was retried: attempts=%d error=%v", attempts, err)
	}
}

func TestDiscoveryAsmDeclOnlyClassifiesConcreteABIMismatches(t *testing.T) {
	for _, diagnostic := range []string{
		"file.s:1: [386] f: wrong argument size 0; expected $...-12",
		"file.s:2: [386] f: invalid offset ret+4(FP); expected ret+8(FP)",
		"file.s:3: [386] f: invalid MOVL of x+0(FP); uint64 is 8-byte value",
	} {
		if !isDiscoveryAsmDeclABIMismatch(diagnostic) {
			t.Fatalf("concrete ABI diagnostic was not classified: %q", diagnostic)
		}
	}
	for _, diagnostic := range []string{
		"file.s:1: [arm] f: unknown variable unnamed_lo; offset 36 is ret1_lo+36(FP)",
		"file.s:1: [amd64] f+0: function f+0 missing Go declaration",
		"package dependency is missing",
	} {
		if isDiscoveryAsmDeclABIMismatch(diagnostic) {
			t.Fatalf("non-ABI diagnostic was classified as N/A: %q", diagnostic)
		}
	}
}

func TestDiscoveryConstraintTagsReadsOnlyTheSourceHeader(t *testing.T) {
	file := filepath.Join(t.TempDir(), "generated.go")
	contents := "//go:build realtag\n\npackage generated\n\nvar template = `\n//go:build invalid%template\n`\n" + strings.Repeat("x", 128<<10)
	writeTestFile(t, file, contents)
	tags, err := discoveryConstraintTags(file)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"realtag"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("constraint tags = %#v, want %#v", tags, want)
	}
}

func TestDiscoveryBuildConfigurationsRecordsDirectoryWithoutCurrentGoPackage(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "misnamed.go"), ".LCPI0_0:\n  .byte 1\n")
	writeTestFile(t, filepath.Join(dir, "routine.s"), "TEXT ·routine(SB), $0-0\nRET\n")
	candidate := discoveryCandidate{Module: "example.com/broken", Version: "v1.0.0", AsmFiles: []string{"routine.s"}}
	var evidence []discoverySourceNotApplicableItem
	configs, err := discoveryBuildConfigurationsWithEvidence(candidate, dir, []string{"linux/amd64"}, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 0 || len(evidence) != 1 || evidence[0].Kind != discoverySourceNotApplicableNoGoPackage || !strings.Contains(evidence[0].Reason, "misnamed.go") {
		t.Fatalf("configs = %#v, evidence = %#v", configs, evidence)
	}
}

func TestDiscoveryRecordsGoAcceptedAssemblyWithoutObjectSymbols(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "package.go"), "package fixture\n")
	writeTestFile(t, filepath.Join(dir, "example.s"), "LONG $0xd471c1c4; BYTE $0xc0\n")
	writeTestFile(t, filepath.Join(dir, "routine_amd64.s"), "TEXT ·routine(SB), $0-0\nRET\n")
	candidate := discoveryCandidate{
		Module: "example.com/fixture", Version: "v1.0.0",
		AsmFiles: []string{"example.s", "routine_amd64.s"},
	}
	var evidence []discoverySourceNotApplicableItem
	configs, err := discoveryBuildConfigurationsWithEvidence(candidate, dir, []string{"linux/amd64"}, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || !reflect.DeepEqual(configs[0].AsmFiles, []string{"routine_amd64.s"}) {
		t.Fatalf("configs = %#v; want only the symbol-bearing file", configs)
	}
	if len(evidence) != 1 || evidence[0].AsmFile != "example.s" ||
		evidence[0].Kind != "go_assembler_emits_no_symbols" ||
		!reflect.DeepEqual(evidence[0].Targets, []string{"linux/amd64"}) {
		t.Fatalf("source evidence = %#v; want proven no-symbol object", evidence)
	}
}

func TestDiscoverySymbolDirectiveProbeSpansReadBoundary(t *testing.T) {
	file := filepath.Join(t.TempDir(), "boundary.s")
	writeTestFile(t, file, strings.Repeat("x", 64<<10-2)+"TEXT ·routine(SB), $0-0\n")
	mentions, err := discoverySourceMentionsSymbolDirective(file)
	if err != nil {
		t.Fatal(err)
	}
	if !mentions {
		t.Fatal("missed a TEXT directive split across read chunks")
	}
}

func TestInferUnsuffixedAssemblyTargetsTreatsCurrentGoRejectedSourceAsInapplicable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fixture.s")
	writeTestFile(t, file, "this is deliberately not current Go assembly\n")
	contexts := []build.Context{build.Default, build.Default}
	contexts[0].GOOS, contexts[0].GOARCH = "linux", "amd64"
	contexts[1].GOOS, contexts[1].GOARCH = "linux", "arm64"
	eligible, restricted, reason, err := inferUnsuffixedAssemblyTargetsDetailed(file, contexts)
	if err != nil {
		t.Fatal(err)
	}
	if !restricted || len(eligible) != 0 {
		t.Fatalf("eligible = %#v, restricted = %v; want explicit empty target set", eligible, restricted)
	}
	if !strings.Contains(reason, "rejected") || !strings.Contains(reason, "linux/amd64") || !strings.Contains(reason, "linux/arm64") {
		t.Fatalf("reason = %q, want rejected targets", reason)
	}
}

func TestInferUnsuffixedAssemblyTargetsUsesEmptyGeneratedHeaderForArchitectureProbe(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x86.s")
	writeTestFile(t, file, "#include \"go_asm.h\"\nTEXT ·x(SB), $0-0\nMOVQ AX, AX\nRET\n")
	contexts := []build.Context{build.Default, build.Default}
	contexts[0].GOOS, contexts[0].GOARCH = "linux", "amd64"
	contexts[1].GOOS, contexts[1].GOARCH = "linux", "arm64"
	eligible, restricted, err := inferUnsuffixedAssemblyTargets(file, contexts)
	if err != nil {
		t.Fatal(err)
	}
	if !restricted || !eligible["linux/amd64"] || eligible["linux/arm64"] || len(eligible) != 1 {
		t.Fatalf("eligible = %#v, restricted = %v; want only linux/amd64", eligible, restricted)
	}
}

func TestMissingGoAsmHeaderRecognizesHostDiagnostics(t *testing.T) {
	for _, message := range []string{
		`fatal error: go_asm.h: No such file or directory`,
		`open go_asm.h: The system cannot find the file specified.`,
		`could not find included file "go_asm.h"`,
	} {
		if !missingGoAsmHeader(message) {
			t.Errorf("missingGoAsmHeader(%q) = false, want true", message)
		}
	}
	if missingGoAsmHeader("missing unrelated.h: no such file or directory") {
		t.Fatal("missingGoAsmHeader accepted an unrelated missing include")
	}
}

func TestLoadDiscoveryCandidatesDeduplicatesAndMergesMatchedRecords(t *testing.T) {
	dir := t.TempDir()
	records := filepath.Join(dir, "records")
	if err := os.Mkdir(records, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(records, "01.jsonl"), strings.Join([]string{
		`{"kind":"scanned","module":"example.com/noasm","version":"v1.0.0"}`,
		`{"kind":"matched","module":"example.com/asm","version":"v1.2.3","architectures":["amd64"],"asm_files":["root_amd64.s"]}`,
	}, "\n")+"\n")
	writeTestFile(t, filepath.Join(records, "02.jsonl"), strings.Join([]string{
		`{"kind":"failure","module":"example.com/fail","version":"@latest","error":"404"}`,
		`{"kind":"matched","module":"example.com/asm","version":"v1.2.3","architectures":["unknown","arm64","amd64"],"asm_files":["sub/future_riscv64.s","sub/asm_arm64.s","root_amd64.s"]}`,
	}, "\n")+"\n")
	// A previous per-run layout must not silently expand the active corpus.
	legacy := filepath.Join(dir, "runs", "old", "records")
	if err := os.MkdirAll(legacy, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(legacy, "03.jsonl"),
		`{"kind":"matched","module":"example.com/legacy","version":"v9.9.9","asm_files":["legacy_amd64.s"]}`+"\n")

	got, err := loadDiscoveryCandidates(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryCandidate{{
		Module:        "example.com/asm",
		Version:       "v1.2.3",
		Architectures: []string{"amd64", "arm64", "unknown"},
		AsmFiles:      []string{"root_amd64.s", "sub/asm_arm64.s", "sub/future_riscv64.s"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestLoadDiscoveryCandidatesRejectsUnsafeAssemblyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	writeTestFile(t, path, `{"kind":"matched","module":"example.com/asm","version":"v1.0.0","asm_files":["../escape_amd64.s"]}`+"\n")
	if _, err := loadDiscoveryCandidates(path); err == nil || !strings.Contains(err.Error(), "unsafe assembly path") {
		t.Fatalf("loadDiscoveryCandidates() error = %v, want unsafe path failure", err)
	}
}

func TestDiscoveryShardCoversEveryCandidateExactlyOnce(t *testing.T) {
	candidates := make([]discoveryCandidate, 97)
	for i := range candidates {
		candidates[i] = discoveryCandidate{Module: fmt.Sprintf("example.com/module-%03d", i), Version: "v1.0.0"}
	}
	seen := make(map[string]int, len(candidates))
	for shard := 0; shard < 13; shard++ {
		for _, candidate := range selectDiscoveryShard(candidates, shard, 13) {
			seen[candidate.exactKey()]++
		}
	}
	for _, candidate := range candidates {
		if seen[candidate.exactKey()] != 1 {
			t.Fatalf("candidate %s occurred in %d shards, want exactly one", candidate.exactKey(), seen[candidate.exactKey()])
		}
	}
}

func TestFilterDiscoveryCandidatesForTargetsUsesRecordedAssemblyPaths(t *testing.T) {
	candidates := []discoveryCandidate{
		{
			Module:   "example.com/mixed",
			Version:  "v1.0.0",
			AsmFiles: []string{"asm_amd64.s", "asm_linux_riscv64.s", "asm_plan9_riscv64.s", "portable.s"},
		},
		{
			Module:   "example.com/amd64-only",
			Version:  "v1.0.0",
			AsmFiles: []string{"asm_amd64.s"},
		},
	}
	got, err := filterDiscoveryCandidatesForTargets(candidates, []string{"linux/riscv64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryCandidate{{
		Module:        "example.com/mixed",
		Version:       "v1.0.0",
		Architectures: []string{"riscv64", "unknown"},
		AsmFiles:      []string{"asm_linux_riscv64.s", "portable.s"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target candidates = %#v, want %#v", got, want)
	}
}

func TestFilterDiscoveryCandidatesForTargetsKeepsUnknownSuffixesConservatively(t *testing.T) {
	candidates := []discoveryCandidate{{
		Module:   "example.com/generated",
		Version:  "v1.0.0",
		AsmFiles: []string{"asm_amd64x.s", "asm_linux.s", "asm_windows.s"},
	}}
	got, err := filterDiscoveryCandidatesForTargets(candidates, []string{"linux/riscv64"})
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := []string{"asm_amd64x.s", "asm_linux.s"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].AsmFiles, wantFiles) {
		t.Fatalf("target candidates = %#v, want files %#v", got, wantFiles)
	}
}

func TestDiscoveryPackagePatternsUseOnlyAssemblyDirectories(t *testing.T) {
	candidate := discoveryCandidate{
		Module:   "example.com/root",
		Version:  "v1.0.0",
		AsmFiles: []string{"root_amd64.s", "internal/a_amd64.s", "internal/sub/b_arm64.s"},
	}
	want := []string{"example.com/root", "example.com/root/internal", "example.com/root/internal/sub"}
	if got := discoveryPackagePatterns(candidate); !reflect.DeepEqual(got, want) {
		t.Fatalf("patterns = %#v, want %#v", got, want)
	}
}

func TestDiscoveryExecutionPlanUsesDeclaredModulePathAndExactForkContent(t *testing.T) {
	candidate := discoveryCandidate{
		Module:   "example.com/fork",
		Version:  "v1.2.3",
		AsmFiles: []string{"crypto/hash_amd64.s"},
	}
	plan, err := makeDiscoveryExecutionPlan(candidate, "example.com/upstream")
	if err != nil {
		t.Fatal(err)
	}
	if plan.ModulePath != "example.com/upstream" {
		t.Fatalf("module path = %q, want declared path", plan.ModulePath)
	}
	if want := []string{"example.com/upstream/crypto"}; !reflect.DeepEqual(plan.Patterns, want) {
		t.Fatalf("patterns = %#v, want %#v", plan.Patterns, want)
	}
	for _, want := range []string{
		"require example.com/upstream v1.2.3",
		"replace example.com/upstream => example.com/fork v1.2.3",
	} {
		if !strings.Contains(plan.GoMod, want) {
			t.Fatalf("go.mod missing %q:\n%s", want, plan.GoMod)
		}
	}
}

func TestParseDeclaredModulePath(t *testing.T) {
	for _, test := range []struct {
		contents string
		want     string
	}{
		{contents: "module example.com/plain\n", want: "example.com/plain"},
		{contents: "// generated\nmodule \"example.com/quoted\" // comment\n", want: "example.com/quoted"},
	} {
		got, err := parseDeclaredModulePath([]byte(test.contents))
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("declared module = %q, want %q", got, test.want)
		}
	}
}

func TestApplicableDiscoveryAssemblyFilesUsesExactTargetBuildRules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		fullPath := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, fullPath, contents)
	}
	write("pkg.go", "package pkg\n")
	write("asm_linux_amd64.s", "TEXT ·amd64(SB),0,$0-0\nRET\n")
	write("asm_freebsd_amd64.s", "TEXT ·freebsd(SB),0,$0-0\nRET\n")
	write("tagged.s", "//go:build linux && arm64\n\nTEXT ·arm64(SB),0,$0-0\nRET\n")
	write("_hidden/hidden.go", "package hidden\n")
	write("_hidden/hidden_amd64.s", "TEXT ·hidden(SB),0,$0-0\nRET\n")
	write("nested/go.mod", "module example.com/nested\n\ngo 1.27\n")
	write("nested/nested.go", "package nested\n")
	write("nested/nested_amd64.s", "TEXT ·nested(SB),0,$0-0\nRET\n")

	candidate := discoveryCandidate{AsmFiles: []string{
		"_hidden/hidden_amd64.s",
		"asm_freebsd_amd64.s",
		"asm_linux_amd64.s",
		"nested/nested_amd64.s",
		"tagged.s",
	}}
	got, err := applicableDiscoveryAssemblyFiles(candidate, dir, []string{"linux/amd64", "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"asm_linux_amd64.s", "tagged.s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applicable assembly = %#v, want %#v", got, want)
	}
}

func TestDiscoveryBuildConfigurationsCoverMutuallyExclusiveCustomTags(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "pkg.go"), "package pkg\n")
	writeTestFile(t, filepath.Join(dir, "default.s"), "//go:build !special\n\nTEXT ·defaultImpl(SB),0,$0-0\nRET\n")
	writeTestFile(t, filepath.Join(dir, "special.s"), "//go:build special\n\nTEXT ·specialImpl(SB),0,$0-0\nRET\n")
	candidate := discoveryCandidate{
		Module:   "example.com/customtags",
		Version:  "v1.0.0",
		AsmFiles: []string{"default.s", "special.s"},
	}
	got, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryBuildConfiguration{
		{Targets: []string{"linux/amd64"}, AsmFiles: []string{"default.s"}},
		{BuildTags: []string{"special"}, Targets: []string{"linux/amd64"}, AsmFiles: []string{"special.s"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build configurations = %#v, want %#v", got, want)
	}
}

func TestDiscoveryBuildConfigurationsCoverTargetSpecificTagAssignments(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "pkg.go"), "package pkg\n")
	writeTestFile(t, filepath.Join(dir, "hybrid.s"), "//go:build (amd64 && avx) || (arm64 && neon)\n\nTEXT ·hybrid(SB),0,$0-0\nRET\n")
	candidate := discoveryCandidate{
		Module:   "example.com/targettags",
		Version:  "v1.0.0",
		AsmFiles: []string{"hybrid.s"},
	}
	got, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/amd64", "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryBuildConfiguration{
		{BuildTags: []string{"avx"}, Targets: []string{"linux/amd64"}, AsmFiles: []string{"hybrid.s"}},
		{BuildTags: []string{"neon"}, Targets: []string{"linux/arm64"}, AsmFiles: []string{"hybrid.s"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build configurations = %#v, want %#v", got, want)
	}
}

func TestDiscoveryBuildConfigurationsDoNotEnumerateUnrelatedPackageTags(t *testing.T) {
	for _, test := range []struct {
		name      string
		asmTags   string
		defaultGo bool
		wantTags  []string
	}{
		{name: "default-package", defaultGo: true},
		{name: "one-relevant-tag", asmTags: "feature058", wantTags: []string{"feature058"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.defaultGo {
				writeTestFile(t, filepath.Join(dir, "default.go"), "package pkg\n")
			}
			for i := 0; i < 59; i++ {
				tag := fmt.Sprintf("feature%03d", i)
				name := fmt.Sprintf("tagged_%03d.go", i)
				writeTestFile(t, filepath.Join(dir, name), "//go:build "+tag+"\n\npackage pkg\n")
			}
			asmSource := "TEXT ·f(SB),$0-0\nRET\n"
			if test.asmTags != "" {
				asmSource = "//go:build " + test.asmTags + "\n\n" + asmSource
			}
			writeTestFile(t, filepath.Join(dir, "f_amd64.s"), asmSource)

			candidate := discoveryCandidate{
				Module: "example.com/manytags", Version: "v1.0.0",
				AsmFiles: []string{"f_amd64.s"},
			}
			configs, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/amd64"})
			if err != nil {
				t.Fatal(err)
			}
			want := []discoveryBuildConfiguration{{
				BuildTags: test.wantTags,
				Targets:   []string{"linux/amd64"},
				AsmFiles:  []string{"f_amd64.s"},
			}}
			if !reflect.DeepEqual(configs, want) {
				t.Fatalf("build configurations = %#v, want %#v", configs, want)
			}
		})
	}
}

func TestDiscoveryBuildConfigurationsSolveManyRelevantTags(t *testing.T) {
	for _, test := range []struct {
		name         string
		count        int
		operator     string
		wantAll      bool
		additional   string
		inapplicable bool
	}{
		{name: "conjunction", count: 17, operator: " && ", wantAll: true},
		{name: "disjunction", count: 59, operator: " || "},
		{name: "negated", count: 17, operator: " && ", wantAll: true, additional: " && !forbidden"},
		{name: "ignored-generator", count: 59, operator: " || ", additional: " && ignore", inapplicable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			var tags []string
			for i := 0; i < test.count; i++ {
				tags = append(tags, fmt.Sprintf("required%02d", i))
			}
			expression := strings.Join(tags, test.operator)
			if test.operator == " || " && test.additional != "" {
				expression = "(" + expression + ")"
			}
			writeTestFile(t, filepath.Join(dir, "pkg.go"),
				"//go:build "+expression+test.additional+"\n\npackage pkg\n")
			writeTestFile(t, filepath.Join(dir, "f_amd64.s"), "TEXT ·f(SB),$0-0\nRET\n")
			candidate := discoveryCandidate{
				Module: "example.com/manyrelevant", Version: "v1.0.0",
				AsmFiles: []string{"f_amd64.s"},
			}
			configs, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/amd64"})
			if err != nil {
				t.Fatal(err)
			}
			if test.inapplicable {
				if len(configs) != 0 {
					t.Fatalf("ignored generator has configurations: %#v", configs)
				}
				return
			}
			wantTags := tags[:1]
			if test.wantAll {
				wantTags = tags
			}
			want := []discoveryBuildConfiguration{{
				BuildTags: wantTags, Targets: []string{"linux/amd64"},
				AsmFiles: []string{"f_amd64.s"},
			}}
			if !reflect.DeepEqual(configs, want) {
				t.Fatalf("build configurations = %#v, want %#v", configs, want)
			}
		})
	}
}

func TestDiscoveryBuildConfigurationsDoNotEnableIgnoredGeneratorSources(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "pkg.go"), "package pkg\n")
	writeTestFile(t, filepath.Join(dir, "generated.s"), "//go:build ignore\n\nTEXT ·generated(SB),0,$0-0\nRET\n")
	candidate := discoveryCandidate{
		Module:   "example.com/generator",
		Version:  "v1.0.0",
		AsmFiles: []string{"generated.s"},
	}
	got, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("build configurations = %#v, want ignored generator assembly to remain inapplicable", got)
	}
}

func TestDiscoveryBuildConfigurationsInferUnsuffixedAssemblyFromGoAssembler(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "pkg.go"), "package pkg\n")
	writeTestFile(t, filepath.Join(dir, "goid.s"), "TEXT ·goid(SB),0,$0-0\nMOVQ AX, BX\nLEAQ (BX), CX\nRET\n")
	candidate := discoveryCandidate{
		Module:   "example.com/goid",
		Version:  "v1.0.0",
		AsmFiles: []string{"goid.s"},
	}
	got, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/386", "linux/amd64", "linux/arm64", "js/wasm"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryBuildConfiguration{{Targets: []string{"linux/amd64"}, AsmFiles: []string{"goid.s"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build configurations = %#v, want %#v", got, want)
	}
}

func TestDiscoveryBuildConfigurationsKeepTrulyCrossArchUnsuffixedAssembly(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "pkg.go"), "package pkg\n")
	writeTestFile(t, filepath.Join(dir, "return.s"), "TEXT ·returnOnly(SB),0,$0-0\nRET\n")
	candidate := discoveryCandidate{
		Module:   "example.com/returnonly",
		Version:  "v1.0.0",
		AsmFiles: []string{"return.s"},
	}
	got, err := discoveryBuildConfigurations(candidate, dir, []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryBuildConfiguration{{Targets: []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64"}, AsmFiles: []string{"return.s"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build configurations = %#v, want %#v", got, want)
	}
}

func TestValidateDiscoveryReportRejectsZeroAssemblyAndSkippedTargets(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.com/root", Version: "v1.0.0", AsmFiles: []string{"root_amd64.s"}}
	report := matrixReport{
		Targets:      []targetReport{{Goos: "linux", Goarch: "amd64"}},
		TotalTargets: 1,
	}
	err := validateDiscoveryReport([]string{"linux/amd64"}, candidate, report)
	if err == nil || !strings.Contains(err.Error(), "no assembly") {
		t.Fatalf("validateDiscoveryReport() error = %v, want no assembly failure", err)
	}

	report.Targets[0].TotalAsm = 1
	report.Targets[0].Success = 1
	report.TotalAsm = 1
	report.Success = 1
	err = validateDiscoveryReport([]string{"linux/amd64", "windows/amd64"}, candidate, report)
	if err == nil || !strings.Contains(err.Error(), "target coverage changed") {
		t.Fatalf("validateDiscoveryReport() error = %v, want target coverage failure", err)
	}
}

func TestValidateDiscoveryReportRejectsEveryUnobservedApplicableAssemblyFile(t *testing.T) {
	candidate := discoveryCandidate{
		Module:   "example.com/root",
		Version:  "v1.0.0",
		AsmFiles: []string{"root_amd64.s", "asm_s390x.s"},
	}
	report := matrixReport{
		Targets: []targetReport{{
			Goos:     "linux",
			Goarch:   "amd64",
			AsmFiles: []string{"/go/pkg/mod/example.com/root@v1.0.0/different_amd64.s"},
			TotalAsm: 1,
			Success:  1,
		}},
		TotalTargets: 1,
		TotalAsm:     1,
		Success:      1,
	}
	err := validateDiscoveryReport([]string{"linux/amd64"}, candidate, report)
	if err == nil || !strings.Contains(err.Error(), "assembly files were not exercised") {
		t.Fatalf("validateDiscoveryReport() error = %v, want unobserved file failure", err)
	}

	report.Targets[0].AsmFiles = []string{"/go/pkg/mod/example.com/root@v1.0.0/root_amd64.s"}
	if err := validateDiscoveryReport([]string{"linux/amd64"}, candidate, report); err == nil || !strings.Contains(err.Error(), "asm_s390x.s") {
		t.Fatalf("validateDiscoveryReport() error = %v, want every candidate file required", err)
	}

	filtered := candidate
	filtered.AsmFiles = []string{"root_amd64.s"}
	if err := validateDiscoveryReport([]string{"linux/amd64"}, filtered, report); err != nil {
		t.Fatalf("validateDiscoveryReport() with prefiltered candidate error = %v", err)
	}
}

func TestValidateDiscoveryReportAcceptsOnlyEvidenceBackedTargetNotApplicable(t *testing.T) {
	candidate := discoveryCandidate{
		Module:   "example.com/root",
		Version:  "v1.0.0",
		AsmFiles: []string{"cross_arch.s"},
	}
	report := matrixReport{
		Targets: []targetReport{
			{
				Goos:     "linux",
				Goarch:   "amd64",
				AsmFiles: []string{"/go/pkg/mod/example.com/root@v1.0.0/cross_arch.s"},
				TotalAsm: 1,
				Success:  1,
			},
			{
				Goos:          "linux",
				Goarch:        "386",
				AsmFiles:      []string{"/go/pkg/mod/example.com/root@v1.0.0/cross_arch.s"},
				TotalAsm:      1,
				NotApplicable: 1,
				NotApplicableItems: []targetNotApplicableItem{{
					PkgPath:         "example.com/root",
					AsmFile:         "/go/pkg/mod/example.com/root@v1.0.0/cross_arch.s",
					Kind:            targetNotApplicableGoTextArgSize,
					Symbol:          "example.com/root.StructFieldB",
					DeclaredArgSize: 25,
					ExpectedArgSize: 17,
					Reason:          "TEXT argument size is incompatible with the Go declaration on 386",
				}},
			},
		},
		TotalTargets:  2,
		TotalAsm:      2,
		Success:       1,
		NotApplicable: 1,
	}
	if err := validateDiscoveryReport([]string{"linux/amd64", "linux/386"}, candidate, report); err != nil {
		t.Fatalf("validateDiscoveryReport() error = %v", err)
	}
	details := collectMatrixNotApplicableItems(report)
	if len(details) != 1 || details[0].Target != "linux/386" || details[0].Symbol != "example.com/root.StructFieldB" {
		t.Fatalf("not-applicable details = %#v", details)
	}

	report.Targets[1].NotApplicableItems[0].Kind = "unsupported_instruction"
	if err := validateDiscoveryReport([]string{"linux/amd64", "linux/386"}, candidate, report); err == nil || !strings.Contains(err.Error(), "invalid not-applicable evidence") {
		t.Fatalf("validateDiscoveryReport() error = %v, want evidence rejection", err)
	}
}

func TestDiscoveryCorpusReportAccountsForEverySelectedCandidate(t *testing.T) {
	report := discoveryCorpusReport{Selected: 7, Passed: 3, Failed: 2, NotApplicable: 2}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	report.NotApplicable--
	if err := validateDiscoveryCorpusAccounting(report); err == nil || !strings.Contains(err.Error(), "accounting mismatch") {
		t.Fatalf("validateDiscoveryCorpusAccounting() error = %v, want accounting mismatch", err)
	}
}

func TestDiscoveryCorpusReportAccountingMatchesAuditableResults(t *testing.T) {
	report := discoveryCorpusReport{
		Selected:     2,
		Passed:       2,
		Translations: 3,
		Results: []discoveryCorpusResult{
			{Module: "example.com/a", Version: "v1.0.0", Status: discoveryStatusPassed, Translations: 1},
			{Module: "example.com/b", Version: "v1.0.0", Status: discoveryStatusFailed, Translations: 2},
		},
	}
	if err := validateDiscoveryCorpusAccounting(report); err == nil || !strings.Contains(err.Error(), "result status counts") {
		t.Fatalf("validateDiscoveryCorpusAccounting() error = %v, want status count mismatch", err)
	}

	report.Passed = 1
	report.Failed = 1
	report.Translations = 2
	if err := validateDiscoveryCorpusAccounting(report); err == nil || !strings.Contains(err.Error(), "translation counts") {
		t.Fatalf("validateDiscoveryCorpusAccounting() error = %v, want translation count mismatch", err)
	}
}

func writeDiscoveryReportFixture(t *testing.T) (string, string, discoverySourceIdentity) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger")
	records := filepath.Join(ledger, "records")
	if err := os.MkdirAll(records, 0755); err != nil {
		t.Fatal(err)
	}
	candidates := []discoveryCandidate{
		{Module: "example.com/a", Version: "v1.0.0", Architectures: []string{"amd64"}, AsmFiles: []string{"a_amd64.s"}},
		{Module: "example.com/b", Version: "v2.0.0", Architectures: []string{"arm64"}, AsmFiles: []string{"b_arm64.s"}},
	}
	for i, candidate := range candidates {
		record := discoveryRecord{Kind: "matched", Module: candidate.Module, Version: candidate.Version, Architectures: candidate.Architectures, AsmFiles: candidate.AsmFiles}
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(records, fmt.Sprintf("%02d.jsonl", i)), string(data)+"\n")
	}
	reports := filepath.Join(t.TempDir(), "reports")
	if err := os.MkdirAll(reports, 0755); err != nil {
		t.Fatal(err)
	}
	const shardCount = 2
	provenance := fixtureDiscoveryProvenance(t, ledger)
	for shard := 0; shard < shardCount; shard++ {
		selected := selectDiscoveryShard(candidates, shard, shardCount)
		report := discoveryCorpusReport{
			SchemaVersion:      discoveryReportSchema,
			Provenance:         provenance,
			Targets:            []string{"linux/amd64", "linux/arm64"},
			ShardIndex:         shard,
			ShardCount:         shardCount,
			CandidateTotal:     len(candidates),
			EligibleCandidates: len(candidates),
			Selected:           len(selected),
			Passed:             len(selected),
		}
		for _, candidate := range selected {
			report.Results = append(report.Results, discoveryCorpusResult{
				Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
				DiscoveredAsmFiles: candidate.AsmFiles, Translations: 1,
			})
			report.Translations++
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(reports, fmt.Sprintf("shard-%d.json", shard)), string(data)+"\n")
	}
	return ledger, reports, provenance.Source
}

func TestVerifyDiscoveryCorpusReportsRequiresExactLedgerCoverage(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err != nil {
		t.Fatalf("complete reports failed verification: %v", err)
	}
	if err := os.Remove(filepath.Join(reports, "shard-1.json")); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil || !strings.Contains(err.Error(), "shard reports") {
		t.Fatalf("missing shard verification error = %v", err)
	}
}

func TestVerifyDiscoveryCorpusReportsRejectsMissingProvenance(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	reportPath := filepath.Join(reports, "shard-0.json")
	report, err := readDiscoveryCorpusReport(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	report.Provenance = discoveryCorpusProvenance{}
	if err := writeDiscoveryCorpusReport(reportPath, report); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatal("accepted reports without source/toolchain provenance; matching candidates do not prove one frozen run")
	}
}

func TestDiscoveryConfigurationAsmFilesDeduplicatesTargets(t *testing.T) {
	configs := []discoveryBuildConfiguration{
		{Targets: []string{"linux/amd64"}, AsmFiles: []string{"pkg/a_amd64.s", "pkg/b.s"}},
		{Targets: []string{"windows/amd64"}, AsmFiles: []string{"pkg/a_amd64.s"}},
		{Targets: []string{"linux/386"}, AsmFiles: []string{"pkg/b.s"}},
	}
	want := []string{"pkg/a_amd64.s", "pkg/b.s"}
	if got := discoveryConfigurationAsmFiles(configs); !reflect.DeepEqual(got, want) {
		t.Fatalf("applicable assembly files = %#v, want %#v", got, want)
	}
}

func TestDiscoveryCorpusReportValidatesSourceNotApplicableEvidence(t *testing.T) {
	result := discoveryCorpusResult{
		Module:             "example.com/root",
		Version:            "v1.0.0",
		Status:             discoveryStatusNotApplicable,
		DiscoveredAsmFiles: []string{"pkg/a_amd64.s", "pkg/b.s", "pkg/c.s"},
		SourceNotApplicableItems: []discoverySourceNotApplicableItem{
			{AsmFile: "pkg/a_amd64.s", Targets: []string{"linux/amd64"}, Kind: discoverySourceNotApplicableGoAssembler, Reason: "current Go assembler rejected the source"},
			{AsmFiles: []string{"pkg/b.s"}, Targets: []string{"windows/amd64"}, Kind: discoverySourceNotApplicableGoBuild, Reason: "current Go compiler rejected the exact package"},
			{AsmFile: "pkg/c.s", Targets: []string{"linux/amd64"}, Kind: discoverySourceNotApplicableNoSymbols, Reason: "current Go assembler emitted no object symbols"},
		},
	}
	report := discoveryCorpusReport{Selected: 1, NotApplicable: 1, Results: []discoveryCorpusResult{result}}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatalf("valid source N/A evidence error = %v", err)
	}

	invalid := report
	invalid.Results = append([]discoveryCorpusResult(nil), report.Results...)
	invalid.Results[0].SourceNotApplicableItems = append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems...)
	invalid.Results[0].SourceNotApplicableItems[1].AsmFiles = []string{"pkg/not-discovered.s"}
	if err := validateDiscoveryCorpusAccounting(invalid); err == nil || !strings.Contains(err.Error(), "invalid source not-applicable evidence") {
		t.Fatalf("validateDiscoveryCorpusAccounting() error = %v, want invalid source evidence", err)
	}

	invalid.Results[0].SourceNotApplicableItems[1] = discoverySourceNotApplicableItem{
		AsmFiles: []string{"pkg/b.s"}, Targets: []string{"linux/amd64"}, Kind: "unsupported_instruction", Reason: "not valid N/A evidence",
	}
	if err := validateDiscoveryCorpusAccounting(invalid); err == nil || !strings.Contains(err.Error(), "invalid source not-applicable evidence") {
		t.Fatalf("validateDiscoveryCorpusAccounting() error = %v, want invalid kind rejection", err)
	}
}

func TestTranslatorInvocationAcceptsExactPatterns(t *testing.T) {
	invocation := makeTranslatorInvocationForTargetsAndTags(
		"/corpus",
		"example.com/root",
		[]string{"example.com/root/internal/...", "example.com/root"},
		[]string{"avx", "sse"},
		[]string{"linux/amd64", "windows/amd64"},
		[]string{"internal/fast.s", "root_amd64.s"},
		"/tmp/out",
		"/repo",
		"/bin/llc-22",
		"/tmp/report.json",
	)
	if !containsString(invocation.Args, "-patterns=example.com/root/internal/...,example.com/root") {
		t.Fatalf("translator args = %#v, want exact package patterns", invocation.Args)
	}
	if containsString(invocation.Args, "-strict-load") {
		t.Fatalf("discovery translator args = %#v, must tolerate unrelated Go package errors", invocation.Args)
	}
	if !containsString(invocation.Args, "-tags=avx,sse") {
		t.Fatalf("discovery translator args = %#v, want explicit custom build tags", invocation.Args)
	}
	if !containsString(invocation.Args, "-targets=linux/amd64,windows/amd64") || containsString(invocation.Args, "-all-targets") {
		t.Fatalf("discovery translator args = %#v, want only applicable targets", invocation.Args)
	}
	if !containsString(invocation.Args, "-asm-files=internal/fast.s,root_amd64.s") {
		t.Fatalf("discovery translator args = %#v, want exact assembly allowlist", invocation.Args)
	}
}

func TestDiscoveryTranslatorInvocationCompilesObjectWithoutOptimization(t *testing.T) {
	invocation := makeDiscoveryTranslatorInvocation(
		"/corpus", "example.com/root", []string{"example.com/root"}, nil,
		[]string{"linux/amd64"}, []string{"asm_amd64.s"},
		"/tmp/out", "/repo", "/bin/llc-22", "/tmp/report.json",
	)
	if !containsString(invocation.Args, "-compile") ||
		!containsString(invocation.Args, "-llc-opt-level=0") {
		t.Fatalf("discovery translator args = %v, want object compilation at -O0", invocation.Args)
	}
}

func TestDiscoveryCommandEnvironmentMatchesCgoDisabledApplicability(t *testing.T) {
	env := discoveryCommandEnvironment([]string{
		"CGO_ENABLED=1",
		"GOFLAGS=-mod=vendor",
		"GOTOOLCHAIN=auto",
		"GOWORK=/tmp/work",
		"GIT_CONFIG_GLOBAL=/tmp/rewrite-github-to-ssh",
		"GIT_TERMINAL_PROMPT=1",
	})
	want := map[string]string{
		"CGO_ENABLED":         "0",
		"GOFLAGS":             "-mod=mod",
		"GOTOOLCHAIN":         "local",
		"GOWORK":              "off",
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_TERMINAL_PROMPT": "0",
	}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && want[key] == value {
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("discovery command environment omitted required overrides: %v; env=%v", want, env)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}
