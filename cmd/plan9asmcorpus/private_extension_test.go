package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrivateExtensionMustAssembleWithCurrentGo(t *testing.T) {
	moduleDir := t.TempDir()
	const source = "#include \"textflag.h\"\nTEXT ·amxSet(SB),NOSPLIT,$0-0\n WORD $0x00201220\n RET\n"
	file := filepath.Join(moduleDir, "amx_darwin_arm64.s")
	writeTestFile(t, file, source)
	skip := discoveryPrivateExtensionSkip{AsmFile: filepath.Base(file), Target: "darwin/arm64"}
	workDir := t.TempDir()
	if err := verifyPrivateExtensionGoAssembler(context.Background(), workDir, moduleDir, os.Environ(), skip); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, file, strings.Replace(source, "WORD $0x00201220", "NOT_A_GO_INSTRUCTION", 1))
	if err := verifyPrivateExtensionGoAssembler(context.Background(), workDir, moduleDir, os.Environ(), skip); err == nil {
		t.Fatal("invalid Go assembly was accepted as a private-extension skip")
	}
}

func TestCuratedPrivateExtensionIsExactLedgerCandidate(t *testing.T) {
	root := filepath.Join("..", "..")
	ledger := filepath.Join(root, "testdata", "discovery", "ledger")
	skips, err := loadPrivateExtensionSkips(root, ledger)
	if err != nil {
		t.Fatal(err)
	}
	const key = "github.com/fiber/ai@v0.1.2"
	if len(skips) != 1 || skips[key].AsmFile != "internal/kernel/kernel_amx_darwin_arm64.s" ||
		skips[key].Target != "darwin/arm64" {
		t.Fatalf("private-extension manifest = %#v", skips)
	}
}

func TestPrivateExtensionManifestRejectsUnlistedFile(t *testing.T) {
	root := t.TempDir()
	ledger := filepath.Join(root, "ledger")
	record := discoveryRecord{
		Kind: "matched", Module: "example.com/asm", Version: "v1.0.0",
		Architectures: []string{"arm64"}, AsmFiles: []string{"kernel/amx_darwin_arm64.s"},
	}
	recordData, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, ledger, string(recordData)+"\n")
	manifestDir := filepath.Join(root, "testdata", "corpus")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := discoveryPrivateExtensionManifest{
		SchemaVersion: 1,
		Skips: []discoveryPrivateExtensionSkip{{
			Module: "example.com/asm", Version: "v1.0.0",
			AsmFile: "kernel/other.s", Target: "darwin/arm64",
			SourceSHA256: strings.Repeat("a", 64), Opcode: "0x00201220",
			Reason: "private instruction", EvidenceURLs: []string{"https://example.com/source"},
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(manifestDir, "private-extensions.json"), string(data))
	if _, err := loadPrivateExtensionSkips(root, ledger); err == nil {
		t.Fatal("unlisted assembly file accepted as private extension")
	}
	manifest.Skips[0].AsmFile = "kernel/amx_darwin_arm64.s"
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(manifestDir, "private-extensions.json"), string(data))
	if skips, err := loadPrivateExtensionSkips(root, ledger); err != nil || len(skips) != 1 {
		t.Fatalf("exact file rejected: %#v, %v", skips, err)
	}
}

func TestPrivateExtensionFiltersOnlyPinnedFileAndTarget(t *testing.T) {
	skip := discoveryPrivateExtensionSkip{
		Module: "example.com/asm", Version: "v1.0.0",
		AsmFile: "kernel/amx_darwin_arm64.s", Target: "darwin/arm64",
	}
	configs := []discoveryBuildConfiguration{{
		Targets:  []string{"darwin/arm64", "linux/arm64"},
		AsmFiles: []string{"kernel/amx_darwin_arm64.s", "kernel/neon_arm64.s"},
	}}
	filtered, active, err := filterPrivateExtensionConfigurations(configs, skip)
	if err != nil || !active {
		t.Fatalf("filter private extension = %v, %v", active, err)
	}
	want := []discoveryBuildConfiguration{
		{Targets: []string{"darwin/arm64"}, AsmFiles: []string{"kernel/neon_arm64.s"}},
		{Targets: []string{"linux/arm64"}, AsmFiles: []string{"kernel/amx_darwin_arm64.s", "kernel/neon_arm64.s"}},
	}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf("filtered configurations = %#v, want %#v", filtered, want)
	}

	filtered, active, err = filterPrivateExtensionConfigurations([]discoveryBuildConfiguration{{
		Targets: []string{"linux/arm64"}, AsmFiles: []string{"kernel/neon_arm64.s"},
	}}, skip)
	if err != nil || active || len(filtered) != 1 {
		t.Fatalf("unrelated target was skipped: %#v, %v, %v", filtered, active, err)
	}
}

func TestPrivateExtensionProofPinsExactSource(t *testing.T) {
	moduleDir := t.TempDir()
	const source = "#define AMX_SET WORD $0x00201220\nTEXT amxSet(SB),$0-0\n AMX_SET\n RET\n"
	file := filepath.Join(moduleDir, "kernel", "amx_darwin_arm64.s")
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, file, source)
	digest := sha256.Sum256([]byte(source))
	skip := discoveryPrivateExtensionSkip{
		Module: "example.com/asm", Version: "v1.0.0",
		AsmFile: "kernel/amx_darwin_arm64.s", Target: "darwin/arm64",
		SourceSHA256: hex.EncodeToString(digest[:]), Opcode: "0x00201220",
		Reason: "private AMX encoding", EvidenceURLs: []string{"https://example.com/source"},
	}
	if err := verifyPrivateExtensionSource(moduleDir, skip); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, file, strings.Replace(source, "0x00201220", "0x00201221", 1))
	if err := verifyPrivateExtensionSource(moduleDir, skip); err == nil {
		t.Fatal("changed source accepted as pinned private extension")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateExtensionSource(moduleDir, skip); err == nil {
		t.Fatal("missing source accepted as pinned private extension")
	}
}

func TestPrivateExtensionCandidateIsNotPassed(t *testing.T) {
	skip := discoveryPrivateExtensionSkip{
		Module: "example.com/asm", Version: "v1.0.0",
		AsmFile: "kernel/amx_darwin_arm64.s", Target: "darwin/arm64",
		SourceSHA256: strings.Repeat("a", 64), Opcode: "0x00201220",
		Reason: "private AMX encoding", EvidenceURLs: []string{"https://example.com/source"},
	}
	result := discoveryCorpusResult{
		Module: skip.Module, Version: skip.Version,
		Status:             discoveryStatusSkippedPrivateExtension,
		DiscoveredAsmFiles: []string{skip.AsmFile, "kernel/neon_arm64.s"},
		ApplicableAsmFiles: []string{"kernel/neon_arm64.s"},
		BuildConfigurations: []discoveryBuildConfiguration{{
			Targets: []string{"darwin/arm64"}, AsmFiles: []string{"kernel/neon_arm64.s"},
		}},
		Translations: 1, PrivateExtension: &skip,
	}
	report := discoveryCorpusReport{
		Selected: 1, SkippedPrivateExtension: 1, Translations: 1,
		Results: []discoveryCorpusResult{result},
	}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	if report.Passed != 0 {
		t.Fatal("private extension candidate counted as passed")
	}
	report.Results[0].BuildConfigurations[0].AsmFiles = append(
		report.Results[0].BuildConfigurations[0].AsmFiles, skip.AsmFile,
	)
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("private extension file was also claimed as translated")
	}
	report.Results[0].BuildConfigurations[0].AsmFiles = []string{"kernel/neon_arm64.s"}
	report.Results[0].Translations = 2
	report.Translations = 2
	if err := validateDiscoveryCorpusAccounting(report); err == nil {
		t.Fatal("private extension result claimed an untested translation")
	}
}

func TestPrivateExtensionSkipSurvivesAuditedAssemblyLedger(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	root := t.TempDir()
	manifestDir := filepath.Join(root, "testdata", "corpus")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	skip := discoveryPrivateExtensionSkip{
		Module: "example.com/a", Version: "v1.0.0",
		AsmFile: "a_amd64.s", Target: "linux/amd64",
		SourceSHA256: strings.Repeat("a", 64), Opcode: "0x00201220",
		Reason: "private instruction", EvidenceURLs: []string{"https://example.com/source"},
	}
	manifest := discoveryPrivateExtensionManifest{SchemaVersion: 1, Skips: []discoveryPrivateExtensionSkip{skip}}
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(manifestDir, "private-extensions.json"), string(data))
	}
	writeManifest()
	for shard := 0; shard < 2; shard++ {
		name := filepath.Join(reports, "shard-"+string(rune('0'+shard))+".json")
		report, err := readDiscoveryCorpusReport(name)
		if err != nil {
			t.Fatal(err)
		}
		for i := range report.Results {
			if report.Results[i].Module != skip.Module {
				continue
			}
			report.Results[i].Status = discoveryStatusSkippedPrivateExtension
			report.Results[i].Translations = 0
			report.Results[i].PrivateExtension = &skip
			report.Passed--
			report.Translations--
			report.SkippedPrivateExtension++
			if err := writeDiscoveryCorpusReport(name, report); err != nil {
				t.Fatal(err)
			}
		}
	}
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, root)
	if err != nil || !progress.Verified || progress.Passed != 1 || progress.SkippedPrivateExtension != 1 {
		t.Fatalf("private-extension progress = %+v, %v", progress, err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("c", 64))
	if err != nil || restored.SkippedPrivateExtension != 1 {
		t.Fatalf("restored private-extension progress = %+v, %v", restored, err)
	}
	manifest.Skips[0].Opcode = "0x00201221"
	writeManifest()
	_, err = collectDiscoveryProgress(
		ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, root,
	)
	if err == nil {
		t.Fatal("forged private-extension report was accepted after manifest changed")
	}
}
