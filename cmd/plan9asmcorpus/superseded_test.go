package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupersededSkipRequiresNewerScannedVersion(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := os.MkdirAll(filepath.Join(ledger, "records"), 0755); err != nil {
		t.Fatal(err)
	}
	records := `{"kind":"matched","module":"example.com/old","version":"v1.2.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}` + "\n" +
		`{"kind":"scanned","module":"example.com/current","version":"v1.3.0"}` + "\n"
	writeTestFile(t, filepath.Join(ledger, "records", "00.jsonl"), records)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "testdata", "corpus"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := discoverySupersededManifest{
		SchemaVersion: 1,
		Skips: []discoverySupersededSkip{{
			Module: "example.com/old", Version: "v1.2.0",
			ReplacementModule: "example.com/current", ReplacementVersion: "v1.3.0",
			Reason: "renamed project", EvidenceURLs: []string{"https://example.com/rename"},
		}},
	}
	writeManifest := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(root, "testdata", "corpus", "superseded-modules.json"), string(data))
	}
	writeManifest()
	if skips, err := loadSupersededSkips(root, ledger); err != nil || len(skips) != 1 {
		t.Fatalf("valid supersession = %v, %v", skips, err)
	}
	for _, test := range []struct {
		name    string
		version string
		module  string
	}{
		{"not newer", "v1.2.0", "example.com/current"},
		{"not scanned", "v1.4.0", "example.com/current"},
		{"unknown project", "v1.3.0", "example.com/unrelated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest.Skips[0].ReplacementVersion = test.version
			manifest.Skips[0].ReplacementModule = test.module
			writeManifest()
			if _, err := loadSupersededSkips(root, ledger); err == nil {
				t.Fatal("unproved supersession was accepted")
			}
		})
	}
}

func TestCuratedSupersededVersionsAreInScanLedger(t *testing.T) {
	root := filepath.Join("..", "..")
	ledger := filepath.Join(root, "testdata", "discovery", "ledger")
	skips, err := loadSupersededSkips(root, ledger)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"github.com/celliott/gvisor@v0.0.0-20180504232233-3b895abd3b05",
		"github.com/0pcom/skywire@v1.3.69",
	} {
		if _, ok := skips[key]; !ok {
			t.Fatalf("missing curated supersession %s", key)
		}
	}
	if len(skips) != 2 {
		t.Fatalf("got %d superseded versions, want 2", len(skips))
	}
}

func TestSupersededSkipIsAuditedAndNotCountedAsPass(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	var old discoveryCorpusResult
	var reportPath string
	for shard := 0; shard < 2; shard++ {
		path := filepath.Join(reports, "shard-"+string('0'+rune(shard))+".json")
		report, err := readDiscoveryCorpusReport(path)
		if err != nil {
			t.Fatal(err)
		}
		for i := range report.Results {
			if report.Results[i].Module != "example.com/a" {
				continue
			}
			old = report.Results[i]
			reportPath = path
			report.Results[i].Status = discoveryStatusSkippedSuperseded
			report.Results[i].Translations = 0
			report.Results[i].Superseded = &discoverySupersededSkip{
				Module: old.Module, Version: old.Version,
				ReplacementModule: "example.com/b", ReplacementVersion: "v2.0.0",
				Reason: "new version", EvidenceURLs: []string{"https://example.com/proof"},
			}
			report.Passed--
			report.Translations--
			report.SkippedSuperseded++
			if err := writeDiscoveryCorpusReport(path, report); err != nil {
				t.Fatal(err)
			}
		}
	}
	if reportPath == "" {
		t.Fatal("missing old candidate")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "testdata", "corpus"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := discoverySupersededManifest{SchemaVersion: 1, Skips: []discoverySupersededSkip{{
		Module: old.Module, Version: old.Version,
		ReplacementModule: "example.com/b", ReplacementVersion: "v2.0.0",
		Reason: "new version", EvidenceURLs: []string{"https://example.com/proof"},
	}}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "testdata", "corpus", "superseded-modules.json"), string(data))
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, root)
	if err != nil || !progress.Verified || progress.Passed != 1 || progress.SkippedSuperseded != 1 {
		t.Fatalf("superseded progress = %+v, %v", progress, err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("c", 64))
	if err != nil || restored.SkippedSuperseded != 1 {
		t.Fatalf("restored progress = %+v, %v", restored, err)
	}
	found := false
	for _, candidate := range restored.Candidates {
		if candidate.Status != discoveryStatusSkippedSuperseded {
			continue
		}
		found = true
		if candidate.Superseded == nil || candidate.Superseded.ReplacementModule != "example.com/b" ||
			candidate.Superseded.Reason != "new version" {
			t.Fatalf("supersession evidence was lost: %+v", candidate)
		}
	}
	if !found {
		t.Fatal("assembly ledger lost superseded candidate")
	}
	report, err := readDiscoveryCorpusReport(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := range report.Results {
		if report.Results[i].Status == discoveryStatusSkippedSuperseded {
			report.Results[i].Superseded.ReplacementVersion = "v9.0.0"
		}
	}
	if err := writeDiscoveryCorpusReport(reportPath, report); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, root); err == nil {
		t.Fatal("report supersession diverged from manifest")
	}
}

func TestSupersededRunnerDoesNotDownloadOldVersion(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "testdata", "corpus"), 0755); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(root, "ledger")
	writeTestFile(t, ledger, `{"kind":"matched","module":"example.com/old","version":"v1.2.0","architectures":["amd64"],"asm_files":["f_amd64.s"]}`+"\n"+
		`{"kind":"scanned","module":"example.com/current","version":"v1.3.0"}`+"\n")
	manifest := discoverySupersededManifest{SchemaVersion: 1, Skips: []discoverySupersededSkip{{
		Module: "example.com/old", Version: "v1.2.0",
		ReplacementModule: "example.com/current", ReplacementVersion: "v1.3.0",
		Reason: "new version", EvidenceURLs: []string{"https://example.com/proof"},
	}}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "testdata", "corpus", "superseded-modules.json"), string(data))
	reportPath := filepath.Join(root, "report.json")
	err = runDiscoveryCorpus(discoveryCorpusConfig{
		LedgerPath: ledger, RepoRoot: root, ShardCount: 1,
		CandidateTimeout: time.Minute, ReportPath: reportPath, Targets: []string{"linux/amd64"},
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
		runCandidate: func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			t.Fatal("superseded candidate was executed")
			return matrixReport{}, nil, nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := readDiscoveryCorpusReport(reportPath)
	if err != nil || report.SkippedSuperseded != 1 || report.Passed != 0 || report.Translations != 0 {
		t.Fatalf("runner report = %+v, %v", report, err)
	}
}
