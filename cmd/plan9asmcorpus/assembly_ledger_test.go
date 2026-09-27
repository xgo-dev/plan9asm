package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssemblyLedgerPersistsAuditedProgress(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatalf("idempotent update: %v", err)
	}
	got, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete || !got.Verified || got.Passed != 2 || got.CandidateTotal != 2 || len(got.Candidates) != 2 {
		t.Fatalf("assembly ledger = %+v", got)
	}
	for _, candidate := range got.Candidates {
		if candidate.Status != discoveryStatusPassed {
			t.Fatalf("candidate = %+v", candidate)
		}
	}
	if _, err := readAssemblyLedger(output, strings.Repeat("b", 64), semanticSource); err == nil {
		t.Fatal("stale scan ledger accepted")
	}
	if _, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("b", 64)); err == nil {
		t.Fatal("stale source accepted")
	}
}

func TestAssemblyLedgerSemanticSourceExcludesOnlyItsEvidence(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v: %s", err, output)
	}
	writeTestFile(t, filepath.Join(root, "translator.go"), "package translator\n")
	before, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "testdata", "discovery", "assembly-ledger"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "testdata", "discovery", "assembly-ledger", "manifest.json"), "{}\n")
	afterEvidence, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if afterEvidence != before {
		t.Fatal("assembly evidence changed semantic source fingerprint")
	}
	writeTestFile(t, filepath.Join(root, "translator.go"), "package changed\n")
	afterSource, err := collectDiscoverySemanticSourceSHA(root)
	if err != nil {
		t.Fatal(err)
	}
	if afterSource == before {
		t.Fatal("translator change did not invalidate assembly evidence")
	}
}

func TestAssemblyLedgerKeepsMissingReportsPending(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	if err := os.Remove(filepath.Join(reports, "shard-1.json")); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	got, err := readAssemblyLedger(output, progress.LedgerSHA256, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified || got.Complete || got.Passed != progress.Passed || got.Pending != progress.Pending {
		t.Fatalf("partial assembly ledger = %+v", got)
	}
	if got.Pending == 0 {
		t.Fatal("missing report did not leave any candidate pending")
	}
}

func TestAssemblyLedgerRejectsTamperedShard(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob(filepath.Join(output, "records", "*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("record shards = %v, %v", shards, err)
	}
	if err := os.WriteFile(shards[0], []byte(`{"module":"example.com/forged","version":"v1.0.0","status":"passed"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource); err == nil {
		t.Fatal("tampered record shard accepted")
	}
}

func TestAssemblyLedgerRefusesUnrecognizedExistingDirectory(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(output, "unrelated.txt")
	writeTestFile(t, marker, "keep me\n")
	if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err == nil {
		t.Fatal("overwrote an unrecognized directory")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep me\n" {
		t.Fatalf("unrecognized directory was modified: %q, %v", data, err)
	}
}

func TestAssemblyLedgerRefusesBroadDestination(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"/", t.TempDir(), filepath.Join(t.TempDir(), "ledger")} {
		if err := writeAssemblyLedger(output, progress, strings.Repeat("a", 64)); err == nil {
			t.Fatalf("accepted unsafe destination %q", output)
		}
	}
}

func TestAssemblyLedgerDestinationDoesNotOverlapScanInput(t *testing.T) {
	root := t.TempDir()
	scan := filepath.Join(root, "ledger")
	for _, output := range []string{
		scan,
		filepath.Join(scan, "assembly-ledger"),
		root,
	} {
		if err := validateAssemblyLedgerDestination(scan, output); err == nil {
			t.Fatalf("accepted overlapping destination %q", output)
		}
	}
	if err := validateAssemblyLedgerDestination(scan, filepath.Join(root, "assembly-ledger")); err != nil {
		t.Fatal(err)
	}
}
