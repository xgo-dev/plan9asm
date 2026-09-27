package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryProgressAccountsForPendingShards(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	targets := []string{"linux/amd64", "linux/arm64"}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.Complete || !progress.Verified || progress.Passed != 2 || progress.Pending != 0 || progress.PassedShards != 2 {
		t.Fatalf("complete progress = %+v", progress)
	}

	removed, err := readDiscoveryCorpusReport(filepath.Join(reports, "shard-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(reports, "shard-1.json")); err != nil {
		t.Fatal(err)
	}
	progress, err = collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Complete || progress.Verified || progress.ReportedShards != 1 || progress.Pending != removed.Selected {
		t.Fatalf("partial progress = %+v", progress)
	}
	if progress.CandidateTotal != progress.Passed+progress.NotApplicable+progress.Failed+progress.Pending {
		t.Fatalf("candidate funnel does not balance: %+v", progress)
	}
	if len(progress.PendingShards) != 1 || progress.PendingShards[0] != 1 {
		t.Fatalf("pending shards = %v", progress.PendingShards)
	}

	if err := os.Remove(filepath.Join(reports, "shard-0.json")); err != nil {
		t.Fatal(err)
	}
	progress, err = collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Complete || progress.Verified || progress.Pending != 2 || progress.Provenance != nil {
		t.Fatalf("untested inventory must stay pending: %+v", progress)
	}
	for _, candidate := range progress.Candidates {
		if candidate.Status != "pending" {
			t.Fatalf("untested candidate = %+v", candidate)
		}
	}
}

func TestDiscoveryProgressPreservesInvalidSourceSkipReasonInAssemblyLedger(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	path := filepath.Join(reports, "shard-1.json")
	report, err := readDiscoveryCorpusReport(path)
	if err != nil {
		t.Fatal(err)
	}
	result := &report.Results[0]
	result.Status = discoveryStatusSkippedInvalidSource
	result.Translations = 0
	result.InvalidSourceReason = "raw ARM64 word is invalid"
	result.InvalidSourceEvidence = []discoveryInvalidMachineCodeEvidence{{
		AsmFile: result.DiscoveredAsmFiles[0], SHA256: strings.Repeat("a", 64),
		SourceExpression: "WORD $0x09c961ce", Word: "0x09c961ce",
		Architecture: "arm64",
	}}
	report.Passed--
	report.Translations--
	report.SkippedInvalidSource++
	if err := writeDiscoveryCorpusReport(path, report); err != nil {
		t.Fatal(err)
	}
	repoRoot := t.TempDir()
	manifestPath := filepath.Join(repoRoot, "testdata", "corpus", "invalid-machine-code.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(discoveryInvalidMachineCodeManifest{
		SchemaVersion: 1,
		Skips: []discoveryInvalidMachineCodeSkip{{
			Module: result.Module, Version: result.Version,
			Reason: result.InvalidSourceReason, Evidence: result.InvalidSourceEvidence,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, manifestPath, string(manifest))
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.Verified || progress.SkippedInvalidSource != 1 || progress.Passed != 1 {
		t.Fatalf("invalid-source skip miscounted: %+v", progress)
	}
	snapshot := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("c", 64)
	if err := writeAssemblyLedger(snapshot, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(snapshot, progress.LedgerSHA256, semanticSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range restored.Candidates {
		if candidate.Status == discoveryStatusSkippedInvalidSource {
			if candidate.InvalidSourceReason != result.InvalidSourceReason || len(candidate.InvalidSourceEvidence) != 1 {
				t.Fatalf("skip reason/evidence lost: %+v", candidate)
			}
			report.Results[0].InvalidSourceReason = "unlisted reason"
			if err := writeDiscoveryCorpusReport(path, report); err != nil {
				t.Fatal(err)
			}
			if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2, repoRoot); err == nil {
				t.Fatal("report skip reason did not match pinned manifest")
			}
			return
		}
	}
	t.Fatal("missing skipped exact version in assembly ledger")
}

func TestDiscoveryProgressKeepsCheckpointedShardIncomplete(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	path := filepath.Join(reports, "shard-1.json")
	report, err := readDiscoveryCorpusReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if report.Selected < 2 {
		t.Fatal("fixture needs at least two candidates in shard 1")
	}
	report.Results = report.Results[:1]
	report.Selected = 1
	report.Passed = 1
	report.Translations = 1
	report.Partial = true
	if err := writeDiscoveryCorpusReport(path, report); err != nil {
		t.Fatal(err)
	}

	targets := []string{"linux/amd64", "linux/arm64"}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Complete || progress.Verified || progress.ReportedShards != 2 ||
		progress.Passed != 1 || progress.Pending != 1 || len(progress.PartialShards) != 1 ||
		progress.PartialShards[0] != 1 || len(progress.PendingShards) != 1 || progress.PendingShards[0] != 1 {
		t.Fatalf("checkpointed progress = %+v", progress)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, source); err == nil {
		t.Fatal("checkpointed shard passed the complete-coverage gate")
	}
	snapshot := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("c", 64)
	if err := writeAssemblyLedger(snapshot, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(snapshot, progress.LedgerSHA256, semanticSource)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Passed != 1 || restored.Pending != 1 || restored.Verified {
		t.Fatalf("snapshot promoted incomplete shard: %+v", restored)
	}
}

func TestDiscoveryProgressRejectsFullInventoryMarkedPartial(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	path := filepath.Join(reports, "shard-1.json")
	report, err := readDiscoveryCorpusReport(path)
	if err != nil {
		t.Fatal(err)
	}
	report.Partial = true
	if err := writeDiscoveryCorpusReport(path, report); err != nil {
		t.Fatal(err)
	}
	if _, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2); err == nil {
		t.Fatal("accepted contradictory complete/partial report")
	}
}

func TestDiscoveryProgressRetainsFailuresWithoutPassingGate(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	files, err := discoveryCorpusReportFiles(reports)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, file := range files {
		report, err := readDiscoveryCorpusReport(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Results) == 0 {
			continue
		}
		report.Results[0].Status = discoveryStatusFailed
		report.Results[0].Error = "unsupported instruction"
		report.Passed--
		report.Failed++
		if err := writeDiscoveryCorpusReport(file, report); err != nil {
			t.Fatal(err)
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("fixture contains no candidate")
	}
	targets := []string{"linux/amd64", "linux/arm64"}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.Complete || progress.Verified || progress.Failed != 1 || progress.Pending != 0 || progress.FailedShards != 1 {
		t.Fatalf("failed progress = %+v", progress)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, source); err == nil {
		t.Fatal("progress reporting must not weaken the final passing gate")
	}
}

func TestDiscoveryProgressRejectsUnauditableReports(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*discoveryCorpusReport)
		want   string
	}{
		{
			name: "stale source",
			mutate: func(r *discoveryCorpusReport) {
				r.Provenance.Source.Revision = strings.Repeat("b", 40)
			},
			want: "provenance",
		},
		{
			name: "stale ledger",
			mutate: func(r *discoveryCorpusReport) {
				r.Provenance.LedgerSHA256 = strings.Repeat("b", 64)
			},
			want: "provenance",
		},
		{
			name: "dirty",
			mutate: func(r *discoveryCorpusReport) {
				r.Provenance.Source.Dirty = true
			},
			want: "provenance",
		},
		{
			name: "filtered",
			mutate: func(r *discoveryCorpusReport) {
				r.TargetFiltered = true
			},
			want: "target-filtered",
		},
		{
			name: "missing target",
			mutate: func(r *discoveryCorpusReport) {
				r.Targets = r.Targets[:1]
			},
			want: "targets",
		},
		{
			name: "wrong shard count",
			mutate: func(r *discoveryCorpusReport) {
				r.ShardCount++
			},
			want: "shard_count",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			file := filepath.Join(reports, "shard-0.json")
			report, err := readDiscoveryCorpusReport(file)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&report)
			if err := writeDiscoveryCorpusReport(file, report); err != nil {
				t.Fatal(err)
			}
			_, err = collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestDiscoveryProgressRejectsInvalidResultCounts(t *testing.T) {
	for _, translations := range []int{-1, 0} {
		ledger, reports, source := writeDiscoveryReportFixture(t)
		files, err := discoveryCorpusReportFiles(reports)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			report, err := readDiscoveryCorpusReport(file)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Results) == 0 {
				continue
			}
			report.Translations += translations - report.Results[0].Translations
			report.Results[0].Translations = translations
			if err := writeDiscoveryCorpusReport(file, report); err != nil {
				t.Fatal(err)
			}
			_, err = collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
			if err == nil {
				t.Errorf("accepted passed candidate with %d translations", translations)
			}
			break
		}
	}
}

func TestDiscoveryProgressRejectsMissingCandidateWithinReportedShard(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	files, err := discoveryCorpusReportFiles(reports)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		report, err := readDiscoveryCorpusReport(file)
		if err != nil {
			t.Fatal(err)
		}
		if report.Selected == 0 {
			continue
		}
		report.Results = report.Results[1:]
		report.Selected--
		report.Passed--
		report.Translations--
		if err := writeDiscoveryCorpusReport(file, report); err != nil {
			t.Fatal(err)
		}
		_, err = collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
		if err == nil || !strings.Contains(err.Error(), "shard inventory") {
			t.Fatalf("omitted candidate error = %v", err)
		}
		return
	}
	t.Fatal("fixture contains no candidate")
}

func TestDiscoveryCorpusReportAtomicPublication(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shard-0.json")
	report := discoveryCorpusReport{
		Results: []discoveryCorpusResult{{Error: strings.Repeat("diagnostic ", 100000)}},
	}
	if err := writeDiscoveryCorpusReport(file, report); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 16; i++ {
			if err := writeDiscoveryCorpusReport(file, report); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	var readErr error
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if readErr != nil {
				t.Fatalf("progress reader saw partially published report: %v", readErr)
			}
			return
		default:
			if _, err := readDiscoveryCorpusReport(file); err != nil && readErr == nil {
				readErr = err
			}
		}
	}
}

func TestDiscoveryProgressRejectsContradictoryOutcomes(t *testing.T) {
	for _, outcome := range []string{"not_applicable_with_translations", "not_applicable_without_reason", "failed_without_error", "passed_with_error"} {
		t.Run(outcome, func(t *testing.T) {
			ledger, reports, source := writeDiscoveryReportFixture(t)
			files, err := discoveryCorpusReportFiles(reports)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				report, err := readDiscoveryCorpusReport(file)
				if err != nil {
					t.Fatal(err)
				}
				if len(report.Results) == 0 {
					continue
				}
				result := &report.Results[0]
				switch outcome {
				case "not_applicable_with_translations", "not_applicable_without_reason":
					result.Status = discoveryStatusNotApplicable
					report.Passed--
					report.NotApplicable++
					if outcome == "not_applicable_without_reason" {
						report.Translations -= result.Translations
						result.Translations = 0
					} else {
						result.NotApplicableReason = "no applicable sources"
					}
				case "failed_without_error":
					result.Status = discoveryStatusFailed
					report.Passed--
					report.Failed++
				case "passed_with_error":
					result.Error = "LLVM compilation failed"
				}
				if err := writeDiscoveryCorpusReport(file, report); err != nil {
					t.Fatal(err)
				}
				_, err = collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
				if err == nil {
					t.Fatalf("accepted contradictory outcome %s", outcome)
				}
				return
			}
			t.Fatal("fixture contains no candidate")
		})
	}
}

func TestDiscoveryProgressCountsSourceNotApplicableSeparately(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	files, err := discoveryCorpusReportFiles(reports)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		report, err := readDiscoveryCorpusReport(file)
		if err != nil {
			t.Fatal(err)
		}
		report.NotApplicable = report.Passed
		report.Passed, report.Translations = 0, 0
		for i := range report.Results {
			result := &report.Results[i]
			result.Status = discoveryStatusNotApplicable
			result.Translations = 0
			result.NotApplicableReason = "current Go rejects the exact package"
			result.SourceNotApplicableItems = []discoverySourceNotApplicableItem{{
				AsmFiles: result.DiscoveredAsmFiles,
				Targets:  report.Targets,
				Kind:     discoverySourceNotApplicableGoBuild,
				Reason:   "current Go compiler rejection",
			}}
		}
		if err := writeDiscoveryCorpusReport(file, report); err != nil {
			t.Fatal(err)
		}
	}
	targets := []string{"linux/amd64", "linux/arm64"}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.Complete || !progress.Verified || progress.NotApplicable != 2 || progress.Passed != 0 || progress.Translations != 0 {
		t.Fatalf("source N/A must not become compiled candidates: %+v", progress)
	}
	if err := verifyDiscoveryCorpusReports(ledger, reports, targets, source); err != nil {
		t.Fatalf("valid source N/A rejected: %v", err)
	}
}
