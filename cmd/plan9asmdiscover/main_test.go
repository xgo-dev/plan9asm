package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEscapeProxyPath(t *testing.T) {
	got, err := escapeProxyPath("github.com/Azure/azure-sdk-for-go")
	if err != nil {
		t.Fatal(err)
	}
	if want := "github.com/!azure/azure-sdk-for-go"; got != want {
		t.Fatalf("escapeProxyPath() = %q, want %q", got, want)
	}
}

func TestValidateConfigRejectsNonPositiveHTTPTimeout(t *testing.T) {
	err := validateConfig(config{
		indexURL:    defaultIndexURL,
		proxyURL:    defaultProxyURL,
		scanMode:    scanModeHistory,
		before:      "2026-09-15T00:00:00Z",
		after:       indexEpoch,
		workers:     1,
		maxZipSize:  1,
		httpTimeout: 0,
	})
	if err == nil {
		t.Fatal("validateConfig() accepted a non-positive HTTP timeout")
	}
}

func TestIncrementalScanIgnoresHistoryBatchLimit(t *testing.T) {
	if got := scanLimit(scanModeIncremental, defaultScanLimit); got != 0 {
		t.Fatalf("incremental scan limit = %d, want complete head interval", got)
	}
	if got := scanLimit(scanModeHistory, 123); got != 123 {
		t.Fatalf("history scan limit = %d, want requested 123", got)
	}
}

func TestSeenReportsRecordOnlyCompletedExactVersions(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "previous.json")
	data, err := json.Marshal(discoveryReport{
		SchemaVersion: 1,
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v1.0.0"},
			{Path: "example.com/noasm", Version: "v2.0.0"},
		},
		Matched: []candidate{{Module: "example.com/old-match", Version: "v3.0.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	seen, err := loadSeenReports([]string{reportPath})
	if err != nil {
		t.Fatal(err)
	}
	wantSeen := []moduleVersion{
		{Path: "example.com/a", Version: "v1.0.0"},
		{Path: "example.com/noasm", Version: "v2.0.0"},
		{Path: "example.com/old-match", Version: "v3.0.0"},
	}
	for _, item := range wantSeen {
		if _, ok := seen[scanKey(item)]; !ok {
			t.Errorf("completed version is not recorded: %s@%s", item.Path, item.Version)
		}
	}
	for _, item := range []moduleVersion{
		{Path: "example.com/a", Version: "v1.1.0"},
		{Path: "example.com/new", Version: "v1.0.0"},
	} {
		if _, ok := seen[scanKey(item)]; ok {
			t.Errorf("unscanned exact version is recorded: %s@%s", item.Path, item.Version)
		}
	}
}

func TestSeenReportsReadCompressedLedger(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "scan-ledger.json.gz")
	file, err := os.Create(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(file)
	if err := json.NewEncoder(zw).Encode(discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned: []moduleVersion{
			{Path: "example.com/with-asm", Version: "v1.0.0"},
			{Path: "example.com/without-asm", Version: "v2.0.0"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	seen, err := loadSeenReports([]string{reportPath})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []moduleVersion{
		{Path: "example.com/with-asm", Version: "v1.0.0"},
		{Path: "example.com/without-asm", Version: "v2.0.0"},
	} {
		if _, ok := seen[scanKey(item)]; !ok {
			t.Errorf("compressed ledger omitted %s@%s", item.Path, item.Version)
		}
	}
}

func TestLoadSeenReportsPreservesMatchAcrossReportOrder(t *testing.T) {
	dir := t.TempDir()
	item := candidate{
		Module: "example.com/asm", Version: "v1.0.0",
		Architectures: []string{"amd64"}, AsmFiles: []string{"asm_amd64.s"},
	}
	paths := []string{filepath.Join(dir, "matched.json"), filepath.Join(dir, "scanned.json")}
	for i, report := range []discoveryReport{
		{SchemaVersion: discoverySchema, Matched: []candidate{item}},
		{SchemaVersion: discoverySchema, Scanned: []moduleVersion{{Path: item.Module, Version: item.Version}}},
	} {
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths[i], data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seen, err := loadSeenReports(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got := seen[scanKey(moduleVersion{Path: item.Module, Version: item.Version})].Match; !reflect.DeepEqual(got, item) {
		t.Fatalf("later scanned-only report erased assembly metadata: %#v", got)
	}
}

func TestLoadSeenReportsIndexesGitHubPseudoVersionCaseAliases(t *testing.T) {
	version := "v0.0.0-20260914132724-051eaffddbc5"
	reportPath := filepath.Join(t.TempDir(), "seen.json")
	data, err := json.Marshal(discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "github.com/L2Beat/l2beat", Version: version}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	seen, sourceSeen, err := loadSeenState([]string{reportPath})
	if err != nil {
		t.Fatal(err)
	}
	alias := moduleVersion{Path: "github.com/l2beat/l2beat", Version: version}
	if key := sourceScanKey(alias); key == "" {
		t.Fatal("sourceScanKey() did not recognize GitHub pseudo-version")
	} else if _, ok := sourceSeen[key]; !ok {
		t.Fatalf("seen report did not index case-insensitive repository source key %q", key)
	}
	if len(seen) != 1 {
		t.Fatalf("source aliases polluted exact-version checkpoint count: %d", len(seen))
	}
	if key := sourceScanKey(moduleVersion{Path: "github.com/l2beat/l2beat", Version: "v1.2.3"}); key != "" {
		t.Fatalf("sourceScanKey() unsafely reused mutable semantic tag as %q", key)
	}
	if a, b := sourceScanKey(alias), sourceScanKey(moduleVersion{Path: "github.com/L2BEAT/l2beat", Version: version}); a != b {
		t.Fatalf("GitHub owner/repository case aliases differ: %q != %q", a, b)
	}
	if a, b := sourceScanKey(
		moduleVersion{Path: "github.com/l2beat/l2beat/Sub", Version: version},
	), sourceScanKey(moduleVersion{Path: "github.com/l2beat/l2beat/sub", Version: version}); a == b {
		t.Fatalf("sourceScanKey() folded case-sensitive module subdirectory: %q", a)
	}
}

func TestShardedReportRoundTripIsDeterministic(t *testing.T) {
	report := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC),
		ScanDirection: "bidirectional",
		IndexRanges: []indexRange{{
			Since: "2019-04-10T00:00:00Z", Before: "2019-04-11T00:00:00Z", IndexEntries: 3,
		}},
		IndexEntries:  3,
		UniqueModules: 3,
		Scanned: []moduleVersion{
			{Path: "example.com/noasm", Version: "v2.0.0"},
			{Path: "example.com/asm", Version: "v1.0.0"},
		},
		Matched: []candidate{{
			Module:        "example.com/asm",
			Version:       "v1.0.0",
			Architectures: []string{"arm64", "amd64"},
			AsmFiles:      []string{"z_arm64.s", "a_amd64.s"},
		}},
		Failures: []scanFailure{{
			Module: "example.com/broken", Version: "v3.0.0", Error: "missing ZIP",
		}},
	}

	dir1 := filepath.Join(t.TempDir(), "run-one")
	if err := writeShardedReport(dir1, report); err != nil {
		t.Fatal(err)
	}
	reordered := report
	reordered.Scanned = append([]moduleVersion(nil), report.Scanned...)
	reordered.Scanned[0], reordered.Scanned[1] = reordered.Scanned[1], reordered.Scanned[0]
	dir2 := filepath.Join(t.TempDir(), "run-two")
	if err := writeShardedReport(dir2, reordered); err != nil {
		t.Fatal(err)
	}

	files1 := readDirectoryFiles(t, dir1)
	files2 := readDirectoryFiles(t, dir2)
	if !reflect.DeepEqual(files1, files2) {
		t.Fatalf("sharded output depends on input order\nfirst: %#v\nsecond: %#v", files1, files2)
	}
	if _, ok := files1["manifest.json"]; !ok {
		t.Fatal("sharded output has no manifest.json")
	}
	for name, data := range files1 {
		if strings.HasSuffix(name, ".gz") {
			t.Fatalf("sharded output contains opaque gzip file %q", name)
		}
		if strings.HasPrefix(name, "records/") && !bytes.HasSuffix(data, []byte("\n")) {
			t.Errorf("JSONL shard %q has no trailing newline", name)
		}
	}

	loaded, err := readSeenReport(dir1)
	if err != nil {
		t.Fatal(err)
	}
	sortDiscoveryReport(&report)
	if !reflect.DeepEqual(loaded, report) {
		t.Fatalf("round trip = %#v, want %#v", loaded, report)
	}

	hash := sha256.Sum256([]byte("example.com/asm"))
	wantShard := fmt.Sprintf("records/%02x.jsonl", hash[0])
	if _, ok := files1[wantShard]; !ok {
		t.Fatalf("module was not written to stable shard %q; files: %#v", wantShard, files1)
	}
}

func TestShardedLedgerUpdateReplacesOlderModuleVersions(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	initial := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC),
		ScanDirection: "bidirectional",
		IndexRanges: []indexRange{{
			Since: "2026-09-01T00:00:00Z", Before: "2026-09-02T00:00:00Z", IndexEntries: 10,
		}},
		IndexEntries: 10,
		Skipped:      3,
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v1.9.0"},
			{Path: "example.com/a", Version: "v1.10.0-rc.1"},
		},
		Matched: []candidate{{
			Module: "example.com/a", Version: "v1.9.0",
			Architectures: []string{"amd64"}, AsmFiles: []string{"old_amd64.s"},
		}},
		Failures: []scanFailure{{Module: "example.com/a", Version: "v1.10.0", Error: "temporary proxy failure"}},
	}
	if err := writeShardedReport(ledger, initial); err != nil {
		t.Fatal(err)
	}
	update := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
		ScanDirection: "bidirectional",
		IndexRanges: []indexRange{{
			Since: "2026-08-31T00:00:00Z", Before: "2026-09-01T00:00:00Z", IndexEntries: 11,
		}},
		IndexEntries: 11,
		Skipped:      4,
		Scanned:      []moduleVersion{{Path: "example.com/a", Version: "v1.10.0"}},
		Matched: []candidate{{
			Module: "example.com/a", Version: "v1.10.0",
			Architectures: []string{"arm64"}, AsmFiles: []string{"new_arm64.s"},
		}},
	}
	if err := writeShardedReport(ledger, update); err != nil {
		t.Fatal(err)
	}

	report, err := readSeenReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	wantScanned := []moduleVersion{{Path: "example.com/a", Version: "v1.10.0"}}
	if !reflect.DeepEqual(report.Scanned, wantScanned) {
		t.Fatalf("scanned versions = %#v, want only current latest %#v", report.Scanned, wantScanned)
	}
	if len(report.Matched) != 1 || report.Matched[0].Version != "v1.10.0" || len(report.Failures) != 0 {
		t.Fatalf("updated ledger retained an obsolete version or completed failure: %#v", report)
	}
	if report.IndexEntries != 21 || report.UniqueModules != 1 {
		t.Fatalf("updated ledger counts = index %d, modules %d; want 21, 1", report.IndexEntries, report.UniqueModules)
	}
	if earliestIndexRangeLower(report.IndexRanges) != "2026-08-31T00:00:00Z" || latestIndexRangeUpper(report.IndexRanges) != "2026-09-02T00:00:00Z" || len(report.IndexRanges) != 2 {
		t.Fatalf("derived dual scan cursors are inconsistent with ranges %#v", report.IndexRanges)
	}
	if report.Skipped != 7 {
		t.Fatalf("skipped count = %d, want 7 across disjoint ranges", report.Skipped)
	}
	files := readDirectoryFiles(t, ledger)
	for name := range files {
		if strings.HasPrefix(name, "runs/") {
			t.Fatalf("updated ledger created a per-run path %q", name)
		}
	}
	hash := sha256.Sum256([]byte("example.com/a"))
	shardName := fmt.Sprintf("records/%02x.jsonl", hash[0])
	shard := string(files[shardName])
	if strings.Contains(shard, `"version":"v1.9.0"`) || strings.Contains(shard, `"version":"v1.10.0-rc.1"`) {
		t.Fatalf("record shard retained obsolete module versions:\n%s", shard)
	}
	beforeRerun := readDirectoryFiles(t, ledger)
	if err := writeShardedReport(ledger, update); err != nil {
		t.Fatal(err)
	}
	afterRerun := readDirectoryFiles(t, ledger)
	if !reflect.DeepEqual(afterRerun, beforeRerun) {
		t.Fatal("rerunning an identical reverse range changed the canonical ledger")
	}
}

func TestMergeDiscoveryReportsRejectsPartiallyOverlappingIndexRanges(t *testing.T) {
	_, err := mergeDiscoveryReports(
		discoveryReport{SchemaVersion: discoverySchema, IndexRanges: []indexRange{{
			Since: "2026-09-01T00:00:00Z", Before: "2026-09-03T00:00:00Z", IndexEntries: 20,
		}}},
		discoveryReport{SchemaVersion: discoverySchema, IndexRanges: []indexRange{{
			Since: "2026-09-02T00:00:00Z", Before: "2026-09-04T00:00:00Z", IndexEntries: 20,
		}}},
	)
	if err == nil {
		t.Fatal("mergeDiscoveryReports() accepted ranges whose aggregate count cannot be computed exactly")
	}
}

func TestMergeDiscoveryReportsRejectsGapBetweenDualCursors(t *testing.T) {
	_, err := mergeDiscoveryReports(
		discoveryReport{
			SchemaVersion: discoverySchema,
			IndexRanges: []indexRange{{
				Since: "2026-09-01T00:00:00Z", Before: "2026-09-02T00:00:00Z", IndexEntries: 20,
			}},
		},
		discoveryReport{
			SchemaVersion: discoverySchema,
			IndexRanges: []indexRange{{
				Since: "2026-09-03T00:00:00Z", Before: "2026-09-04T00:00:00Z", IndexEntries: 20,
			}},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "unverified gap") {
		t.Fatalf("mergeDiscoveryReports() error = %v, want dual-cursor gap rejection", err)
	}
}

func TestResolveScanWindowStartsEmptyLedgerAtCurrentTime(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	history, err := resolveScanWindow(&discoveryReport{}, scanModeHistory, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if history.Before != now.Format(time.RFC3339Nano) || history.After != indexEpoch {
		t.Fatalf("empty history window = %#v", history)
	}
	incremental, err := resolveScanWindow(&discoveryReport{}, scanModeIncremental, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if incremental.Before != now.Format(time.RFC3339Nano) || incremental.After != incremental.Before {
		t.Fatalf("empty incremental window = %#v", incremental)
	}
}

func TestEmptyIncrementalScanPersistsStableCursorAnchor(t *testing.T) {
	anchor := "2026-09-15T12:00:00Z"
	report, err := discover(context.Background(), http.DefaultClient, config{
		indexURL:    "https://index.invalid/index",
		proxyURL:    "https://proxy.invalid",
		scanMode:    scanModeIncremental,
		before:      anchor,
		after:       anchor,
		limit:       0,
		workers:     1,
		maxZipSize:  1,
		httpTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRanges := []indexRange{{Since: anchor, Before: anchor, IndexEntries: 0}}
	if !reflect.DeepEqual(report.IndexRanges, wantRanges) {
		t.Fatalf("empty incremental ranges = %#v, want stable anchor %#v", report.IndexRanges, wantRanges)
	}
	ledger := filepath.Join(t.TempDir(), "ledger")
	if err := writeShardedReport(ledger, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := readShardedReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	next, err := resolveScanWindow(&loaded, scanModeIncremental, "", time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if next.After != anchor {
		t.Fatalf("incremental scan lost empty-ledger anchor: %#v", next)
	}
}

func TestResolveScanWindowRejectsHistoryCursorThatWouldLeaveGap(t *testing.T) {
	existing := discoveryReport{IndexRanges: []indexRange{{
		Since: "2026-09-14T00:00:00Z", Before: "2026-09-15T00:00:00Z", IndexEntries: 10,
	}}}
	_, err := resolveScanWindow(&existing, scanModeHistory, "2026-09-13T23:00:00Z", time.Now())
	if err == nil || !strings.Contains(err.Error(), "derived history cursor") {
		t.Fatalf("resolveScanWindow() error = %v, want gap prevention", err)
	}
}

func TestMergeDiscoveryReportsNewestExactFailureReplacesOlderSuccess(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
		Matched: []candidate{{
			Module: "example.com/a", Version: "v1.0.0", AsmFiles: []string{"old_amd64.s"},
		}},
	}
	update := discoveryReport{
		SchemaVersion: discoverySchema,
		Failures: []scanFailure{{
			Module: "example.com/a", Version: "v1.1.0", Error: "temporary proxy failure",
		}},
	}
	merged, err := mergeDiscoveryReports(base, update)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Scanned) != 0 || len(merged.Matched) != 0 {
		t.Fatalf("new latest failure retained obsolete successful version: %#v", merged)
	}
	wantFailure := update.Failures
	if !reflect.DeepEqual(merged.Failures, wantFailure) {
		t.Fatalf("failures = %#v, want %#v", merged.Failures, wantFailure)
	}
}

func TestMergeDiscoveryReportsMajorUpgradeReplacesLowerModulePaths(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/lib/v2", Version: "v2.99.0"}},
		Matched: []candidate{{
			Module: "example.com/lib/v2", Version: "v2.99.0", AsmFiles: []string{"old_amd64.s"},
		}},
	}
	update := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.1.0"}},
		Matched: []candidate{{
			Module: "example.com/lib/v3", Version: "v3.1.0", AsmFiles: []string{"new_amd64.s"},
		}},
	}
	merged, err := mergeDiscoveryReports(base, update)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Scanned) != 1 || merged.Scanned[0].Path != "example.com/lib/v3" ||
		len(merged.Matched) != 1 || merged.Matched[0].Module != "example.com/lib/v3" {
		t.Fatalf("major upgrade retained lower module path: %#v", merged)
	}

	obsolete := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/lib/v2", Version: "v2.100.0"}},
	}
	merged, err = mergeDiscoveryReports(merged, obsolete)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Scanned) != 1 || merged.Scanned[0].Path != "example.com/lib/v3" ||
		len(merged.Matched) != 1 || merged.Matched[0].Module != "example.com/lib/v3" {
		t.Fatalf("later lower-major history record displaced v3: %#v", merged)
	}
}

func TestMergeDiscoveryReportsRetainsOnlyCurrentLatestResolutionFailure(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
	}
	failedResolution := discoveryReport{
		SchemaVersion: discoverySchema,
		Failures:      []scanFailure{{Module: "example.com/a", Version: "@latest", Error: "proxy unavailable"}},
	}
	merged, err := mergeDiscoveryReports(base, failedResolution)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Scanned) != 1 || !reflect.DeepEqual(merged.Failures, failedResolution.Failures) {
		t.Fatalf("latest resolution failure did not preserve retry and last exact result: %#v", merged)
	}
	success := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.1.0"}},
	}
	merged, err = mergeDiscoveryReports(merged, success)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged.Scanned, success.Scanned) || len(merged.Failures) != 0 {
		t.Fatalf("successful latest resolution retained obsolete records: %#v", merged)
	}
}

func TestMergeDiscoveryReportsPreservesUntouchedLatestResolutionFailure(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/a", Version: "v1.0.0"}},
		Failures:      []scanFailure{{Module: "example.com/a", Version: "@latest", Error: "proxy unavailable"}},
	}
	update := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned:       []moduleVersion{{Path: "example.com/b", Version: "v2.0.0"}},
	}
	merged, err := mergeDiscoveryReports(base, update)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged.Failures, base.Failures) {
		t.Fatalf("unrelated update discarded retryable @latest failure: %#v", merged)
	}
}

func TestSortDiscoveryReportUsesGoSemver(t *testing.T) {
	report := discoveryReport{Scanned: []moduleVersion{
		{Path: "example.com/a", Version: "v1.10.1-0.20260914000000-0123456789ab"},
		{Path: "example.com/a", Version: "v1.10.0+incompatible"},
		{Path: "example.com/a", Version: "v1.9.0"},
		{Path: "example.com/a", Version: "v1.10.0"},
		{Path: "example.com/a", Version: "v1.10.0-rc.1"},
	}}
	sortDiscoveryReport(&report)
	want := []string{
		"v1.9.0",
		"v1.10.0-rc.1",
		"v1.10.0",
		"v1.10.0+incompatible",
		"v1.10.1-0.20260914000000-0123456789ab",
	}
	for i, item := range report.Scanned {
		if item.Version != want[i] {
			t.Fatalf("semver order[%d] = %q, want %q; all: %#v", i, item.Version, want[i], report.Scanned)
		}
	}
}

func TestLoadSeenReportsAcceptsSingleLedgerDirectory(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	report := discoveryReport{
		SchemaVersion: discoverySchema,
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v1.0.0"},
			{Path: "example.com/b", Version: "v2.0.0"},
		},
	}
	if err := writeShardedReport(ledger, report); err != nil {
		t.Fatal(err)
	}
	seen, err := loadSeenReports([]string{ledger})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []moduleVersion{
		{Path: "example.com/a", Version: "v1.0.0"},
		{Path: "example.com/b", Version: "v2.0.0"},
	} {
		if _, ok := seen[scanKey(item)]; !ok {
			t.Errorf("ledger directory omitted %s@%s", item.Path, item.Version)
		}
	}
	loaded, err := readSeenReport(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Scanned) != 2 || len(loaded.Failures) != 0 || loaded.UniqueModules != 2 {
		t.Fatalf("ledger report was not normalized: %#v", loaded)
	}
}

func TestShardedReportRejectsInvalidOrUnsafeInput(t *testing.T) {
	t.Run("existing output without manifest", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeShardedReport(dir, discoveryReport{SchemaVersion: discoverySchema}); err == nil {
			t.Fatal("writeShardedReport() overwrote a directory that is not a ledger")
		}
	})

	t.Run("missing manifest", func(t *testing.T) {
		if _, err := readSeenReport(t.TempDir()); err == nil {
			t.Fatal("readSeenReport() accepted a directory without a manifest")
		}
	})

	tests := map[string]struct {
		manifest shardedManifest
		record   string
	}{
		"unsupported format": {
			manifest: shardedManifest{SchemaVersion: discoverySchema, Format: "unknown"},
		},
		"invalid JSONL": {
			manifest: shardedManifest{SchemaVersion: discoverySchema, Format: shardedFormat, Scanned: 1},
			record:   "not json\n",
		},
		"incomplete module": {
			manifest: shardedManifest{SchemaVersion: discoverySchema, Format: shardedFormat, Scanned: 1},
			record:   `{"kind":"scanned","module":"example.com/lib"}` + "\n",
		},
		"unknown kind": {
			manifest: shardedManifest{SchemaVersion: discoverySchema, Format: shardedFormat, Scanned: 1},
			record:   `{"kind":"mystery","module":"example.com/lib","version":"v1.0.0"}` + "\n",
		},
		"wrong count": {
			manifest: shardedManifest{SchemaVersion: discoverySchema, Format: shardedFormat, Scanned: 2},
			record:   `{"kind":"scanned","module":"example.com/lib","version":"v1.0.0"}` + "\n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			manifest, err := json.Marshal(test.manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.record != "" {
				if err := os.Mkdir(filepath.Join(dir, "records"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "records", "00.jsonl"), []byte(test.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readSeenReport(dir); err == nil {
				t.Fatal("readSeenReport() accepted an invalid sharded report")
			}
		})
	}
}

func TestShardedReportRefusesConcurrentLedgerWriter(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "ledger")
	release, err := acquireLedgerLock(ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()
	err = writeShardedReport(ledger, discoveryReport{SchemaVersion: discoverySchema})
	if err == nil || !strings.Contains(err.Error(), "another discovery writer") {
		t.Fatalf("writeShardedReport() with held lock error = %v", err)
	}
}

func readDirectoryFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSeenReportsRejectInvalidInput(t *testing.T) {
	tests := map[string][]byte{
		"invalid-json":        []byte("not json"),
		"invalid-gzip-header": {0x1f, 0x8b},
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte(`{"schema_version":2}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), compressed.Bytes()...)
	corrupt[len(corrupt)-1] ^= 0xff
	tests["invalid-gzip-checksum"] = corrupt

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			reportPath := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(reportPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSeenReports([]string{reportPath}); err == nil {
				t.Fatal("loadSeenReports() accepted invalid input")
			}
		})
	}

	if _, err := loadSeenReports([]string{filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("loadSeenReports() accepted a missing report")
	}
}

func TestCommittedScanLedger(t *testing.T) {
	reportPath := filepath.Join("..", "..", "testdata", "discovery", "ledger")
	err := filepath.WalkDir(filepath.Dir(reportPath), func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".gz") {
			t.Errorf("compressed discovery result must not be committed: %s", name)
		}
		if relative, relErr := filepath.Rel(reportPath, name); relErr == nil {
			relative = filepath.ToSlash(relative)
			if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
				return nil
			}
			parts := strings.Split(relative, "/")
			if parts[0] != "manifest.json" && parts[0] != "records" {
				t.Errorf("discovery ledger contains a per-run or unexpected path: %s", relative)
			}
			if len(parts) > 2 {
				t.Errorf("discovery ledger must have exactly one records directory: %s", relative)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := readSeenReport(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != discoverySchema {
		t.Fatalf("ledger schema = %d, want %d", report.SchemaVersion, discoverySchema)
	}
	if report.IndexEntries == 0 || len(report.Scanned) == 0 {
		t.Fatalf("ledger is empty: %d index entries, %d scanned versions", report.IndexEntries, len(report.Scanned))
	}
	if report.ScanDirection != "bidirectional" {
		t.Fatalf("ledger scan direction = %q, want bidirectional", report.ScanDirection)
	}
	historyBefore := earliestIndexRangeLower(report.IndexRanges)
	if _, err := time.Parse(time.RFC3339Nano, historyBefore); err != nil {
		t.Fatalf("invalid derived history ledger cursor %q: %v", historyBefore, err)
	}
	incrementalSince := latestIndexRangeUpper(report.IndexRanges)
	if _, err := time.Parse(time.RFC3339Nano, incrementalSince); err != nil {
		t.Fatalf("invalid derived incremental ledger cursor %q: %v", incrementalSince, err)
	}
	entries := 0
	for _, item := range report.IndexRanges {
		entries += item.IndexEntries
	}
	if entries != report.IndexEntries {
		t.Fatalf("ledger index ranges contain %d entries, want manifest total %d", entries, report.IndexEntries)
	}

	seen, err := loadSeenReports([]string{reportPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(report.Scanned) {
		t.Fatalf("ledger has %d unique completed versions, want %d", len(seen), len(report.Scanned))
	}
	for _, item := range report.Matched {
		key := scanKey(moduleVersion{Path: item.Module, Version: item.Version})
		if _, ok := seen[key]; !ok {
			t.Errorf("assembly match is not recorded as scanned: %s@%s", item.Module, item.Version)
		}
	}
	for _, item := range report.Failures {
		key := scanKey(moduleVersion{Path: item.Module, Version: item.Version})
		if _, ok := seen[key]; ok {
			t.Errorf("failed version must remain eligible for retry: %s@%s", item.Module, item.Version)
		}
	}

	issueMatches := map[string]candidate{}
	for _, item := range report.Matched {
		issueMatches[scanKey(moduleVersion{Path: item.Module, Version: item.Version})] = item
	}
	wantIssueFiles := map[string][]string{
		scanKey(moduleVersion{Path: "github.com/coder/websocket", Version: "v1.8.15"}): {
			"mask_amd64.s",
			"mask_arm64.s",
		},
		scanKey(moduleVersion{Path: "github.com/klauspost/compress", Version: "v1.20.0"}): {
			"huff0/decompress_amd64.s",
			"huff0/decompress_arm64.s",
			"internal/cpuinfo/cpuinfo_amd64.s",
			"s2/decode_amd64.s",
			"s2/decode_arm64.s",
			"s2/encodeblock_amd64.s",
			"s2/encodeblock_arm64.s",
			"zstd/fse_decoder_amd64.s",
			"zstd/fse_decoder_arm64.s",
			"zstd/internal/xxhash/xxhash_amd64.s",
			"zstd/internal/xxhash/xxhash_arm64.s",
			"zstd/matchlen_amd64.s",
			"zstd/seqdec_amd64.s",
			"zstd/seqdec_arm64.s",
		},
		scanKey(moduleVersion{Path: "github.com/tmthrgd/go-hex", Version: "v0.0.0-20190904060850-447a3041c3bc"}): {
			"hex_decode_amd64.s",
			"hex_encode_amd64.s",
		},
	}
	for exactKey, wantFiles := range wantIssueFiles {
		match, ok := issueMatches[exactKey]
		if !ok {
			t.Errorf("issue library version was not independently discovered: %s", strings.Replace(exactKey, "\x00", "@", 1))
			continue
		}
		if !reflect.DeepEqual(match.AsmFiles, wantFiles) {
			t.Errorf("discovered assembly for %s = %#v, want %#v", strings.Replace(exactKey, "\x00", "@", 1), match.AsmFiles, wantFiles)
		}
	}
}

func TestInspectModulesRecordsLatestVersionWhenInspectionFails(t *testing.T) {
	archive := testModuleZip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.1.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			serveRangeData(t, w, r, archive)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.1.0.zip"):
			http.Error(w, "missing", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	matched, failures, scanned, skipped := inspectModules(context.Background(), server.Client(), server.URL, []moduleVersion{
		{Path: "example.com/lib", Version: "v1.0.0"},
	}, nil, nil, 1, int64(len(archive))+1)
	if len(matched) != 0 || len(failures) != 1 {
		t.Fatalf("inspectModules() matched %d and failed %d modules, want 0 and 1", len(matched), len(failures))
	}
	if len(scanned) != 0 {
		t.Fatalf("scanned versions = %#v, want none", scanned)
	}
	if failures[0].Module != "example.com/lib" || failures[0].Version != "v1.1.0" {
		t.Fatalf("failure version = %#v, want exact latest version", failures[0])
	}
	if skipped != 0 {
		t.Fatalf("skipped versions = %d, want 0", skipped)
	}
}

func TestInspectModulesRecordsLatestResolutionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	matched, failures, scanned, skipped := inspectModules(context.Background(), server.Client(), server.URL, []moduleVersion{
		{Path: "example.com/lib", Version: "v1.0.0"},
	}, nil, nil, 1, 1<<20)
	if len(matched) != 0 || len(scanned) != 0 || skipped != 0 || len(failures) != 1 {
		t.Fatalf("unexpected result: matched=%#v failures=%#v scanned=%#v skipped=%d", matched, failures, scanned, skipped)
	}
	if failures[0].Version != "@latest" || failures[0].Error != "decode @latest: missing Version" {
		t.Fatalf("resolution failure = %#v", failures[0])
	}
}

func TestInspectModulesSkipsPreviouslyCompletedLatestVersion(t *testing.T) {
	archive := testModuleZip(t)
	var latestZipRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.1.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			serveRangeData(t, w, r, archive)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.1.0.zip"):
			latestZipRequests.Add(1)
			serveRangeData(t, w, r, archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	latest := moduleVersion{Path: "example.com/lib", Version: "v1.1.0"}
	priorMatch := candidate{
		Module: latest.Path, Version: latest.Version,
		Architectures: []string{"amd64"}, AsmFiles: []string{"asm_amd64.s"},
	}
	collector := newTrafficCollector()
	ctx := context.WithValue(context.Background(), trafficCollectorContextKey{}, collector)
	matched, failures, scanned, skipped := inspectModules(ctx, server.Client(), server.URL, []moduleVersion{
		{Path: "example.com/lib", Version: "v1.0.0"},
	}, map[string]seenResult{scanKey(latest): {Match: priorMatch}}, nil, 1, int64(len(archive))+1)
	if !reflect.DeepEqual(matched, []candidate{priorMatch}) || len(failures) != 0 {
		t.Fatalf("inspectModules() matched %#v and failed %d modules, want reused match", matched, len(failures))
	}
	wantScanned := []moduleVersion{latest}
	if !reflect.DeepEqual(scanned, wantScanned) {
		t.Fatalf("scanned versions = %#v, want reused latest checkpoint %#v", scanned, wantScanned)
	}
	if got := latestZipRequests.Load(); got != 0 {
		t.Fatalf("previously completed latest version fetched %d times, want 0", got)
	}
	if skipped != 1 {
		t.Fatalf("skipped versions = %d, want 1", skipped)
	}
	report := collector.snapshot(time.Unix(0, 0).UTC(), scanModeHistory, discoveryReport{})
	if len(report.Modules) != 1 || report.Modules[0].Outcome != "reused_matched" {
		t.Fatalf("reused match traffic outcome = %#v, want reused_matched", report.Modules)
	}
}

func TestInspectModulesReusesGitHubPseudoVersionCaseAlias(t *testing.T) {
	version := "v0.0.0-20260914132724-051eaffddbc5"
	var zipRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			_, _ = fmt.Fprintf(w, `{"Version":%q}`, version)
			return
		}
		zipRequests.Add(1)
		http.Error(w, "ZIP must be reused", http.StatusInternalServerError)
	}))
	defer server.Close()

	upper := moduleVersion{Path: "github.com/L2Beat/l2beat", Version: version}
	lower := moduleVersion{Path: "github.com/l2beat/l2beat", Version: version}
	prior := candidate{Module: upper.Path, Version: version, AsmFiles: []string{"asm_amd64.s"}}
	sourceSeen := map[string]seenResult{sourceScanKey(upper): {Match: prior}}
	matched, failures, scanned, skipped := inspectModules(
		context.Background(), server.Client(), server.URL,
		[]moduleVersion{lower}, nil, sourceSeen, 1, 1<<20,
	)
	wantMatch := prior
	wantMatch.Module = lower.Path
	if !reflect.DeepEqual(matched, []candidate{wantMatch}) || len(failures) != 0 || !reflect.DeepEqual(scanned, []moduleVersion{lower}) || skipped != 1 {
		t.Fatalf("case-alias reuse = matched %#v failures %#v scanned %#v skipped %d", matched, failures, scanned, skipped)
	}
	if got := zipRequests.Load(); got != 0 {
		t.Fatalf("case-alias pseudo-version fetched ZIP %d times, want 0", got)
	}
}

func TestInspectModulesCoalescesConcurrentGitHubPseudoVersionCaseAliases(t *testing.T) {
	version := "v0.0.0-20260914132724-051eaffddbc5"
	archive := testModuleZip(t)
	var latestRequests atomic.Int64
	var zipRequests atomic.Int64
	latestReady := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			if latestRequests.Add(1) == 2 {
				close(latestReady)
			}
			<-latestReady
			_, _ = fmt.Fprintf(w, `{"Version":%q}`, version)
			return
		}
		zipRequests.Add(1)
		serveRangeData(t, w, r, archive)
	}))
	defer server.Close()

	collector := newTrafficCollector()
	ctx := context.WithValue(context.Background(), trafficCollectorContextKey{}, collector)
	modules := []moduleVersion{
		{Path: "github.com/L2Beat/l2beat", Version: version},
		{Path: "github.com/l2beat/l2beat", Version: version},
	}
	matched, failures, scanned, skipped := inspectModules(
		ctx, server.Client(), server.URL, modules, nil, nil, 2, int64(len(archive))+1,
	)
	if len(matched) != 2 || len(failures) != 0 || len(scanned) != 2 || skipped != 1 {
		t.Fatalf("concurrent alias result = matched %d failures %d scanned %d skipped %d", len(matched), len(failures), len(scanned), skipped)
	}
	if got := zipRequests.Load(); got != 2 {
		t.Fatalf("concurrent aliases made %d ZIP requests, want one HEAD and one body request", got)
	}
	report := collector.snapshot(time.Unix(0, 0).UTC(), scanModeHistory, discoveryReport{})
	var outcomes []string
	for _, item := range report.Modules {
		outcomes = append(outcomes, item.Outcome)
	}
	sort.Strings(outcomes)
	if want := []string{"matched", "reused_matched"}; !reflect.DeepEqual(outcomes, want) {
		t.Fatalf("concurrent alias outcomes = %#v, want %#v", outcomes, want)
	}
}

func TestInspectModulesChecksLatestWhenIndexedVersionHasNoAssembly(t *testing.T) {
	var noAsm bytes.Buffer
	zw := zip.NewWriter(&noAsm)
	file, err := zw.Create("example.com/lib@v1.0.0/lib.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("package lib\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	latestArchive := testModuleZip(t)
	var indexedZipRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.1.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			indexedZipRequests.Add(1)
			serveRangeData(t, w, r, noAsm.Bytes())
		case strings.HasSuffix(r.URL.Path, "/@v/v1.1.0.zip"):
			serveRangeData(t, w, r, latestArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	matched, failures, scanned, skipped := inspectModules(context.Background(), server.Client(), server.URL, []moduleVersion{
		{Path: "example.com/lib", Version: "v1.0.0"},
	}, nil, nil, 1, int64(len(latestArchive))+1)
	if len(failures) != 0 {
		t.Fatalf("inspectModules() failures = %#v", failures)
	}
	wantScanned := []moduleVersion{{Path: "example.com/lib", Version: "v1.1.0"}}
	if !reflect.DeepEqual(scanned, wantScanned) {
		t.Fatalf("scanned versions = %#v, want %#v", scanned, wantScanned)
	}
	if len(matched) != 1 || matched[0].Module != "example.com/lib" || matched[0].Version != "v1.1.0" {
		t.Fatalf("matched versions = %#v, want latest module version", matched)
	}
	if got := indexedZipRequests.Load(); got != 0 {
		t.Fatalf("indexed archive fetched %d times, want 0; index should only discover module paths", got)
	}
	if skipped != 0 {
		t.Fatalf("skipped versions = %d, want 0", skipped)
	}
}

func TestDiscoverDoesNotTreatAnIndexedVersionAsTheLatestCheckpoint(t *testing.T) {
	archive := testModuleZip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/index":
			_ = json.NewEncoder(w).Encode(indexEntry{
				Path:      "example.com/lib",
				Version:   "v1.0.0",
				Timestamp: time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC),
			})
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.1.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.1.0.zip"):
			serveRangeData(t, w, r, archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, err := discover(context.Background(), server.Client(), config{
		indexURL:    server.URL + "/index",
		proxyURL:    server.URL,
		scanMode:    scanModeHistory,
		before:      time.Date(2019, 4, 10, 0, 0, 1, 0, time.UTC).Format(time.RFC3339Nano),
		after:       indexEpoch,
		limit:       1,
		workers:     1,
		maxZipSize:  int64(len(archive)) + 1,
		httpTimeout: time.Second,
		seen: map[string]seenResult{
			scanKey(moduleVersion{Path: "example.com/lib", Version: "v1.0.0"}): {},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []moduleVersion{{Path: "example.com/lib", Version: "v1.1.0"}}
	if !reflect.DeepEqual(report.Scanned, want) {
		t.Fatalf("scanned versions = %#v, want latest %#v", report.Scanned, want)
	}
}

func TestModulesNeedingInspectionSkipsOlderIndexedVersionsByModule(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.com/already", Version: "v1.0.0"},
		{Path: "example.com/already", Version: "v1.1.0"},
		{Path: "example.com/new-release", Version: "v1.2.0"},
		{Path: "example.com/retry-separately", Version: "v9.0.0"},
		{Path: "example.com/unseen", Version: "v0.1.0"},
	}
	checkpoints := map[string]moduleCheckpoint{
		"example.com/already":          {Path: "example.com/already", Version: "v1.1.0"},
		"example.com/new-release":      {Path: "example.com/new-release", Version: "v1.1.0"},
		"example.com/retry-separately": {Path: "example.com/retry-separately", Version: "@latest"},
	}
	got, skipped := modulesNeedingInspection(entries, checkpoints)
	want := []moduleVersion{
		{Path: "example.com/new-release", Version: "v1.2.0"},
		{Path: "example.com/unseen", Version: "v0.1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesNeedingInspection() = %#v, want %#v", got, want)
	}
	if skipped != 2 {
		t.Fatalf("skipped module paths = %d, want 2", skipped)
	}
}

func TestModulesNeedingInspectionKeepsOnlyHighestModulePathMajor(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.com/lib/v2", Version: "v2.9.0"},
		{Path: "example.com/lib", Version: "v1.10.0"},
		{Path: "example.com/lib/v3", Version: "v3.1.0"},
		{Path: "gopkg.in/yaml.v2", Version: "v2.4.0"},
		{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"},
	}
	got, skipped := modulesNeedingInspection(entries, nil)
	want := []moduleVersion{
		{Path: "example.com/lib/v3", Version: "v3.1.0"},
		{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesNeedingInspection() = %#v, want only highest majors %#v", got, want)
	}
	if skipped != 3 {
		t.Fatalf("skipped obsolete major paths = %d, want 3", skipped)
	}
}

func TestModulesNeedingInspectionOrdersByMajorThenSemverAcrossHistory(t *testing.T) {
	checkpoints := map[string]moduleCheckpoint{}

	first, _ := modulesNeedingInspection([]indexEntry{
		{Path: "example.com/lib/v2", Version: "v2.9.0"},
	}, checkpoints)
	if want := []moduleVersion{{Path: "example.com/lib/v2", Version: "v2.9.0"}}; !reflect.DeepEqual(first, want) {
		t.Fatalf("first history window = %#v, want %#v", first, want)
	}
	chooseModuleCheckpoint(checkpoints, first[0].Path, first[0].Version)

	// This v3 index record is older than the v2 record above, but the module
	// path major has priority over both index time and the v2 semver.
	second, _ := modulesNeedingInspection([]indexEntry{
		{Path: "example.com/lib/v3", Version: "v3.1.0"},
	}, checkpoints)
	if want := []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.1.0"}}; !reflect.DeepEqual(second, want) {
		t.Fatalf("older history window = %#v, want major upgrade %#v", second, want)
	}
	chooseModuleCheckpoint(checkpoints, second[0].Path, second[0].Version)

	obsolete, _ := modulesNeedingInspection([]indexEntry{
		{Path: "example.com/lib", Version: "v1.99.0"},
		{Path: "example.com/lib/v2", Version: "v2.99.0"},
		{Path: "example.com/lib/v3", Version: "v3.0.0"},
	}, checkpoints)
	if len(obsolete) != 0 {
		t.Fatalf("later history revisited lower priority modules: %#v", obsolete)
	}

	upgrade, _ := modulesNeedingInspection([]indexEntry{
		{Path: "example.com/lib/v3", Version: "v3.2.0"},
	}, checkpoints)
	if want := []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.2.0"}}; !reflect.DeepEqual(upgrade, want) {
		t.Fatalf("incremental same-major upgrade = %#v, want %#v", upgrade, want)
	}
}

func TestModulesNeedingInspectionUsesSemverNotIndexArrivalOrder(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.com/lib/v3", Version: "v3.2.0"},
		{Path: "example.com/lib/v3", Version: "v3.1.0"},
	}
	got, _ := modulesNeedingInspection(entries, nil)
	want := []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.2.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesNeedingInspection() = %#v, want semver maximum %#v", got, want)
	}
}

func TestModulesNeedingInspectionAllowsNewMajorPastCheckpoint(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.com/lib", Version: "v1.10.0"},
		{Path: "example.com/lib/v2", Version: "v2.9.0"},
		{Path: "example.com/lib/v3", Version: "v3.0.0"},
	}
	checkpoints := map[string]moduleCheckpoint{
		"example.com/lib": {Path: "example.com/lib/v2", Version: "v2.8.0"},
	}
	got, _ := modulesNeedingInspection(entries, checkpoints)
	want := []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesNeedingInspection() = %#v, want new major %#v", got, want)
	}
}

func TestModulesNeedingInspectionAllowsNewMajorPastLatestFailure(t *testing.T) {
	entries := []indexEntry{{Path: "example.com/lib/v3", Version: "v3.0.0"}}
	checkpoints := map[string]moduleCheckpoint{
		"example.com/lib": {Path: "example.com/lib/v2", Version: "@latest"},
	}
	got, _ := modulesNeedingInspection(entries, checkpoints)
	want := []moduleVersion{{Path: "example.com/lib/v3", Version: "v3.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesNeedingInspection() = %#v, want new major past v2 retry %#v", got, want)
	}
}

func TestResolveScanWindowSeparatesHistoryAndIncrementalCursors(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	existing := discoveryReport{
		IndexRanges: []indexRange{
			{Since: "2025-01-01T00:00:00Z", Before: "2026-09-15T00:00:00Z", IndexEntries: 100},
		},
	}

	history, err := resolveScanWindow(&existing, scanModeHistory, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if history.Before != "2025-01-01T00:00:00Z" || history.After != indexEpoch {
		t.Fatalf("history window = %#v, want only the saved backwards cursor", history)
	}

	incremental, err := resolveScanWindow(&existing, scanModeIncremental, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if incremental.Before != now.Format(time.RFC3339Nano) || incremental.After != "2026-09-15T00:00:00Z" {
		t.Fatalf("incremental window = %#v, want only the new head interval", incremental)
	}
}

func TestResolveScanWindowAllowsIncrementalBeforeHistoryCompletes(t *testing.T) {
	existing := discoveryReport{
		IndexRanges: []indexRange{{
			Since: "2025-01-01T00:00:00Z", Before: "2026-09-15T00:00:00Z", IndexEntries: 10,
		}},
	}
	window, err := resolveScanWindow(&existing, scanModeIncremental, "", time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if window.After != "2026-09-15T00:00:00Z" {
		t.Fatalf("incremental window = %#v, want independent head cursor", window)
	}
}

func TestMergeDiscoveryReportsDerivesDualCursorsFromRanges(t *testing.T) {
	base := discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges: []indexRange{{
			Since: "2025-01-01T00:00:00Z", Before: "2026-09-15T00:00:00Z", IndexEntries: 10,
		}},
	}
	history := discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges: []indexRange{{
			Since: "2024-01-01T00:00:00Z", Before: "2025-01-01T00:00:00Z", IndexEntries: 20,
		}},
	}
	merged, err := mergeDiscoveryReports(base, history)
	if err != nil {
		t.Fatal(err)
	}
	if earliestIndexRangeLower(merged.IndexRanges) != "2024-01-01T00:00:00Z" || latestIndexRangeUpper(merged.IndexRanges) != "2026-09-15T00:00:00Z" {
		t.Fatalf("history merge cursors = %#v", merged)
	}
	incremental := discoveryReport{
		SchemaVersion: discoverySchema,
		IndexRanges: []indexRange{{
			Since: "2026-09-15T00:00:00Z", Before: "2026-09-16T00:00:00Z", IndexEntries: 3,
		}},
	}
	merged, err = mergeDiscoveryReports(merged, incremental)
	if err != nil {
		t.Fatal(err)
	}
	if earliestIndexRangeLower(merged.IndexRanges) != "2024-01-01T00:00:00Z" || latestIndexRangeUpper(merged.IndexRanges) != "2026-09-16T00:00:00Z" {
		t.Fatalf("incremental merge cursors = %#v", merged)
	}
}

func TestReverseIndexSpanHintUsesAdjacentCoveredRange(t *testing.T) {
	existing := &discoveryReport{IndexRanges: []indexRange{{
		Since: "2026-09-14T20:00:00Z", Before: "2026-09-15T00:00:00Z", IndexEntries: 20_000,
	}}}
	got := reverseIndexSpanHint(existing, scanWindow{Before: "2026-09-14T20:00:00Z", After: indexEpoch})
	want := time.Duration(float64(4*time.Hour) * float64(reversePageTarget) / 20_000)
	if got != want {
		t.Fatalf("history span hint = %s, want %s", got, want)
	}
	got = reverseIndexSpanHint(existing, scanWindow{Before: "2026-09-15T01:00:00Z", After: "2026-09-15T00:00:00Z"})
	if got != want {
		t.Fatalf("incremental span hint = %s, want %s", got, want)
	}
}

func TestModuleCheckpointsIncludeFailuresWithoutDowngradingExactVersion(t *testing.T) {
	report := discoveryReport{
		Scanned: []moduleVersion{
			{Path: "example.com/a", Version: "v1.1.0"},
			{Path: "example.com/b", Version: "v2.0.0"},
		},
		Failures: []scanFailure{
			{Module: "example.com/a", Version: "v1.0.0", Error: "old failure"},
			{Module: "example.com/b", Version: "@latest", Error: "retry separately"},
			{Module: "example.com/c", Version: "v3.0.0", Error: "retry separately"},
		},
	}
	want := map[string]moduleCheckpoint{
		"example.com/a": {Path: "example.com/a", Version: "v1.1.0"},
		"example.com/b": {Path: "example.com/b", Version: "@latest"},
		"example.com/c": {Path: "example.com/c", Version: "v3.0.0"},
	}
	if got := moduleCheckpoints(report); !reflect.DeepEqual(got, want) {
		t.Fatalf("moduleCheckpoints() = %#v, want %#v", got, want)
	}
}

func TestModulesForFailureRetryUsesHighestMajorThenSemver(t *testing.T) {
	report := discoveryReport{Failures: []scanFailure{
		{Module: "example.com/lib/v2", Version: "v2.9.0", Error: "old v2"},
		{Module: "example.com/lib/v3", Version: "v3.1.0", Error: "current v3"},
		{Module: "example.com/other", Version: "v1.0.0", Error: "exact failed"},
		{Module: "example.com/other", Version: "@latest", Error: "resolution failed"},
	}}
	got := modulesForFailureRetry(report)
	want := []moduleVersion{
		{Path: "example.com/lib/v3", Version: "v3.1.0"},
		{Path: "example.com/other", Version: "@latest"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modulesForFailureRetry() = %#v, want %#v", got, want)
	}
}

func TestInspectModuleZipFindsTargetAssembly(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, name := range []string{
		"example.com/lib@v1.2.3/hash/hash.go",
		"example.com/lib@v1.2.3/hash/hash_amd64.s",
		"example.com/lib@v1.2.3/hash/hash_arm64.s",
		"example.com/lib@v1.2.3/hash/empty_arm.s",
		"example.com/lib@v1.2.3/hash/comments_386.s",
		"example.com/lib@v1.2.3/cpu/cpu.go",
		"example.com/lib@v1.2.3/cpu/asm.s",
		"example.com/lib@v1.2.3/testdata/rejected_arm.s",
		"example.com/lib@v1.2.3/hash/not-go-assembly.S",
		"example.com/lib@v1.2.3/README.md",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(name, "empty_arm.s") {
			continue
		}
		if strings.Contains(name, "comments_386.s") {
			if _, err := w.Write([]byte("//go:build 386\n\n/* license only */\n")); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := w.Write([]byte("TEXT ·f(SB),0,$0-0\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	files, arches, err := inspectModuleZip(archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := []string{"cpu/asm.s", "hash/hash_amd64.s", "hash/hash_arm64.s"}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Fatalf("assembly files = %#v, want %#v", files, wantFiles)
	}
	wantArches := []string{"amd64", "arm64", "unknown"}
	if !reflect.DeepEqual(arches, wantArches) {
		t.Fatalf("architectures = %#v, want %#v", arches, wantArches)
	}
}

func TestInferAssemblyArchitecture(t *testing.T) {
	tests := map[string]string{
		"foo_386.s":           "386",
		"foo_amd64.s":         "amd64",
		"foo_arm.s":           "arm",
		"foo_arm64.s":         "arm64",
		"foo_loong64.s":       "loong64",
		"foo_mips64x.s":       "unknown",
		"foo_ppc64le.s":       "ppc64le",
		"foo_riscv64.s":       "riscv64",
		"foo_s390x.s":         "s390x",
		"foo_wasm.s":          "wasm",
		"asm_darwin_x86_gc.s": "unknown",
	}
	for name, want := range tests {
		if got := inferAssemblyArchitecture(name); got != want {
			t.Errorf("inferAssemblyArchitecture(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSortDiscoveryReportRebuildsArchitectureHintsFromAllAssemblyPaths(t *testing.T) {
	report := discoveryReport{Matched: []candidate{{
		Module:        "example.com/future",
		Version:       "v1.0.0",
		Architectures: []string{"amd64"},
		AsmFiles: []string{
			"asm_amd64.s",
			"asm_riscv64.s",
			"portable.s",
		},
	}}}
	sortDiscoveryReport(&report)
	want := []string{"amd64", "riscv64", "unknown"}
	if got := report.Matched[0].Architectures; !reflect.DeepEqual(got, want) {
		t.Fatalf("architecture hints = %#v, want %#v", got, want)
	}
}

func TestHTTPReaderAtFetchesCentralDirectoryOutsideCachedTail(t *testing.T) {
	archive := testModuleZip(t)
	server := newRangeServer(t, archive, nil)
	defer server.Close()

	reader, size, err := newHTTPReaderAtWithTail(context.Background(), server.Client(), server.URL, int64(len(archive)), 22)
	if err != nil {
		t.Fatal(err)
	}
	files, arches, err := inspectModuleZipReader(reader, size)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg/asm_amd64.s"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("assembly files = %#v, want %#v", files, want)
	}
	if want := []string{"amd64"}; !reflect.DeepEqual(arches, want) {
		t.Fatalf("architectures = %#v, want %#v", arches, want)
	}
}

func TestHTTPReaderAtDoesNotPrefetchLargeModuleTail(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	large, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "example.com/lib@v1.0.0/pkg/blob.bin",
		Method: zip.Store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(large, bytes.NewReader(make([]byte, 9<<20)), 9<<20); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"example.com/lib@v1.0.0/pkg/pkg.go",
		"example.com/lib@v1.0.0/pkg/asm_amd64.s",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("TEXT ·f(SB),0,$0-0\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var fetched atomic.Int64
	var malformedRange atomic.Bool
	server := newRangeServer(t, archive.Bytes(), func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			return false
		}
		if r.Header.Get("Range") == "" {
			fetched.Add(int64(archive.Len()))
			return false
		}
		var start, end int64
		if fields, err := fmt.Sscanf(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), "%d-%d", &start, &end); err != nil || fields != 2 {
			malformedRange.Store(true)
			return false
		}
		fetched.Add(end - start + 1)
		return false
	})
	defer server.Close()

	reader, size, err := newHTTPReaderAt(context.Background(), server.Client(), server.URL, int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := inspectModuleZipReader(reader, size)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg/asm_amd64.s"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("assembly files = %#v, want %#v", files, want)
	}
	if malformedRange.Load() {
		t.Fatal("HTTP reader sent a malformed Range header")
	}
	if got, limit := fetched.Load(), int64(96<<10); got > limit {
		t.Fatalf("fetched %d bytes, want at most %d", got, limit)
	}
}

func TestHTTPReaderAtNoAssemblyFetchesOnlyEOCDAndDirectory(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	large, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "example.com/lib@v1.0.0/pkg/blob.bin",
		Method: zip.Store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(large, bytes.NewReader(make([]byte, 9<<20)), 9<<20); err != nil {
		t.Fatal(err)
	}
	goFile, err := zw.Create("example.com/lib@v1.0.0/pkg/pkg.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(goFile, "package pkg\n"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var fetched atomic.Int64
	server := newRangeServer(t, archive.Bytes(), func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet {
			var start, end int64
			if fields, err := fmt.Sscanf(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), "%d-%d", &start, &end); err == nil && fields == 2 {
				fetched.Add(end - start + 1)
			}
		}
		return false
	})
	defer server.Close()

	reader, size, err := newHTTPReaderAt(context.Background(), server.Client(), server.URL, int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := inspectModuleZipReader(reader, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("no-assembly ZIP matched files %#v", files)
	}
	if got, limit := fetched.Load(), int64(4<<10); got > limit {
		t.Fatalf("no-assembly ZIP fetched %d bytes, want at most %d", got, limit)
	}
}

func TestHTTPReaderAtFallsBackForZIPComment(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	large, err := zw.CreateHeader(&zip.FileHeader{Name: "example.com/lib@v1.0.0/blob.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(large, bytes.NewReader(make([]byte, 128<<10)), 128<<10); err != nil {
		t.Fatal(err)
	}
	if err := zw.SetComment(strings.Repeat("comment", 100)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	server := newRangeServer(t, archive.Bytes(), nil)
	defer server.Close()
	reader, size, err := newHTTPReaderAt(context.Background(), server.Client(), server.URL, int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectModuleZipReader(reader, size); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPReaderAtRetriesTransientResponses(t *testing.T) {
	archive := testModuleZip(t)
	var heads atomic.Int32
	server := newRangeServer(t, archive, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodHead && heads.Add(1) == 1 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	defer server.Close()

	reader, size, err := newHTTPReaderAtWithTail(context.Background(), server.Client(), server.URL, int64(len(archive)), 22)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectModuleZipReader(reader, size); err != nil {
		t.Fatal(err)
	}
	if got := heads.Load(); got != 2 {
		t.Fatalf("HEAD requests = %d, want 2", got)
	}
}

func TestHTTPReaderAtReusesReadAheadForAssemblyEntries(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, name := range []string{
		"example.com/lib@v1.0.0/pkg/pkg.go",
		"example.com/lib@v1.0.0/pkg/first_amd64.s",
		"example.com/lib@v1.0.0/pkg/second_amd64.s",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("TEXT ·f(SB),0,$0-0\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var ranges atomic.Int32
	server := newRangeServer(t, archive.Bytes(), func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.Header.Get("Range") != "" {
			ranges.Add(1)
		}
		return false
	})
	defer server.Close()
	reader, size, err := newHTTPReaderAtWithTail(context.Background(), server.Client(), server.URL, int64(archive.Len()), 22)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectModuleZipReader(reader, size); err != nil {
		t.Fatal(err)
	}
	if got := ranges.Load(); got > 2 {
		t.Fatalf("range requests = %d, want at most 2 (tail plus one read-ahead block)", got)
	}
}

func TestDiscoveryTrafficAttributesPayloadBytesPerModule(t *testing.T) {
	archive := testModuleZip(t)
	latestBody := []byte(`{"Version":"v1.0.0"}`)
	var identityOnly atomic.Bool
	identityOnly.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			identityOnly.Store(false)
		}
		if strings.HasSuffix(r.URL.Path, "/@latest") {
			w.Header().Set("Content-Length", strconv.Itoa(len(latestBody)))
			_, _ = w.Write(latestBody)
			return
		}
		serveRangeData(t, w, r, archive)
	}))
	defer server.Close()

	collector := newTrafficCollector()
	ctx := context.WithValue(context.Background(), trafficCollectorContextKey{}, collector)
	matched, failures, scanned, skipped := inspectModules(
		ctx, server.Client(), server.URL,
		[]moduleVersion{{Path: "example.com/lib", Version: "v1.0.0"}},
		nil, nil, 1, int64(len(archive))+1,
	)
	if len(matched) != 1 || len(failures) != 0 || len(scanned) != 1 || skipped != 0 {
		t.Fatalf("inspection result = matched %d failures %d scanned %d skipped %d", len(matched), len(failures), len(scanned), skipped)
	}
	if !identityOnly.Load() {
		t.Fatal("discovery request allowed transparent content encoding, making payload accounting ambiguous")
	}
	report := collector.snapshot(time.Unix(0, 0).UTC(), scanModeHistory, discoveryReport{IndexEntries: 1})
	if len(report.Modules) != 1 {
		t.Fatalf("traffic modules = %#v, want one", report.Modules)
	}
	got := report.Modules[0]
	if got.Module != "example.com/lib" || got.IndexedVersion != "v1.0.0" || got.ResolvedVersion != "v1.0.0" || got.Outcome != "matched" {
		t.Fatalf("module traffic identity = %#v", got)
	}
	if got.Latest.Requests != 1 || got.Latest.BodyBytes != int64(len(latestBody)) {
		t.Fatalf("latest traffic = %#v", got)
	}
	if got.ZIPHead.Requests != 1 || got.ZIPHead.BodyBytes != 0 || got.AdvertisedZIPBytes != int64(len(archive)) {
		t.Fatalf("ZIP HEAD traffic = %#v", got)
	}
	if got.ZIPFull.Requests != 1 || got.ZIPFull.BodyBytes != int64(len(archive)) || got.ZIPRange.Requests != 0 {
		t.Fatalf("ZIP body traffic = %#v", got)
	}
	wantBytes := int64(len(latestBody) + len(archive))
	if got.TotalRequests != 3 || got.TotalBodyBytes != wantBytes || report.TotalBodyBytes != wantBytes {
		t.Fatalf("traffic totals = module %#v report %#v, want 3 requests and %d bytes", got, report, wantBytes)
	}
}

func TestReadIndexDoesNotSkipSharedBoundaryTimestamp(t *testing.T) {
	base := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	entries := make([]indexEntry, 2001)
	for i := range entries {
		timestamp := base.Add(time.Duration(i) * time.Nanosecond)
		if i == 2000 {
			timestamp = entries[1999].Timestamp
		}
		entries[i] = indexEntry{Path: fmt.Sprintf("example.com/mod%d", i), Version: "v1.0.0", Timestamp: timestamp}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			t.Fatal(err)
		}
		var since time.Time
		if raw := r.URL.Query().Get("since"); raw != "" {
			since, err = time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		enc := json.NewEncoder(w)
		n := 0
		for _, entry := range entries {
			if entry.Timestamp.Before(since) {
				continue
			}
			if n == limit {
				break
			}
			if err := enc.Encode(entry); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}))
	defer server.Close()

	got, nextSince, err := readIndex(context.Background(), server.Client(), server.URL, "", len(entries))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("readIndex() returned %d entries, want %d", len(got), len(entries))
	}
	if want := entries[len(entries)-1].Timestamp.Format(time.RFC3339Nano); nextSince != want {
		t.Fatalf("next since = %q, want %q", nextSince, want)
	}
}

func TestReadIndexBackwardsSelectsNewestCompleteTimestampGroup(t *testing.T) {
	base := time.Date(2026, time.September, 15, 0, 0, 0, 0, time.UTC)
	entries := []indexEntry{
		{Path: "example.com/old", Version: "v1.0.0", Timestamp: base.Add(-4 * time.Minute)},
		{Path: "example.com/a", Version: "v1.0.0", Timestamp: base.Add(-3 * time.Minute)},
		{Path: "example.com/b", Version: "v1.0.0", Timestamp: base.Add(-2 * time.Minute)},
		{Path: "example.com/c", Version: "v1.0.0", Timestamp: base.Add(-2 * time.Minute)},
		{Path: "example.com/d", Version: "v1.0.0", Timestamp: base.Add(-2 * time.Minute)},
		{Path: "example.com/new", Version: "v1.0.0", Timestamp: base.Add(-time.Minute)},
		{Path: "example.com/after", Version: "v1.0.0", Timestamp: base},
	}
	server := newIndexServer(t, entries)
	defer server.Close()

	got, nextBefore, err := readIndexBackwards(
		context.Background(), server.Client(), server.URL,
		base.Format(time.RFC3339Nano), 3,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := entries[2:6]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readIndexBackwards() = %#v, want newest complete timestamp group %#v", got, want)
	}
	if wantCursor := base.Add(-2 * time.Minute).Format(time.RFC3339Nano); nextBefore != wantCursor {
		t.Fatalf("next before = %q, want %q", nextBefore, wantCursor)
	}
}

func TestReadIndexBackwardsFromStopsAtIncrementalLowerBound(t *testing.T) {
	base := time.Date(2026, time.September, 15, 0, 0, 0, 0, time.UTC)
	entries := []indexEntry{
		{Path: "example.com/before", Version: "v1.0.0", Timestamp: base.Add(-time.Nanosecond)},
		{Path: "example.com/at-lower", Version: "v1.0.0", Timestamp: base},
		{Path: "example.com/inside", Version: "v1.0.0", Timestamp: base.Add(time.Minute)},
		{Path: "example.com/at-upper", Version: "v1.0.0", Timestamp: base.Add(2 * time.Minute)},
	}
	server := newIndexServer(t, entries)
	defer server.Close()

	got, nextBefore, err := readIndexBackwardsFrom(
		context.Background(), server.Client(), server.URL,
		base.Add(2*time.Minute).Format(time.RFC3339Nano),
		base.Format(time.RFC3339Nano), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := entries[1:3]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readIndexBackwardsFrom() = %#v, want bounded interval %#v", got, want)
	}
	if wantCursor := base.Format(time.RFC3339Nano); nextBefore != wantCursor {
		t.Fatalf("next before = %q, want lower bound %q", nextBefore, wantCursor)
	}
}

func TestReadIndexBackwardsConsecutiveWindowsHaveExactContiguousCoverage(t *testing.T) {
	lower := time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC)
	const timestampGroups = 1001
	const entriesPerGroup = 5
	entries := make([]indexEntry, 0, timestampGroups*entriesPerGroup)
	for group := 0; group < timestampGroups; group++ {
		timestamp := lower.Add(time.Duration(group) * time.Millisecond)
		for item := 0; item < entriesPerGroup; item++ {
			entries = append(entries, indexEntry{
				Path:      fmt.Sprintf("example.com/mod-%04d-%d", group, item),
				Version:   "v1.0.0",
				Timestamp: timestamp,
			})
		}
	}
	server := newIndexServer(t, entries)
	defer server.Close()

	before := lower.Add(timestampGroups * time.Millisecond).Format(time.RFC3339Nano)
	after := lower.Format(time.RFC3339Nano)
	var got []indexEntry
	var ranges []indexRange
	for before != after {
		batch, nextBefore, err := readIndexBackwardsFrom(
			context.Background(), server.Client(), server.URL, before, after, 2100,
		)
		if err != nil {
			t.Fatal(err)
		}
		nextTime, nextErr := time.Parse(time.RFC3339Nano, nextBefore)
		beforeTime, beforeErr := time.Parse(time.RFC3339Nano, before)
		if nextErr != nil || beforeErr != nil || !nextTime.Before(beforeTime) {
			t.Fatalf("reverse cursor did not advance: %q -> %q", before, nextBefore)
		}
		got = append(got, batch...)
		ranges = append(ranges, indexRange{Since: nextBefore, Before: before, IndexEntries: len(batch)})
		before = nextBefore
	}
	if err := validateIndexCoverage(reverseIndexRanges(ranges)); err != nil {
		t.Fatalf("consecutive reverse windows are not contiguous: %v", err)
	}
	sort.Slice(got, func(i, j int) bool {
		if !got[i].Timestamp.Equal(got[j].Timestamp) {
			return got[i].Timestamp.Before(got[j].Timestamp)
		}
		return got[i].Path < got[j].Path
	})
	if !reflect.DeepEqual(got, entries) {
		t.Fatalf("consecutive reverse windows returned %d entries, want all %d exactly once", len(got), len(entries))
	}
}

func TestFetchIndexPageRejectsUnorderedFeed(t *testing.T) {
	base := time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC)
	server := newIndexServer(t, []indexEntry{
		{Path: "example.com/new", Version: "v1.0.0", Timestamp: base.Add(time.Second)},
		{Path: "example.com/old", Version: "v1.0.0", Timestamp: base},
	})
	defer server.Close()
	_, err := fetchIndexPage(context.Background(), server.Client(), server.URL, base.Add(-time.Second).Format(time.RFC3339Nano), indexPageLimit)
	if err == nil || !strings.Contains(err.Error(), "not ordered") {
		t.Fatalf("fetchIndexPage() error = %v, want unordered-feed rejection", err)
	}
}

func TestValidateFetchedIndexWindowAcceptsEmptyPrefixAtCompletedLowerBound(t *testing.T) {
	const after = "2026-09-15T16:56:51.924668Z"
	const before = "2026-09-15T22:56:51Z"
	first, err := time.Parse(time.RFC3339Nano, "2026-09-15T16:56:52.269461Z")
	if err != nil {
		t.Fatal(err)
	}
	entries := []indexEntry{{Path: "example.com/lib", Version: "v1.0.0", Timestamp: first}}
	if err := validateFetchedIndexWindow(entries, after, before, after); err != nil {
		t.Fatalf("a fully consumed interval may start before its first entry: %v", err)
	}
	if err := validateFetchedIndexWindow(entries, "2026-09-15T16:56:52Z", before, after); err == nil {
		t.Fatal("partial interval cursor must still equal its first complete timestamp group")
	}
}

func TestValidateFetchedIndexWindowRequiresCursorAtFirstCompleteGroup(t *testing.T) {
	entries := []indexEntry{
		{Path: "example.com/a", Version: "v1.0.0", Timestamp: time.Date(2026, 9, 14, 0, 0, 1, 0, time.UTC)},
		{Path: "example.com/b", Version: "v1.0.0", Timestamp: time.Date(2026, 9, 14, 0, 0, 1, 0, time.UTC)},
		{Path: "example.com/c", Version: "v1.0.0", Timestamp: time.Date(2026, 9, 14, 0, 0, 2, 0, time.UTC)},
	}
	if err := validateFetchedIndexWindow(entries, "2026-09-14T00:00:01Z", "2026-09-14T00:00:03Z", "2026-09-14T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := validateFetchedIndexWindow(entries, "2026-09-14T00:00:01.5Z", "2026-09-14T00:00:03Z", "2026-09-14T00:00:00Z"); err == nil {
		t.Fatal("validateFetchedIndexWindow() accepted a cursor that could skip the first timestamp group")
	}
}

func TestMergeIndexRangesOrdersRFC3339ByTimeNotText(t *testing.T) {
	got, err := mergeIndexRanges([]indexRange{
		{Since: "2026-09-14T00:00:00.5Z", Before: "2026-09-14T00:00:01Z", IndexEntries: 1},
		{Since: "2026-09-14T00:00:00Z", Before: "2026-09-14T00:00:00.5Z", IndexEntries: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Since != "2026-09-14T00:00:00Z" || got[1].Since != "2026-09-14T00:00:00.5Z" {
		t.Fatalf("mergeIndexRanges() ordered RFC3339 timestamps lexically: %#v", got)
	}
}

func reverseIndexRanges(items []indexRange) []indexRange {
	out := append([]indexRange(nil), items...)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func newIndexServer(t *testing.T, entries []indexEntry) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			t.Fatal(err)
		}
		var since time.Time
		if raw := r.URL.Query().Get("since"); raw != "" {
			since, err = time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		encoder := json.NewEncoder(w)
		for _, entry := range entries {
			if entry.Timestamp.Before(since) {
				continue
			}
			if limit == 0 {
				break
			}
			if err := encoder.Encode(entry); err != nil {
				t.Fatal(err)
			}
			limit--
		}
	}))
}

func testModuleZip(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, name := range []string{
		"example.com/lib@v1.0.0/pkg/pkg.go",
		"example.com/lib@v1.0.0/pkg/asm_amd64.s",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("TEXT ·f(SB),0,$0-0\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func newRangeServer(t *testing.T, data []byte, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil && intercept(w, r) {
			return
		}
		serveRangeData(t, w, r, data)
	}))
}

func serveRangeData(t *testing.T, w http.ResponseWriter, r *http.Request, data []byte) {
	t.Helper()
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
		return
	}
	var start, end int
	if _, err := fmt.Sscanf(strings.TrimPrefix(rangeHeader, "bytes="), "%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= len(data) {
		http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
	w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(data[start : end+1])
}
