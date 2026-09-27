// Command plan9asmdiscover finds public Go modules that contain Plan 9
// assembly. It reads the official module index, resolves each distinct module
// to @latest, and inspects the cached module ZIP without executing module code.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/discoverymeta"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const (
	defaultIndexURL    = "https://index.golang.org/index"
	defaultProxyURL    = "https://proxy.golang.org/cached-only"
	discoverySchema    = 2
	shardedFormat      = "plan9asmdiscover-jsonl-v1"
	indexPageLimit     = 2000
	defaultScanLimit   = 2000
	defaultMaxZipSize  = 2 << 30
	defaultHTTPTimeout = 60 * time.Second
	// ZIP readers need the final 65,557 bytes to locate the end record when
	// the archive uses the maximum-length comment. Earlier directory data is
	// fetched lazily through ReaderAt.
	zipEOCDSize         = 22
	zipMaxEOCDSearch    = 65_557
	zipSmallWholeLimit  = 64 << 10
	maxAsmProbeSize     = 8 << 20
	zipReadAhead        = 64 << 10
	httpAttempts        = 3
	httpRetryDelay      = 100 * time.Millisecond
	indexEpoch          = "2019-04-10T00:00:00Z"
	reversePageTarget   = indexPageLimit - 1
	scanModeHistory     = "history"
	scanModeIncremental = "incremental"
	scanModeRetry       = "retry"
)

type indexEntry struct {
	Path      string    `json:"Path"`
	Version   string    `json:"Version"`
	Timestamp time.Time `json:"Timestamp"`
}

type latestInfo struct {
	Version string `json:"Version"`
}

type moduleVersion struct {
	Path    string `json:"module"`
	Version string `json:"version"`
}

type moduleCheckpoint struct {
	Path    string
	Version string
}

type scanWindow struct {
	Before string
	After  string
}

type trafficBucket struct {
	Requests  int   `json:"requests"`
	BodyBytes int64 `json:"body_bytes"`
}

type moduleTraffic struct {
	Module             string        `json:"module"`
	IndexedVersion     string        `json:"indexed_version,omitempty"`
	ResolvedVersion    string        `json:"resolved_version,omitempty"`
	Outcome            string        `json:"outcome,omitempty"`
	Latest             trafficBucket `json:"latest"`
	ZIPHead            trafficBucket `json:"zip_head"`
	ZIPRange           trafficBucket `json:"zip_range"`
	ZIPFull            trafficBucket `json:"zip_full"`
	AdvertisedZIPBytes int64         `json:"advertised_zip_bytes,omitempty"`
	TotalRequests      int           `json:"total_requests"`
	TotalBodyBytes     int64         `json:"total_body_bytes"`
}

type trafficReport struct {
	SchemaVersion  int             `json:"schema_version"`
	GeneratedAt    time.Time       `json:"generated_at"`
	ByteDefinition string          `json:"byte_definition"`
	ScanMode       string          `json:"scan_mode"`
	IndexRanges    []indexRange    `json:"index_ranges,omitempty"`
	IndexEntries   int             `json:"index_entries"`
	UniqueModules  int             `json:"unique_modules"`
	Skipped        int             `json:"skipped"`
	Scanned        int             `json:"scanned"`
	Matched        int             `json:"matched"`
	Failures       int             `json:"failures"`
	Index          trafficBucket   `json:"index"`
	Modules        []moduleTraffic `json:"modules"`
	TotalRequests  int             `json:"total_requests"`
	TotalBodyBytes int64           `json:"total_body_bytes"`
}

type ledgerSummary struct {
	SchemaVersion    int    `json:"schema_version"`
	HistoryBefore    string `json:"history_before"`
	IncrementalSince string `json:"incremental_since"`
	HistoryComplete  bool   `json:"history_complete"`
	IndexRanges      int    `json:"index_ranges"`
	IndexEntries     int    `json:"index_entries"`
	UniqueModules    int    `json:"unique_modules"`
	ScannedRecords   int    `json:"scanned_records"`
	MatchedRecords   int    `json:"matched_records"`
	AssemblyFiles    int    `json:"assembly_files"`
	FailureRecords   int    `json:"failure_records"`
}

type trafficCollector struct {
	mu      sync.Mutex
	index   trafficBucket
	modules map[string]*moduleTraffic
}

type trafficCollectorContextKey struct{}
type trafficModuleContextKey struct{}

type trafficReadCloser struct {
	io.ReadCloser
	collector *trafficCollector
	module    string
	phase     string
}

func (r *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.collector.addBodyBytes(r.module, r.phase, int64(n))
	}
	return n, err
}

type candidate struct {
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures"`
	AsmFiles      []string `json:"asm_files"`
}

type scanFailure struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

type indexRange struct {
	Since        string `json:"since"`
	Before       string `json:"before"`
	IndexEntries int    `json:"index_entries"`
}

type seenResult struct {
	Match candidate
}

type sourceInspectionFlight struct {
	done chan struct{}
}

type sourceInspectionCache struct {
	mu        sync.Mutex
	completed map[string]seenResult
	inFlight  map[string]*sourceInspectionFlight
}

type discoveryReport struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Since, NextSince, and NextBefore are retained only for importing legacy
	// reports. Current bidirectional cursors are derived from IndexRanges.
	Since         string          `json:"since,omitempty"`
	NextSince     string          `json:"next_since,omitempty"`
	ScanDirection string          `json:"scan_direction,omitempty"`
	NextBefore    string          `json:"next_before,omitempty"`
	IndexRanges   []indexRange    `json:"index_ranges,omitempty"`
	IndexEntries  int             `json:"index_entries"`
	UniqueModules int             `json:"unique_modules"`
	Skipped       int             `json:"skipped_previously_scanned,omitempty"`
	Scanned       []moduleVersion `json:"scanned"`
	Matched       []candidate     `json:"matched"`
	Failures      []scanFailure   `json:"failures,omitempty"`
}

type shardedManifest struct {
	SchemaVersion int          `json:"schema_version"`
	Format        string       `json:"format"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Since         string       `json:"since,omitempty"`
	NextSince     string       `json:"next_since,omitempty"`
	ScanDirection string       `json:"scan_direction,omitempty"`
	NextBefore    string       `json:"next_before,omitempty"`
	IndexRanges   []indexRange `json:"index_ranges,omitempty"`
	IndexEntries  int          `json:"index_entries"`
	UniqueModules int          `json:"unique_modules"`
	Skipped       int          `json:"skipped_previously_scanned,omitempty"`
	Scanned       int          `json:"scanned_records"`
	Matched       int          `json:"matched_records"`
	Failures      int          `json:"failure_records"`
	ShardKey      string       `json:"shard_key"`
}

type shardedRecord struct {
	Kind          string   `json:"kind"`
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures,omitempty"`
	AsmFiles      []string `json:"asm_files,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type config struct {
	indexURL      string
	proxyURL      string
	scanMode      string
	before        string
	after         string
	indexSpanHint time.Duration
	limit         int
	workers       int
	maxZipSize    int64
	httpTimeout   time.Duration
	seen          map[string]seenResult
	sourceSeen    map[string]seenResult
	checkpoints   map[string]moduleCheckpoint
}

type pathListFlag []string

func newTrafficCollector() *trafficCollector {
	return &trafficCollector{modules: make(map[string]*moduleTraffic)}
}

func newSourceInspectionCache(existing map[string]seenResult) *sourceInspectionCache {
	completed := make(map[string]seenResult, len(existing))
	for key, result := range existing {
		completed[key] = result
	}
	return &sourceInspectionCache{
		completed: completed,
		inFlight:  make(map[string]*sourceInspectionFlight),
	}
}

func (c *sourceInspectionCache) inspect(ctx context.Context, key string, inspect func() (candidate, error)) (candidate, bool, error) {
	if key == "" {
		item, err := inspect()
		return item, false, err
	}
	for {
		c.mu.Lock()
		if previous, ok := c.completed[key]; ok {
			c.mu.Unlock()
			return previous.Match, true, nil
		}
		if flight, ok := c.inFlight[key]; ok {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return candidate{}, false, ctx.Err()
			case <-flight.done:
			}
			continue
		}
		flight := &sourceInspectionFlight{done: make(chan struct{})}
		c.inFlight[key] = flight
		c.mu.Unlock()

		item, err := inspect()
		c.mu.Lock()
		if err == nil {
			c.completed[key] = seenResult{Match: item}
		}
		delete(c.inFlight, key)
		close(flight.done)
		c.mu.Unlock()
		return item, false, err
	}
}

func withTrafficModule(ctx context.Context, modulePath string) context.Context {
	return context.WithValue(ctx, trafficModuleContextKey{}, modulePath)
}

func trafficContext(ctx context.Context) (*trafficCollector, string) {
	collector, _ := ctx.Value(trafficCollectorContextKey{}).(*trafficCollector)
	modulePath, _ := ctx.Value(trafficModuleContextKey{}).(string)
	return collector, modulePath
}

func trafficPhase(modulePath, method, endpoint string, headers http.Header) string {
	if modulePath == "" {
		return "index"
	}
	if method == http.MethodHead {
		return "zip_head"
	}
	if strings.HasSuffix(endpoint, "/@latest") {
		return "latest"
	}
	if headers.Get("Range") != "" {
		return "zip_range"
	}
	return "zip_full"
}

func (c *trafficCollector) bucket(modulePath, phase string) *trafficBucket {
	if phase == "index" {
		return &c.index
	}
	item := c.modules[modulePath]
	if item == nil {
		item = &moduleTraffic{Module: modulePath}
		c.modules[modulePath] = item
	}
	switch phase {
	case "latest":
		return &item.Latest
	case "zip_head":
		return &item.ZIPHead
	case "zip_range":
		return &item.ZIPRange
	case "zip_full":
		return &item.ZIPFull
	default:
		panic("unknown discovery traffic phase: " + phase)
	}
}

func (c *trafficCollector) addRequest(modulePath, phase string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bucket(modulePath, phase).Requests++
}

func (c *trafficCollector) addBodyBytes(modulePath, phase string, count int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bucket(modulePath, phase).BodyBytes += count
}

func (c *trafficCollector) setAdvertisedZIPBytes(modulePath string, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.modules[modulePath]
	if item == nil {
		item = &moduleTraffic{Module: modulePath}
		c.modules[modulePath] = item
	}
	if size > item.AdvertisedZIPBytes {
		item.AdvertisedZIPBytes = size
	}
}

func (c *trafficCollector) setModuleScan(modulePath, indexedVersion, resolvedVersion, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.modules[modulePath]
	if item == nil {
		item = &moduleTraffic{Module: modulePath}
		c.modules[modulePath] = item
	}
	if indexedVersion != "" {
		item.IndexedVersion = indexedVersion
	}
	if resolvedVersion != "" && resolvedVersion != "@latest" {
		item.ResolvedVersion = resolvedVersion
	}
	if outcome != "" {
		item.Outcome = outcome
	}
}

func (c *trafficCollector) snapshot(generatedAt time.Time, scanMode string, discovery discoveryReport) trafficReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	report := trafficReport{
		SchemaVersion:  1,
		GeneratedAt:    generatedAt,
		ByteDefinition: "HTTP response entity bytes read with Accept-Encoding: identity; excludes headers, TLS, and IP overhead",
		ScanMode:       scanMode,
		IndexRanges:    append([]indexRange(nil), discovery.IndexRanges...),
		IndexEntries:   discovery.IndexEntries,
		UniqueModules:  discovery.UniqueModules,
		Skipped:        discovery.Skipped,
		Scanned:        len(discovery.Scanned),
		Matched:        len(discovery.Matched),
		Failures:       len(discovery.Failures),
		Index:          c.index,
	}
	for _, current := range c.modules {
		item := *current
		item.TotalRequests = item.Latest.Requests + item.ZIPHead.Requests + item.ZIPRange.Requests + item.ZIPFull.Requests
		item.TotalBodyBytes = item.Latest.BodyBytes + item.ZIPHead.BodyBytes + item.ZIPRange.BodyBytes + item.ZIPFull.BodyBytes
		report.Modules = append(report.Modules, item)
		report.TotalRequests += item.TotalRequests
		report.TotalBodyBytes += item.TotalBodyBytes
	}
	sort.Slice(report.Modules, func(i, j int) bool { return report.Modules[i].Module < report.Modules[j].Module })
	report.TotalRequests += report.Index.Requests
	report.TotalBodyBytes += report.Index.BodyBytes
	return report
}

func writeTrafficReport(name string, report trafficReport) error {
	if name == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return fmt.Errorf("create traffic report directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(name), ".plan9asm-traffic-*.json")
	if err != nil {
		return fmt.Errorf("create traffic report: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		file.Close()
		return fmt.Errorf("write traffic report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close traffic report: %w", err)
	}
	if err := os.Rename(temporary, name); err != nil {
		return fmt.Errorf("publish traffic report %q: %w", name, err)
	}
	return nil
}

func (f *pathListFlag) String() string { return strings.Join(*f, ",") }

func (f *pathListFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("seen report path must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func main() {
	indexURL := flag.String("index-url", defaultIndexURL, "Go module index endpoint")
	proxyURL := flag.String("proxy-url", defaultProxyURL, "Go module proxy endpoint")
	scanMode := flag.String("scan-mode", scanModeHistory, "scan mode: history, incremental, or retry")
	before := flag.String("before", "", "optional exclusive upper bound (RFC3339); normally omit so the ledger derives it")
	limit := flag.Int("limit", defaultScanLimit, "approximate history records to inspect backwards; timestamp groups are never split; 0 scans history to 2019; ignored for incremental scans")
	workers := flag.Int("workers", 8, "concurrent module ZIP inspections")
	maxZipSize := flag.Int64("max-zip-bytes", defaultMaxZipSize, "maximum remote module ZIP size considered")
	httpTimeout := flag.Duration("http-timeout", defaultHTTPTimeout, "timeout for each index or proxy request")
	out := flag.String("out", "", "write JSON to this file instead of stdout")
	outDir := flag.String("out-dir", "", "create or update a diff-friendly sharded JSONL ledger directory")
	trafficReportPath := flag.String("traffic-report", "", "write per-module HTTP payload accounting JSON")
	statusOnly := flag.Bool("status", false, "validate -out-dir and print its derived cursors and record counts without scanning")
	convertReport := flag.String("convert-report", "", "convert an existing JSON, JSON.gz, or sharded report into -out-dir")
	var seenReports pathListFlag
	flag.Var(&seenReports, "seen-report", "prior discovery JSON, JSON.gz, or sharded report directory to skip (repeatable)")
	flag.Parse()
	if *out != "" && *outDir != "" {
		fatal(errors.New("-out and -out-dir are mutually exclusive"))
	}
	if *statusOnly && (*outDir == "" || *convertReport != "" || *out != "") {
		fatal(errors.New("-status requires only an existing -out-dir"))
	}
	if *convertReport != "" {
		if *outDir == "" {
			fatal(errors.New("-convert-report requires -out-dir"))
		}
		report, err := readSeenReport(*convertReport)
		if err != nil {
			fatal(err)
		}
		if err := writeShardedReport(*outDir, report); err != nil {
			fatal(err)
		}
		return
	}
	var existing *discoveryReport
	if *outDir != "" {
		if info, err := os.Stat(*outDir); err == nil {
			if !info.IsDir() {
				fatal(fmt.Errorf("-out-dir %q is not a directory", *outDir))
			}
			report, err := readShardedReport(*outDir)
			if err != nil {
				fatal(fmt.Errorf("read -out-dir %q: %w", *outDir, err))
			}
			existing = &report
			seenReports = append(seenReports, *outDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			fatal(fmt.Errorf("read -out-dir %q: %w", *outDir, err))
		}
	}
	if *statusOnly {
		if existing == nil {
			fatal(fmt.Errorf("-status requires existing -out-dir %q", *outDir))
		}
		if err := writeLedgerSummary(os.Stdout, summarizeLedger(*existing)); err != nil {
			fatal(err)
		}
		return
	}
	var window scanWindow
	if *scanMode == scanModeRetry {
		if existing == nil {
			fatal(errors.New("failure retry requires an existing -out-dir discovery ledger"))
		}
	} else {
		var err error
		window, err = resolveScanWindow(existing, *scanMode, *before, time.Now().UTC())
		if err != nil {
			fatal(err)
		}
	}
	seen, sourceSeen, err := loadSeenState(seenReports)
	if err != nil {
		fatal(err)
	}
	checkpoints, err := loadModuleCheckpoints(seenReports)
	if err != nil {
		fatal(err)
	}

	cfg := config{
		indexURL:      *indexURL,
		proxyURL:      strings.TrimRight(*proxyURL, "/"),
		scanMode:      *scanMode,
		before:        window.Before,
		after:         window.After,
		indexSpanHint: reverseIndexSpanHint(existing, window),
		limit:         scanLimit(*scanMode, *limit),
		workers:       *workers,
		maxZipSize:    *maxZipSize,
		httpTimeout:   *httpTimeout,
		seen:          seen,
		sourceSeen:    sourceSeen,
		checkpoints:   checkpoints,
	}
	if err := validateConfig(cfg); err != nil {
		fatal(err)
	}

	ctx := context.Background()
	var traffic *trafficCollector
	if *trafficReportPath != "" {
		traffic = newTrafficCollector()
		ctx = context.WithValue(ctx, trafficCollectorContextKey{}, traffic)
	}
	client := &http.Client{Timeout: cfg.httpTimeout}
	var report discoveryReport
	if cfg.scanMode == scanModeRetry {
		report = retryFailures(ctx, client, cfg, *existing)
	} else {
		report, err = discover(ctx, client, cfg)
	}
	if err != nil {
		fatal(err)
	}
	if traffic != nil {
		if err := writeTrafficReport(*trafficReportPath, traffic.snapshot(time.Now().UTC(), cfg.scanMode, report)); err != nil {
			fatal(err)
		}
	}
	if *outDir != "" {
		if err := writeShardedReport(*outDir, report); err != nil {
			fatal(err)
		}
		persisted, err := readShardedReport(*outDir)
		if err != nil {
			fatal(fmt.Errorf("verify persisted discovery ledger: %w", err))
		}
		if err := writeLedgerSummary(os.Stdout, summarizeLedger(persisted)); err != nil {
			fatal(err)
		}
		return
	}
	var writer io.Writer = os.Stdout
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		writer = file
	}
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fatal(err)
	}
}

func summarizeLedger(report discoveryReport) ledgerSummary {
	assemblyFiles := 0
	for _, item := range report.Matched {
		assemblyFiles += len(item.AsmFiles)
	}
	historyBefore := earliestIndexRangeLower(report.IndexRanges)
	historyTime, historyErr := time.Parse(time.RFC3339Nano, historyBefore)
	epoch, epochErr := time.Parse(time.RFC3339Nano, indexEpoch)
	return ledgerSummary{
		SchemaVersion:    report.SchemaVersion,
		HistoryBefore:    historyBefore,
		IncrementalSince: latestIndexRangeUpper(report.IndexRanges),
		HistoryComplete:  historyBefore != "" && historyErr == nil && epochErr == nil && !historyTime.After(epoch),
		IndexRanges:      len(report.IndexRanges),
		IndexEntries:     report.IndexEntries,
		UniqueModules:    report.UniqueModules,
		ScannedRecords:   len(report.Scanned),
		MatchedRecords:   len(report.Matched),
		AssemblyFiles:    assemblyFiles,
		FailureRecords:   len(report.Failures),
	}
}

func writeLedgerSummary(w io.Writer, summary ledgerSummary) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return fmt.Errorf("write discovery ledger summary: %w", err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func validateConfig(cfg config) error {
	if _, err := url.ParseRequestURI(cfg.indexURL); err != nil {
		return fmt.Errorf("invalid index URL: %w", err)
	}
	if _, err := url.ParseRequestURI(cfg.proxyURL); err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	if cfg.scanMode != scanModeHistory && cfg.scanMode != scanModeIncremental && cfg.scanMode != scanModeRetry {
		return fmt.Errorf("invalid -scan-mode %q: want %s, %s, or %s", cfg.scanMode, scanModeHistory, scanModeIncremental, scanModeRetry)
	}
	if cfg.scanMode != scanModeRetry {
		if _, err := time.Parse(time.RFC3339Nano, cfg.before); err != nil {
			return fmt.Errorf("invalid -before timestamp: %w", err)
		}
		after, err := time.Parse(time.RFC3339Nano, cfg.after)
		if err != nil {
			return fmt.Errorf("invalid lower index bound: %w", err)
		}
		before, _ := time.Parse(time.RFC3339Nano, cfg.before)
		if before.Before(after) {
			return errors.New("index upper bound must not precede its lower bound")
		}
	}
	if cfg.limit < 0 {
		return errors.New("-limit must be nonnegative")
	}
	if cfg.workers <= 0 {
		return errors.New("-workers must be positive")
	}
	if cfg.maxZipSize <= 0 {
		return errors.New("-max-zip-bytes must be positive")
	}
	if cfg.httpTimeout <= 0 {
		return errors.New("-http-timeout must be positive")
	}
	return nil
}

func scanLimit(mode string, requested int) int {
	if mode == scanModeIncremental {
		return 0
	}
	return requested
}

func resolveScanWindow(existing *discoveryReport, mode, requestedBefore string, now time.Time) (scanWindow, error) {
	if mode != scanModeHistory && mode != scanModeIncremental {
		return scanWindow{}, fmt.Errorf("invalid -scan-mode %q: want %s or %s", mode, scanModeHistory, scanModeIncremental)
	}
	if mode == scanModeHistory {
		derived := ""
		if existing != nil {
			derived = earliestIndexRangeLower(existing.IndexRanges)
			if derived == "" {
				derived = existing.NextBefore
			}
		}
		if requestedBefore != "" && derived != "" && requestedBefore != derived {
			return scanWindow{}, fmt.Errorf("-before %q does not match derived history cursor %q; omit -before to continue without a gap", requestedBefore, derived)
		}
		before := requestedBefore
		if before == "" {
			before = derived
		}
		if before == "" {
			before = now.UTC().Format(time.RFC3339Nano)
		}
		return scanWindow{Before: before, After: indexEpoch}, nil
	}
	after := ""
	if existing != nil {
		after = latestIndexRangeUpper(existing.IndexRanges)
		if after == "" && !existing.GeneratedAt.IsZero() {
			after = existing.GeneratedAt.UTC().Format(time.RFC3339Nano)
		}
	}
	if after == "" {
		after = now.UTC().Format(time.RFC3339Nano)
	}
	before := requestedBefore
	if before == "" {
		before = now.UTC().Format(time.RFC3339Nano)
	}
	return scanWindow{Before: before, After: after}, nil
}

func retryFailures(ctx context.Context, client *http.Client, cfg config, existing discoveryReport) discoveryReport {
	modules := modulesForFailureRetry(existing)
	matched, failures, scanned, skipped := inspectModules(
		ctx, client, cfg.proxyURL, modules, cfg.seen, cfg.sourceSeen, cfg.workers, cfg.maxZipSize,
	)
	return discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Now().UTC(),
		UniqueModules: len(modules),
		Skipped:       skipped,
		Scanned:       scanned,
		Matched:       matched,
		Failures:      failures,
	}
}

func modulesForFailureRetry(report discoveryReport) []moduleVersion {
	checkpoints := make(map[string]moduleCheckpoint)
	for _, item := range report.Failures {
		chooseModuleCheckpoint(checkpoints, item.Module, item.Version)
	}
	modules := make([]moduleVersion, 0, len(checkpoints))
	for _, item := range checkpoints {
		modules = append(modules, moduleVersion{Path: item.Path, Version: item.Version})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules
}

func latestIndexRangeUpper(ranges []indexRange) string {
	var latest string
	for _, item := range ranges {
		if latest == "" || timestampBefore(latest, item.Before) {
			latest = item.Before
		}
	}
	return latest
}

func earliestIndexRangeLower(ranges []indexRange) string {
	var earliest string
	for _, item := range ranges {
		if earliest == "" || timestampBefore(item.Since, earliest) {
			earliest = item.Since
		}
	}
	return earliest
}

func reverseIndexSpanHint(existing *discoveryReport, window scanWindow) time.Duration {
	if existing == nil {
		return time.Hour
	}
	for _, item := range existing.IndexRanges {
		if item.IndexEntries <= 0 || item.Since != window.Before && item.Before != window.After {
			continue
		}
		since, sinceErr := time.Parse(time.RFC3339Nano, item.Since)
		before, beforeErr := time.Parse(time.RFC3339Nano, item.Before)
		if sinceErr != nil || beforeErr != nil || !before.After(since) {
			continue
		}
		hint := time.Duration(float64(before.Sub(since)) * float64(reversePageTarget) / float64(item.IndexEntries))
		if hint > 0 {
			return hint
		}
	}
	return time.Hour
}

func discover(ctx context.Context, client *http.Client, cfg config) (discoveryReport, error) {
	entries, nextBefore, err := readIndexBackwardsFromWithHint(ctx, client, cfg.indexURL, cfg.before, cfg.after, cfg.limit, cfg.indexSpanHint)
	if err != nil {
		return discoveryReport{}, err
	}
	if err := validateFetchedIndexWindow(entries, nextBefore, cfg.before, cfg.after); err != nil {
		return discoveryReport{}, err
	}
	modules, skippedModules := modulesNeedingInspection(entries, cfg.checkpoints)
	uniqueModules := len(modules) + skippedModules

	matched, failures, scanned, skipped := inspectModules(ctx, client, cfg.proxyURL, modules, cfg.seen, cfg.sourceSeen, cfg.workers, cfg.maxZipSize)
	report := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Now().UTC(),
		ScanDirection: cfg.scanMode,
		IndexEntries:  len(entries),
		UniqueModules: uniqueModules,
		Skipped:       skippedModules + skipped,
		Scanned:       scanned,
		Matched:       matched,
		Failures:      failures,
	}
	report.IndexRanges = []indexRange{{
		Since: nextBefore, Before: cfg.before, IndexEntries: len(entries),
	}}
	return report, nil
}

func validateFetchedIndexWindow(entries []indexEntry, nextBefore, before, after string) error {
	nextTime, err := time.Parse(time.RFC3339Nano, nextBefore)
	if err != nil {
		return fmt.Errorf("invalid returned index cursor %q: %w", nextBefore, err)
	}
	beforeTime, err := time.Parse(time.RFC3339Nano, before)
	if err != nil {
		return fmt.Errorf("invalid index upper bound %q: %w", before, err)
	}
	afterTime, err := time.Parse(time.RFC3339Nano, after)
	if err != nil {
		return fmt.Errorf("invalid index lower bound %q: %w", after, err)
	}
	if nextTime.Before(afterTime) || nextTime.After(beforeTime) {
		return fmt.Errorf("returned index cursor %s is outside requested interval [%s,%s)", nextBefore, after, before)
	}
	if len(entries) == 0 {
		if !nextTime.Equal(afterTime) {
			return fmt.Errorf("empty index result stopped at %s instead of lower bound %s", nextBefore, after)
		}
		return nil
	}
	// A fully drained interval retains its requested lower bound, including
	// an empty prefix before the first record. Partial batches must still
	// stop at the first complete timestamp group so the next batch loses none.
	if !nextTime.Equal(afterTime) && !entries[0].Timestamp.Equal(nextTime) {
		return fmt.Errorf("returned index cursor %s does not equal first complete timestamp group %s", nextBefore, entries[0].Timestamp.Format(time.RFC3339Nano))
	}
	for i, entry := range entries {
		if entry.Timestamp.Before(nextTime) || !entry.Timestamp.Before(beforeTime) {
			return fmt.Errorf("index entry %s@%s timestamp %s is outside committed interval [%s,%s)", entry.Path, entry.Version, entry.Timestamp.Format(time.RFC3339Nano), nextBefore, before)
		}
		if i > 0 && entry.Timestamp.Before(entries[i-1].Timestamp) {
			return fmt.Errorf("index result is not ordered at %s@%s", entry.Path, entry.Version)
		}
	}
	return nil
}

func modulesNeedingInspection(entries []indexEntry, checkpoints map[string]moduleCheckpoint) ([]moduleVersion, int) {
	moduleSet := make(map[string]string, len(entries))
	for _, entry := range entries {
		// Module-path major has priority across a family; within one exact path,
		// retain the greatest Go semantic version regardless of index arrival
		// order. The index entry only triggers a fresh @latest resolution.
		if previous, ok := moduleSet[entry.Path]; !ok || compareModuleVersions(previous, entry.Version) < 0 {
			moduleSet[entry.Path] = entry.Version
		}
	}
	families := make(map[string]moduleVersion, len(moduleSet))
	for modulePath, indexedVersion := range moduleSet {
		item := moduleVersion{Path: modulePath, Version: indexedVersion}
		family := moduleFamily(modulePath)
		if previous, ok := families[family]; !ok || compareModuleCandidates(previous, item) < 0 {
			families[family] = item
		}
	}
	modules := make([]moduleVersion, 0, len(families))
	skipped := len(moduleSet) - len(families)
	for family, item := range families {
		checkpoint, ok := checkpoints[family]
		if ok && !indexedVersionMayBeNewer(item, checkpoint) {
			skipped++
			continue
		}
		modules = append(modules, item)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, skipped
}

func indexedVersionMayBeNewer(indexed moduleVersion, checkpoint moduleCheckpoint) bool {
	if checkpoint.Version == "@latest" && indexed.Path == checkpoint.Path {
		return false
	}
	return compareModuleCandidates(
		moduleVersion{Path: checkpoint.Path, Version: checkpoint.Version},
		indexed,
	) < 0
}

func loadSeenReports(paths []string) (map[string]seenResult, error) {
	seen, _, err := loadSeenState(paths)
	return seen, err
}

func loadSeenState(paths []string) (map[string]seenResult, map[string]seenResult, error) {
	seen := make(map[string]seenResult)
	sourceSeen := make(map[string]seenResult)
	for _, reportPath := range paths {
		report, err := readSeenReport(reportPath)
		if err != nil {
			return nil, nil, err
		}
		for _, item := range report.Scanned {
			if item.Path == "" || item.Version == "" {
				return nil, nil, fmt.Errorf("seen report %q contains an incomplete scanned version", reportPath)
			}
			rememberSeenResult(seen, scanKey(item), seenResult{})
			rememberSeenResult(sourceSeen, sourceScanKey(item), seenResult{})
		}
		// Older reports did not contain the complete scanned set, but their
		// successful matches are still safe to reuse.
		for _, item := range report.Matched {
			if item.Module != "" && item.Version != "" {
				version := moduleVersion{Path: item.Module, Version: item.Version}
				result := seenResult{Match: item}
				rememberSeenResult(seen, scanKey(version), result)
				rememberSeenResult(sourceSeen, sourceScanKey(version), result)
			}
		}
	}
	return seen, sourceSeen, nil
}

func rememberSeenResult(seen map[string]seenResult, key string, result seenResult) {
	if key == "" {
		return
	}
	previous, ok := seen[key]
	if !ok || previous.Match.Module == "" || result.Match.Module != "" {
		seen[key] = result
	}
}

func sourceScanKey(item moduleVersion) string {
	if !module.IsPseudoVersion(item.Version) {
		return ""
	}
	revision, err := module.PseudoVersionRev(item.Version)
	if err != nil || revision == "" {
		return ""
	}
	parts := strings.Split(item.Path, "/")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "github.com") {
		return ""
	}
	canonical := "github.com/" + strings.ToLower(parts[1]) + "/" + strings.ToLower(parts[2])
	if len(parts) > 3 {
		canonical += "/" + strings.Join(parts[3:], "/")
	}
	return "source\x00" + canonical + "\x00" + revision
}

func loadModuleCheckpoints(paths []string) (map[string]moduleCheckpoint, error) {
	checkpoints := make(map[string]moduleCheckpoint)
	for _, reportPath := range paths {
		report, err := readSeenReport(reportPath)
		if err != nil {
			return nil, err
		}
		for _, checkpoint := range moduleCheckpoints(report) {
			chooseModuleCheckpoint(checkpoints, checkpoint.Path, checkpoint.Version)
		}
	}
	return checkpoints, nil
}

func moduleCheckpoints(report discoveryReport) map[string]moduleCheckpoint {
	checkpoints := make(map[string]moduleCheckpoint)
	for _, item := range report.Scanned {
		chooseModuleCheckpoint(checkpoints, item.Path, item.Version)
	}
	for _, item := range report.Matched {
		chooseModuleCheckpoint(checkpoints, item.Module, item.Version)
	}
	for _, item := range report.Failures {
		chooseModuleCheckpoint(checkpoints, item.Module, item.Version)
	}
	return checkpoints
}

func chooseModuleCheckpoint(checkpoints map[string]moduleCheckpoint, modulePath, version string) {
	if modulePath == "" || version == "" {
		return
	}
	family := moduleFamily(modulePath)
	candidate := moduleCheckpoint{Path: modulePath, Version: version}
	previous, ok := checkpoints[family]
	if !ok || compareModuleCheckpoints(previous, candidate) < 0 {
		checkpoints[family] = candidate
	}
}

func moduleFamily(modulePath string) string {
	prefix, _, ok := module.SplitPathVersion(modulePath)
	if ok {
		return prefix
	}
	return modulePath
}

func compareModuleCandidates(a, b moduleVersion) int {
	return compareModuleCheckpoints(
		moduleCheckpoint{Path: a.Path, Version: a.Version},
		moduleCheckpoint{Path: b.Path, Version: b.Version},
	)
}

func compareModuleCheckpoints(a, b moduleCheckpoint) int {
	if a.Path == b.Path && (a.Version == "@latest" || b.Version == "@latest") {
		if a.Version == b.Version {
			return 0
		}
		if a.Version == "@latest" {
			return 1
		}
		return -1
	}
	aMajor := moduleMajor(a.Path, a.Version)
	bMajor := moduleMajor(b.Path, b.Version)
	if aMajor != bMajor {
		if aMajor < bMajor {
			return -1
		}
		return 1
	}
	if a.Version == "@latest" || b.Version == "@latest" {
		if a.Version == b.Version {
			return strings.Compare(a.Path, b.Path)
		}
		if a.Version == "@latest" {
			return 1
		}
		return -1
	}
	if compared := compareModuleVersions(a.Version, b.Version); compared != 0 {
		return compared
	}
	return strings.Compare(a.Path, b.Path)
}

func moduleMajor(modulePath, version string) int {
	_, pathMajor, ok := module.SplitPathVersion(modulePath)
	if ok && pathMajor != "" {
		raw := strings.TrimPrefix(strings.TrimPrefix(pathMajor, "/v"), ".v")
		if major, err := strconv.Atoi(raw); err == nil {
			return major
		}
	}
	major := strings.TrimPrefix(semver.Major(version), "v")
	parsed, _ := strconv.Atoi(major)
	return parsed
}

func readSeenReport(reportPath string) (discoveryReport, error) {
	info, err := os.Stat(reportPath)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read seen report %q: %w", reportPath, err)
	}
	if info.IsDir() {
		return readShardedReports(reportPath)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read seen report %q: %w", reportPath, err)
	}
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return discoveryReport{}, fmt.Errorf("decompress seen report %q: %w", reportPath, err)
		}
		data, err = io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			return discoveryReport{}, fmt.Errorf("decompress seen report %q: %w", reportPath, err)
		}
	}
	var report discoveryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return discoveryReport{}, fmt.Errorf("decode seen report %q: %w", reportPath, err)
	}
	return report, nil
}

func writeShardedReport(reportPath string, report discoveryReport) (returnErr error) {
	release, err := acquireLedgerLock(reportPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := release(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()

	exists := false
	if info, err := os.Stat(reportPath); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("write sharded report %q: path already exists and is not a directory", reportPath)
		}
		existing, err := readShardedReport(reportPath)
		if err != nil {
			return fmt.Errorf("update sharded report %q: %w", reportPath, err)
		}
		report, err = mergeDiscoveryReports(existing, report)
		if err != nil {
			return fmt.Errorf("update sharded report %q: %w", reportPath, err)
		}
		exists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("write sharded report %q: %w", reportPath, err)
	} else {
		var mergeErr error
		report, mergeErr = mergeDiscoveryReports(discoveryReport{}, report)
		if mergeErr != nil {
			return fmt.Errorf("write sharded report %q: %w", reportPath, mergeErr)
		}
	}

	parent := filepath.Dir(reportPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create sharded report parent %q: %w", parent, err)
	}
	temporary, err := os.MkdirTemp(parent, ".plan9asmdiscover-*")
	if err != nil {
		return fmt.Errorf("create temporary sharded report: %w", err)
	}
	defer os.RemoveAll(temporary)

	records := make(map[byte][]shardedRecord)
	add := func(record shardedRecord) {
		hash := sha256.Sum256([]byte(record.Module))
		records[hash[0]] = append(records[hash[0]], record)
	}
	for _, item := range report.Scanned {
		add(shardedRecord{Kind: "scanned", Module: item.Path, Version: item.Version})
	}
	for _, item := range report.Matched {
		add(shardedRecord{
			Kind:          "matched",
			Module:        item.Module,
			Version:       item.Version,
			Architectures: item.Architectures,
			AsmFiles:      item.AsmFiles,
		})
	}
	for _, item := range report.Failures {
		add(shardedRecord{Kind: "failure", Module: item.Module, Version: item.Version, Error: item.Error})
	}

	recordsDir := filepath.Join(temporary, "records")
	if err := os.Mkdir(recordsDir, 0o755); err != nil {
		return fmt.Errorf("create record shard directory: %w", err)
	}
	shards := make([]int, 0, len(records))
	for shard := range records {
		shards = append(shards, int(shard))
	}
	sort.Ints(shards)
	for _, shard := range shards {
		items := records[byte(shard)]
		sort.Slice(items, func(i, j int) bool {
			return compareShardedRecords(items[i], items[j]) < 0
		})
		name := filepath.Join(recordsDir, fmt.Sprintf("%02x.jsonl", shard))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("create record shard %q: %w", name, err)
		}
		encoder := json.NewEncoder(file)
		for _, item := range items {
			if err := encoder.Encode(item); err != nil {
				file.Close()
				return fmt.Errorf("write record shard %q: %w", name, err)
			}
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close record shard %q: %w", name, err)
		}
	}

	manifest := shardedManifest{
		SchemaVersion: report.SchemaVersion,
		Format:        shardedFormat,
		GeneratedAt:   report.GeneratedAt,
		Since:         report.Since,
		NextSince:     report.NextSince,
		ScanDirection: report.ScanDirection,
		NextBefore:    report.NextBefore,
		IndexRanges:   report.IndexRanges,
		IndexEntries:  report.IndexEntries,
		UniqueModules: report.UniqueModules,
		Skipped:       report.Skipped,
		Scanned:       len(report.Scanned),
		Matched:       len(report.Matched),
		Failures:      len(report.Failures),
		ShardKey:      "sha256(module)[0]",
	}
	manifestFile, err := os.OpenFile(filepath.Join(temporary, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create sharded report manifest: %w", err)
	}
	encoder := json.NewEncoder(manifestFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		manifestFile.Close()
		return fmt.Errorf("write sharded report manifest: %w", err)
	}
	if err := manifestFile.Close(); err != nil {
		return fmt.Errorf("close sharded report manifest: %w", err)
	}
	if !exists {
		if err := os.Rename(temporary, reportPath); err != nil {
			return fmt.Errorf("publish sharded report %q: %w", reportPath, err)
		}
		return nil
	}
	backup := temporary + "-previous"
	if err := os.Rename(reportPath, backup); err != nil {
		return fmt.Errorf("replace sharded report %q: preserve previous ledger: %w", reportPath, err)
	}
	if err := os.Rename(temporary, reportPath); err != nil {
		if restoreErr := os.Rename(backup, reportPath); restoreErr != nil {
			return fmt.Errorf("replace sharded report %q: %v (also failed to restore previous ledger: %v)", reportPath, err, restoreErr)
		}
		return fmt.Errorf("replace sharded report %q: %w", reportPath, err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove previous sharded report %q after replacement: %w", backup, err)
	}
	return nil
}

func acquireLedgerLock(reportPath string) (func() error, error) {
	parent := filepath.Dir(reportPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("create ledger parent %q: %w", parent, err)
	}
	lockPath := filepath.Join(parent, "."+filepath.Base(reportPath)+".writer-lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("another discovery writer holds %q; do not update one ledger concurrently", lockPath)
		}
		return nil, fmt.Errorf("lock discovery ledger %q: %w", reportPath, err)
	}
	return func() error {
		if err := os.Remove(lockPath); err != nil {
			return fmt.Errorf("unlock discovery ledger %q: %w", reportPath, err)
		}
		return nil
	}, nil
}

func upgradeDiscoveryReport(report discoveryReport) (discoveryReport, error) {
	switch report.SchemaVersion {
	case 0:
		report.SchemaVersion = discoverySchema
	case discoverySchema:
	default:
		return discoveryReport{}, fmt.Errorf("unsupported discovery schema %d", report.SchemaVersion)
	}
	if len(report.IndexRanges) == 0 {
		report.SchemaVersion = discoverySchema
		return report, nil
	}
	ranges, err := mergeIndexRanges(report.IndexRanges)
	if err != nil {
		return discoveryReport{}, err
	}
	report.IndexRanges = ranges
	report.Since = ""
	report.NextSince = ""
	report.NextBefore = ""
	report.ScanDirection = "bidirectional"
	if err := validateIndexCoverage(report.IndexRanges); err != nil {
		return discoveryReport{}, err
	}
	return report, nil
}

func validateIndexCoverage(ranges []indexRange) error {
	for i := 1; i < len(ranges); i++ {
		if timestampBefore(ranges[i].Since, ranges[i-1].Since) {
			return fmt.Errorf("index ranges are not in chronological order at [%s,%s)", ranges[i].Since, ranges[i].Before)
		}
		if ranges[i-1].Before != ranges[i].Since {
			return fmt.Errorf("index ranges [%s,%s) and [%s,%s) leave an unverified gap", ranges[i-1].Since, ranges[i-1].Before, ranges[i].Since, ranges[i].Before)
		}
	}
	return nil
}

func mergeDiscoveryReports(base, update discoveryReport) (discoveryReport, error) {
	var err error
	base, err = upgradeDiscoveryReport(base)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("upgrade base discovery report: %w", err)
	}
	update, err = upgradeDiscoveryReport(update)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("upgrade update discovery report: %w", err)
	}
	merged := discoveryReport{SchemaVersion: discoverySchema}
	merged.GeneratedAt = base.GeneratedAt
	if update.GeneratedAt.After(merged.GeneratedAt) {
		merged.GeneratedAt = update.GeneratedAt
	}
	merged.Since = earlierTimestamp(base.Since, update.Since)
	merged.NextSince = laterTimestamp(base.NextSince, update.NextSince)
	merged.ScanDirection = base.ScanDirection
	if update.ScanDirection != "" {
		merged.ScanDirection = update.ScanDirection
	}
	merged.IndexRanges, err = mergeIndexRanges(base.IndexRanges, update.IndexRanges)
	if err != nil {
		return discoveryReport{}, err
	}
	if len(merged.IndexRanges) > 0 {
		merged.ScanDirection = "bidirectional"
		merged.Since = ""
		merged.NextSince = ""
		merged.NextBefore = ""
		if err := validateIndexCoverage(merged.IndexRanges); err != nil {
			return discoveryReport{}, err
		}
		for _, item := range merged.IndexRanges {
			merged.IndexEntries += item.IndexEntries
		}
	} else {
		overlaps := discoveryRangesOverlap(base.Since, base.NextSince, update.Since, update.NextSince)
		merged.IndexEntries = mergeRunCount(base.IndexEntries, update.IndexEntries, overlaps)
	}
	overlaps := discoveryRangesOverlap(base.Since, base.NextSince, update.Since, update.NextSince) ||
		indexRangeSetsOverlap(base.IndexRanges, update.IndexRanges)
	if len(merged.IndexRanges) > 0 && len(base.IndexRanges) == 0 && len(update.IndexRanges) > 0 {
		// The first reverse range replaces the unprovable aggregate statistics
		// from legacy forward windows.
		merged.Skipped = update.Skipped
	} else {
		merged.Skipped = mergeRunCount(base.Skipped, update.Skipped, overlaps)
	}

	scanned := make(map[string]moduleVersion, len(base.Scanned)+len(update.Scanned)+len(base.Matched)+len(update.Matched))
	failures := make(map[string]scanFailure, len(base.Failures)+len(update.Failures))
	type candidateSets struct {
		candidate candidate
		arches    map[string]bool
		asmFiles  map[string]bool
	}
	// The active record for a module family is selected by module-path major
	// first and Go semantic version second, across both sides of the merge.
	// This is deliberately monotonic while history is scanned backwards: an
	// older index window may introduce /v3 after /v2 was already inspected,
	// but a still older /v2 record can never displace that /v3 checkpoint.
	// Exact failures participate too, keeping the highest version retryable.
	authoritative := make(map[string]moduleCheckpoint)
	for _, report := range []discoveryReport{base, update} {
		for _, item := range report.Scanned {
			chooseAuthoritativeVersion(authoritative, item.Path, item.Version)
		}
		for _, item := range report.Matched {
			chooseAuthoritativeVersion(authoritative, item.Module, item.Version)
		}
		for _, item := range report.Failures {
			chooseAuthoritativeVersion(authoritative, item.Module, item.Version)
		}
	}
	resolvedByUpdate := make(map[string]bool)
	markResolvedByUpdate := func(modulePath, version string) {
		if !semver.IsValid(version) {
			return
		}
		family := moduleFamily(modulePath)
		latest := authoritative[family]
		if latest.Path == modulePath && latest.Version == version {
			resolvedByUpdate[family] = true
		}
	}
	for _, item := range update.Scanned {
		markResolvedByUpdate(item.Path, item.Version)
	}
	for _, item := range update.Matched {
		markResolvedByUpdate(item.Module, item.Version)
	}
	for _, item := range update.Failures {
		markResolvedByUpdate(item.Module, item.Version)
	}
	keep := func(isUpdate bool, modulePath, version string) bool {
		latest, ok := authoritative[moduleFamily(modulePath)]
		if version == "@latest" {
			// A current resolution failure remains retryable alongside the last
			// known exact result. Only an authoritative exact resolution in this
			// update removes it; unrelated history batches must preserve it.
			return isUpdate || !resolvedByUpdate[moduleFamily(modulePath)]
		}
		return !ok || modulePath == latest.Path && version == latest.Version
	}
	matched := make(map[string]*candidateSets, len(base.Matched)+len(update.Matched))
	addCandidate := func(item candidate) {
		key := scanKey(moduleVersion{Path: item.Module, Version: item.Version})
		set := matched[key]
		if set == nil {
			set = &candidateSets{
				candidate: candidate{Module: item.Module, Version: item.Version},
				arches:    make(map[string]bool),
				asmFiles:  make(map[string]bool),
			}
			matched[key] = set
		}
		for _, arch := range item.Architectures {
			set.arches[arch] = true
		}
		for _, asmFile := range item.AsmFiles {
			set.asmFiles[asmFile] = true
		}
		scanned[key] = moduleVersion{Path: item.Module, Version: item.Version}
	}
	for reportIndex, report := range []discoveryReport{base, update} {
		isUpdate := reportIndex == 1
		for _, item := range report.Scanned {
			if !keep(isUpdate, item.Path, item.Version) {
				continue
			}
			scanned[scanKey(item)] = item
		}
		for _, item := range report.Matched {
			if !keep(isUpdate, item.Module, item.Version) {
				continue
			}
			addCandidate(item)
		}
		for _, item := range report.Failures {
			if !keep(isUpdate, item.Module, item.Version) {
				continue
			}
			failures[scanKey(moduleVersion{Path: item.Module, Version: item.Version})] = item
		}
	}
	modules := make(map[string]bool)
	for key, item := range scanned {
		merged.Scanned = append(merged.Scanned, item)
		modules[item.Path] = true
		delete(failures, key)
	}
	for _, set := range matched {
		for arch := range set.arches {
			set.candidate.Architectures = append(set.candidate.Architectures, arch)
		}
		for asmFile := range set.asmFiles {
			set.candidate.AsmFiles = append(set.candidate.AsmFiles, asmFile)
		}
		merged.Matched = append(merged.Matched, set.candidate)
		modules[set.candidate.Module] = true
	}
	for _, item := range failures {
		merged.Failures = append(merged.Failures, item)
		modules[item.Module] = true
	}
	merged.UniqueModules = len(modules)
	sortDiscoveryReport(&merged)
	return merged, nil
}

func indexRangeSetsOverlap(a, b []indexRange) bool {
	for _, left := range a {
		for _, right := range b {
			if timestampBefore(left.Since, right.Before) && timestampBefore(right.Since, left.Before) {
				return true
			}
		}
	}
	return false
}

func chooseAuthoritativeVersion(versions map[string]moduleCheckpoint, modulePath, version string) {
	if modulePath == "" || !semver.IsValid(version) {
		return
	}
	family := moduleFamily(modulePath)
	candidate := moduleCheckpoint{Path: modulePath, Version: version}
	if previous, ok := versions[family]; !ok || compareModuleCheckpoints(previous, candidate) < 0 {
		versions[family] = candidate
	}
}

func mergeIndexRanges(groups ...[]indexRange) ([]indexRange, error) {
	type timedIndexRange struct {
		value  indexRange
		since  time.Time
		before time.Time
	}
	var ranges []timedIndexRange
	for _, group := range groups {
		for _, item := range group {
			since, err := time.Parse(time.RFC3339Nano, item.Since)
			if err != nil {
				return nil, fmt.Errorf("invalid index range since %q: %w", item.Since, err)
			}
			before, err := time.Parse(time.RFC3339Nano, item.Before)
			if err != nil {
				return nil, fmt.Errorf("invalid index range before %q: %w", item.Before, err)
			}
			if since.After(before) || since.Equal(before) && item.IndexEntries != 0 {
				return nil, fmt.Errorf("invalid index range [%s,%s): since must precede before unless the range is an empty cursor anchor", item.Since, item.Before)
			}
			if item.IndexEntries < 0 {
				return nil, fmt.Errorf("invalid index range [%s,%s): index_entries must be nonnegative", item.Since, item.Before)
			}
			item.Since = since.UTC().Format(time.RFC3339Nano)
			item.Before = before.UTC().Format(time.RFC3339Nano)
			ranges = append(ranges, timedIndexRange{value: item, since: since.UTC(), before: before.UTC()})
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if !ranges[i].since.Equal(ranges[j].since) {
			return ranges[i].since.Before(ranges[j].since)
		}
		return ranges[i].before.Before(ranges[j].before)
	})
	normalized := make([]indexRange, 0, len(ranges))
	for _, timed := range ranges {
		item := timed.value
		if len(normalized) == 0 {
			normalized = append(normalized, item)
			continue
		}
		previous := &normalized[len(normalized)-1]
		if item.Since == previous.Since && item.Before == previous.Before {
			if item.IndexEntries != previous.IndexEntries {
				return nil, fmt.Errorf("index range [%s,%s) has conflicting entry counts %d and %d", item.Since, item.Before, previous.IndexEntries, item.IndexEntries)
			}
			continue
		}
		if timestampBefore(item.Since, previous.Before) {
			return nil, fmt.Errorf("index ranges [%s,%s) and [%s,%s) overlap; exact aggregate coverage is unknown", previous.Since, previous.Before, item.Since, item.Before)
		}
		normalized = append(normalized, item)
	}
	return normalized, nil
}

func discoveryRangesOverlap(aSince, aNext, bSince, bNext string) bool {
	if aSince == "" || aNext == "" || bSince == "" || bNext == "" {
		return false
	}
	return timestampBefore(aSince, bNext) && timestampBefore(bSince, aNext)
}

func timestampBefore(left, right string) bool {
	leftTime, leftErr := time.Parse(time.RFC3339Nano, left)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, right)
	if leftErr == nil && rightErr == nil {
		return leftTime.Before(rightTime)
	}
	return left < right
}

func mergeRunCount(base, update int, overlaps bool) int {
	if overlaps {
		if update > base {
			return update
		}
		return base
	}
	return base + update
}

func readShardedReports(reportPath string) (discoveryReport, error) {
	if _, err := os.Stat(filepath.Join(reportPath, "manifest.json")); err == nil {
		return readShardedReport(reportPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return discoveryReport{}, fmt.Errorf("read sharded report %q: %w", reportPath, err)
	}
	// Accept the former per-run tree only as an import source. Newly written
	// ledgers always have one manifest and one records directory at the root.
	var manifests []string
	err := filepath.WalkDir(reportPath, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "manifest.json" {
			manifests = append(manifests, name)
		}
		return nil
	})
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read sharded reports %q: %w", reportPath, err)
	}
	if len(manifests) == 0 {
		return discoveryReport{}, fmt.Errorf("read sharded reports %q: no manifest.json found", reportPath)
	}
	sort.Strings(manifests)
	var combined discoveryReport
	for _, manifestPath := range manifests {
		report, err := readShardedReport(filepath.Dir(manifestPath))
		if err != nil {
			return discoveryReport{}, err
		}
		combined, err = mergeDiscoveryReports(combined, report)
		if err != nil {
			return discoveryReport{}, fmt.Errorf("read sharded reports %q: %w", reportPath, err)
		}
	}
	return combined, nil
}

func earlierTimestamp(current, candidate string) string {
	if current == "" || candidate != "" && timestampBefore(candidate, current) {
		return candidate
	}
	return current
}

func laterTimestamp(current, candidate string) string {
	if candidate != "" && (current == "" || timestampBefore(current, candidate)) {
		return candidate
	}
	return current
}

func readShardedReport(reportPath string) (discoveryReport, error) {
	manifestPath := filepath.Join(reportPath, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("read sharded report manifest %q: %w", manifestPath, err)
	}
	var manifest shardedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: %w", manifestPath, err)
	}
	if manifest.Format != shardedFormat {
		return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: unsupported format %q", manifestPath, manifest.Format)
	}
	if manifest.SchemaVersion != discoverySchema {
		return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: unsupported schema %d", manifestPath, manifest.SchemaVersion)
	}
	if manifest.ShardKey != "sha256(module)[0]" {
		return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: unsupported shard key %q", manifestPath, manifest.ShardKey)
	}
	report := discoveryReport{
		SchemaVersion: manifest.SchemaVersion,
		GeneratedAt:   manifest.GeneratedAt,
		Since:         manifest.Since,
		NextSince:     manifest.NextSince,
		ScanDirection: manifest.ScanDirection,
		NextBefore:    manifest.NextBefore,
		IndexRanges:   manifest.IndexRanges,
		IndexEntries:  manifest.IndexEntries,
		UniqueModules: manifest.UniqueModules,
		Skipped:       manifest.Skipped,
	}
	if len(report.IndexRanges) > 0 {
		report, err = upgradeDiscoveryReport(report)
		if err != nil {
			return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: %w", manifestPath, err)
		}
		entries := 0
		for _, item := range report.IndexRanges {
			entries += item.IndexEntries
		}
		if entries != manifest.IndexEntries {
			return discoveryReport{}, fmt.Errorf("decode sharded report manifest %q: index range count is %d, want index_entries %d", manifestPath, entries, manifest.IndexEntries)
		}
	}
	recordsDir := filepath.Join(reportPath, "records")
	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		return discoveryReport{}, fmt.Errorf("list sharded report records %q: %w", reportPath, err)
	}
	shards := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != len("00.jsonl") || !strings.HasSuffix(name, ".jsonl") {
			return discoveryReport{}, fmt.Errorf("list sharded report records %q: unexpected entry %q", reportPath, name)
		}
		if _, err := strconv.ParseUint(name[:2], 16, 8); err != nil {
			return discoveryReport{}, fmt.Errorf("list sharded report records %q: invalid shard name %q", reportPath, name)
		}
		shards = append(shards, filepath.Join(recordsDir, name))
	}
	sort.Strings(shards)
	for _, shard := range shards {
		shardNumber, _ := strconv.ParseUint(filepath.Base(shard)[:2], 16, 8)
		file, err := os.Open(shard)
		if err != nil {
			return discoveryReport{}, fmt.Errorf("read record shard %q: %w", shard, err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 16<<20)
		line := 0
		var previous shardedRecord
		for scanner.Scan() {
			line++
			var item shardedRecord
			if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
				file.Close()
				return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: %w", shard, line, err)
			}
			if item.Module == "" || item.Version == "" {
				file.Close()
				return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: incomplete module version", shard, line)
			}
			hash := sha256.Sum256([]byte(item.Module))
			if hash[0] != byte(shardNumber) {
				file.Close()
				return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: module %q belongs in %02x.jsonl", shard, line, item.Module, hash[0])
			}
			if line > 1 && compareShardedRecords(previous, item) >= 0 {
				file.Close()
				return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: records are duplicated or not in module/semver/kind order", shard, line)
			}
			previous = item
			switch item.Kind {
			case "scanned":
				if !semver.IsValid(item.Version) {
					file.Close()
					return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: invalid scanned module version %q", shard, line, item.Version)
				}
				report.Scanned = append(report.Scanned, moduleVersion{Path: item.Module, Version: item.Version})
			case "matched":
				if !semver.IsValid(item.Version) {
					file.Close()
					return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: invalid matched module version %q", shard, line, item.Version)
				}
				report.Matched = append(report.Matched, candidate{
					Module: item.Module, Version: item.Version,
					Architectures: item.Architectures, AsmFiles: item.AsmFiles,
				})
			case "failure":
				report.Failures = append(report.Failures, scanFailure{Module: item.Module, Version: item.Version, Error: item.Error})
			default:
				file.Close()
				return discoveryReport{}, fmt.Errorf("decode record shard %s:%d: unknown record kind %q", shard, line, item.Kind)
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return discoveryReport{}, fmt.Errorf("read record shard %q: %w", shard, scanErr)
		}
		if closeErr != nil {
			return discoveryReport{}, fmt.Errorf("close record shard %q: %w", shard, closeErr)
		}
	}
	if len(report.Scanned) != manifest.Scanned || len(report.Matched) != manifest.Matched || len(report.Failures) != manifest.Failures {
		return discoveryReport{}, fmt.Errorf(
			"read sharded report %q: record counts are scanned=%d/%d matched=%d/%d failures=%d/%d",
			reportPath, len(report.Scanned), manifest.Scanned, len(report.Matched), manifest.Matched, len(report.Failures), manifest.Failures,
		)
	}
	sortDiscoveryReport(&report)
	return report, nil
}

func sortDiscoveryReport(report *discoveryReport) {
	sort.Slice(report.Scanned, func(i, j int) bool {
		if report.Scanned[i].Path != report.Scanned[j].Path {
			return report.Scanned[i].Path < report.Scanned[j].Path
		}
		return compareModuleVersions(report.Scanned[i].Version, report.Scanned[j].Version) < 0
	})
	for i := range report.Matched {
		sort.Strings(report.Matched[i].AsmFiles)
		report.Matched[i].Architectures = discoverymeta.ArchitectureHints(report.Matched[i].AsmFiles)
	}
	sort.Slice(report.Matched, func(i, j int) bool {
		if report.Matched[i].Module != report.Matched[j].Module {
			return report.Matched[i].Module < report.Matched[j].Module
		}
		return compareModuleVersions(report.Matched[i].Version, report.Matched[j].Version) < 0
	})
	sort.Slice(report.Failures, func(i, j int) bool {
		if report.Failures[i].Module != report.Failures[j].Module {
			return report.Failures[i].Module < report.Failures[j].Module
		}
		return compareModuleVersions(report.Failures[i].Version, report.Failures[j].Version) < 0
	})
}

func compareModuleVersions(a, b string) int {
	aValid, bValid := semver.IsValid(a), semver.IsValid(b)
	if aValid && bValid {
		if compared := semver.Compare(a, b); compared != 0 {
			return compared
		}
	} else if aValid != bValid {
		if aValid {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func compareShardedRecords(a, b shardedRecord) int {
	if compared := strings.Compare(a.Module, b.Module); compared != 0 {
		return compared
	}
	if compared := compareModuleVersions(a.Version, b.Version); compared != 0 {
		return compared
	}
	return strings.Compare(a.Kind, b.Kind)
}

func scanKey(module moduleVersion) string {
	return module.Path + "\x00" + module.Version
}

func readIndex(ctx context.Context, client *http.Client, endpoint, since string, limit int) ([]indexEntry, string, error) {
	var entries []indexEntry
	cursor := since
	seen := make(map[string]struct{})
	seenAt := make(map[string]int)
	for limit == 0 || len(entries) < limit {
		pageSize := indexPageLimit
		if limit > 0 {
			pageSize = limit - len(entries) + seenAt[cursor]
			if pageSize > indexPageLimit {
				pageSize = indexPageLimit
			}
		}
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, "", err
		}
		query := parsed.Query()
		query.Set("limit", fmt.Sprint(pageSize))
		if cursor != "" {
			query.Set("since", cursor)
		}
		parsed.RawQuery = query.Encode()

		resp, err := doHTTPRequest(ctx, client, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return nil, "", fmt.Errorf("read module index: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, "", fmt.Errorf("read module index: %s", resp.Status)
		}
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		page := make([]indexEntry, 0, pageSize)
		for scanner.Scan() {
			var entry indexEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				resp.Body.Close()
				return nil, "", fmt.Errorf("decode module index: %w", err)
			}
			if entry.Path == "" || entry.Timestamp.IsZero() {
				resp.Body.Close()
				return nil, "", errors.New("module index entry is missing Path or Timestamp")
			}
			page = append(page, entry)
		}
		scanErr := scanner.Err()
		resp.Body.Close()
		if scanErr != nil {
			return nil, "", fmt.Errorf("read module index: %w", scanErr)
		}
		if len(page) == 0 {
			break
		}
		newEntries := 0
		for _, entry := range page {
			timestamp := entry.Timestamp.Format(time.RFC3339Nano)
			key := entry.Path + "\x00" + entry.Version + "\x00" + timestamp
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			seenAt[timestamp]++
			entries = append(entries, entry)
			newEntries++
			cursor = timestamp
			if limit > 0 && len(entries) == limit {
				break
			}
		}
		if limit > 0 && len(entries) == limit {
			break
		}
		if len(page) < pageSize {
			break
		}
		lastTimestamp := page[len(page)-1].Timestamp.Format(time.RFC3339Nano)
		if newEntries == 0 && lastTimestamp == cursor {
			cursor = page[len(page)-1].Timestamp.Add(time.Nanosecond).Format(time.RFC3339Nano)
		} else {
			cursor = lastTimestamp
		}
	}
	return entries, cursor, nil
}

// readIndexBackwards returns the newest index entries strictly before before.
// index.golang.org only exposes an ascending `since` API, so each reverse page
// brackets a small time window whose complete contents fit in one server page,
// then keeps its newest entries. The earliest timestamp group is kept whole so
// the returned cursor can be used as an exclusive upper bound without losing
// entries that share a timestamp.
func readIndexBackwards(ctx context.Context, client *http.Client, endpoint, before string, limit int) ([]indexEntry, string, error) {
	return readIndexBackwardsFromWithHint(ctx, client, endpoint, before, indexEpoch, limit, time.Hour)
}

// readIndexBackwardsFrom returns newest entries in [after,before). Keeping the
// lower bound explicit lets the completed history scan later reuse the same
// timestamp-safe reverse reader for only the newly published head interval.
func readIndexBackwardsFrom(ctx context.Context, client *http.Client, endpoint, before, after string, limit int) ([]indexEntry, string, error) {
	return readIndexBackwardsFromWithHint(ctx, client, endpoint, before, after, limit, time.Hour)
}

func readIndexBackwardsFromWithHint(ctx context.Context, client *http.Client, endpoint, before, after string, limit int, initialSpanHint time.Duration) ([]indexEntry, string, error) {
	upper, err := time.Parse(time.RFC3339Nano, before)
	if err != nil {
		return nil, "", fmt.Errorf("invalid reverse index cursor %q: %w", before, err)
	}
	lowerBound, err := time.Parse(time.RFC3339Nano, after)
	if err != nil {
		return nil, "", fmt.Errorf("invalid reverse index lower bound %q: %w", after, err)
	}
	if upper.Before(lowerBound) {
		return nil, "", fmt.Errorf("reverse index cursor %s precedes lower bound %s", before, after)
	}
	if limit < 0 {
		return nil, "", errors.New("reverse index limit must be nonnegative")
	}
	var entries []indexEntry
	spanHint := initialSpanHint
	if spanHint <= 0 {
		spanHint = time.Hour
	}
	for limit == 0 || len(entries) < limit {
		target := reversePageTarget
		if limit > 0 && limit-len(entries) < target {
			target = limit - len(entries)
		}
		page, nextSpanHint, err := readIndexPageBefore(ctx, client, endpoint, upper, lowerBound, target, spanHint)
		if err != nil {
			return nil, "", err
		}
		if len(page) == 0 {
			upper = lowerBound
			break
		}
		entries = append(entries, page...)
		upper = page[0].Timestamp
		spanHint = nextSpanHint
		if limit > 0 && limit-len(entries) > 0 && limit-len(entries) < reversePageTarget/10 {
			break
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].Timestamp.Equal(entries[j].Timestamp) {
			return entries[i].Timestamp.Before(entries[j].Timestamp)
		}
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return compareModuleVersions(entries[i].Version, entries[j].Version) < 0
	})
	return entries, upper.Format(time.RFC3339Nano), nil
}

func readIndexPageBefore(ctx context.Context, client *http.Client, endpoint string, upper, lowerBound time.Time, target int, spanHint time.Duration) ([]indexEntry, time.Duration, error) {
	if target <= 0 || target > reversePageTarget {
		return nil, 0, fmt.Errorf("reverse index page target %d is outside 1..%d", target, reversePageTarget)
	}
	if !upper.After(lowerBound) {
		return nil, spanHint, nil
	}
	var narrow, wide time.Duration
	span := spanHint
	if span <= 0 {
		span = time.Hour
	}
	for attempts := 0; attempts < 80; attempts++ {
		lower := upper.Add(-span)
		if lower.Before(lowerBound) {
			lower = lowerBound
		}
		page, err := fetchIndexPage(ctx, client, endpoint, lower.Format(time.RFC3339Nano), indexPageLimit)
		if err != nil {
			return nil, 0, err
		}
		complete := len(page) < indexPageLimit
		if len(page) > 0 && !page[len(page)-1].Timestamp.Before(upper) {
			complete = true
		}
		cut := sort.Search(len(page), func(i int) bool { return !page[i].Timestamp.Before(upper) })
		beforeEntries := page[:cut]
		minimumUseful := (target + 1) / 2
		if complete && (len(beforeEntries) >= minimumUseful || lower.Equal(lowerBound)) {
			if len(beforeEntries) <= target {
				selected := append([]indexEntry(nil), beforeEntries...)
				return selected, nextReverseSpanHint(upper, selected, target, span), nil
			}
			first := len(beforeEntries) - target
			boundary := beforeEntries[first].Timestamp
			for first > 0 && beforeEntries[first-1].Timestamp.Equal(boundary) {
				first--
			}
			selected := append([]indexEntry(nil), beforeEntries[first:]...)
			return selected, nextReverseSpanHint(upper, selected, target, span), nil
		}

		if complete {
			narrow = span
			if wide == 0 {
				span *= 2
			} else {
				span = narrow + (wide-narrow)/2
			}
		} else {
			wide = span
			span = narrow + (wide-narrow)/2
		}
		if span <= 0 || wide > 0 && wide-narrow <= time.Nanosecond {
			return nil, 0, fmt.Errorf("cannot isolate %d index entries before %s in one page", target, upper.Format(time.RFC3339Nano))
		}
	}
	return nil, 0, fmt.Errorf("cannot bracket %d index entries before %s", target, upper.Format(time.RFC3339Nano))
}

func nextReverseSpanHint(upper time.Time, selected []indexEntry, target int, fallback time.Duration) time.Duration {
	if len(selected) == 0 {
		return fallback
	}
	observed := upper.Sub(selected[0].Timestamp)
	if observed <= 0 {
		return time.Nanosecond
	}
	hint := time.Duration(float64(observed) * float64(target) / float64(len(selected)))
	if hint <= 0 {
		return time.Nanosecond
	}
	return hint
}

func fetchIndexPage(ctx context.Context, client *http.Client, endpoint, since string, limit int) ([]indexEntry, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	query.Set("limit", strconv.Itoa(limit))
	if since != "" {
		query.Set("since", since)
	}
	parsed.RawQuery = query.Encode()
	resp, err := doHTTPRequest(ctx, client, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("read module index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read module index: %s", resp.Status)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	entries := make([]indexEntry, 0, limit)
	for scanner.Scan() {
		var entry indexEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("decode module index: %w", err)
		}
		if entry.Path == "" || entry.Timestamp.IsZero() {
			return nil, errors.New("module index entry is missing Path or Timestamp")
		}
		if len(entries) > 0 && entry.Timestamp.Before(entries[len(entries)-1].Timestamp) {
			return nil, fmt.Errorf("module index page is not ordered by timestamp: %s precedes %s", entry.Timestamp.Format(time.RFC3339Nano), entries[len(entries)-1].Timestamp.Format(time.RFC3339Nano))
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read module index: %w", err)
	}
	return entries, nil
}

func inspectModules(ctx context.Context, client *http.Client, proxyURL string, modules []moduleVersion, seen, sourceSeen map[string]seenResult, workers int, maxZipSize int64) ([]candidate, []scanFailure, []moduleVersion, int) {
	sourceCache := newSourceInspectionCache(sourceSeen)
	tasks := make(chan moduleVersion)
	results := make(chan candidate)
	errorsOut := make(chan scanFailure)
	completed := make(chan moduleVersion)
	reused := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for module := range tasks {
				moduleCtx := withTrafficModule(ctx, module.Path)
				collector, _ := trafficContext(moduleCtx)
				if collector != nil {
					collector.setModuleScan(module.Path, module.Version, "", "")
				}
				item, latest, didScan, wasReused, err := inspectLatestModule(moduleCtx, client, proxyURL, module.Path, seen, sourceCache, maxZipSize)
				if collector != nil {
					outcome := "scanned"
					switch {
					case err != nil:
						outcome = "failure"
					case wasReused:
						outcome = "reused_scanned"
						if len(item.AsmFiles) > 0 {
							outcome = "reused_matched"
						}
					case len(item.AsmFiles) > 0:
						outcome = "matched"
					}
					collector.setModuleScan(module.Path, module.Version, latest.Version, outcome)
				}
				if didScan || wasReused {
					completed <- latest
				}
				if wasReused {
					reused <- struct{}{}
				}
				if err != nil {
					errorsOut <- scanFailure{Module: latest.Path, Version: latest.Version, Error: err.Error()}
					continue
				}
				if len(item.AsmFiles) > 0 {
					results <- item
				}
			}
		}()
	}
	go func() {
		for _, module := range modules {
			tasks <- module
		}
		close(tasks)
		wg.Wait()
		close(results)
		close(errorsOut)
		close(completed)
		close(reused)
	}()

	matched := make([]candidate, 0)
	failures := make([]scanFailure, 0)
	scannedSet := make(map[string]moduleVersion)
	skipped := 0
	for results != nil || errorsOut != nil || completed != nil || reused != nil {
		select {
		case item, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			matched = append(matched, item)
		case failure, ok := <-errorsOut:
			if !ok {
				errorsOut = nil
				continue
			}
			failures = append(failures, failure)
		case item, ok := <-completed:
			if !ok {
				completed = nil
				continue
			}
			scannedSet[scanKey(item)] = item
		case _, ok := <-reused:
			if !ok {
				reused = nil
				continue
			}
			skipped++
		}
	}
	scanned := make([]moduleVersion, 0, len(scannedSet))
	for _, item := range scannedSet {
		scanned = append(scanned, item)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Module < matched[j].Module })
	sort.Slice(failures, func(i, j int) bool { return failures[i].Module < failures[j].Module })
	sort.Slice(scanned, func(i, j int) bool {
		if scanned[i].Path != scanned[j].Path {
			return scanned[i].Path < scanned[j].Path
		}
		return scanned[i].Version < scanned[j].Version
	})
	return matched, failures, scanned, skipped
}

func inspectLatestModule(ctx context.Context, client *http.Client, proxyURL, modulePath string, seen map[string]seenResult, sourceCache *sourceInspectionCache, maxZipSize int64) (candidate, moduleVersion, bool, bool, error) {
	latest := moduleVersion{Path: modulePath, Version: "@latest"}
	latestVersion, err := resolveLatest(ctx, client, proxyURL, modulePath)
	if err != nil {
		return candidate{}, latest, false, false, err
	}
	latest.Version = latestVersion
	if previous, ok := seen[scanKey(latest)]; ok {
		return previous.Match, latest, false, true, nil
	}
	item, sourceReused, err := sourceCache.inspect(ctx, sourceScanKey(latest), func() (candidate, error) {
		return inspectModuleVersion(ctx, client, proxyURL, modulePath, latestVersion, maxZipSize)
	})
	if err != nil {
		return candidate{}, latest, false, false, err
	}
	if sourceReused && item.Module != "" {
		item.Module = modulePath
		item.Version = latestVersion
	}
	return item, latest, !sourceReused, sourceReused, nil
}

func resolveLatest(ctx context.Context, client *http.Client, proxyURL, modulePath string) (string, error) {
	escapedModule, err := escapeProxyPath(modulePath)
	if err != nil {
		return "", err
	}
	latestURL := proxyURL + "/" + escapedModule + "/@latest"
	latestBody, err := get(ctx, client, latestURL, 1<<20)
	if err != nil {
		return "", fmt.Errorf("resolve @latest: %w", err)
	}
	var latest latestInfo
	if err := json.Unmarshal(latestBody, &latest); err != nil {
		return "", fmt.Errorf("decode @latest: %w", err)
	}
	if latest.Version == "" {
		return "", errors.New("decode @latest: missing Version")
	}
	return latest.Version, nil
}

func inspectModuleVersion(ctx context.Context, client *http.Client, proxyURL, modulePath, version string, maxZipSize int64) (candidate, error) {
	escapedModule, err := escapeProxyPath(modulePath)
	if err != nil {
		return candidate{}, err
	}
	escapedVersion, err := escapeProxyPath(version)
	if err != nil {
		return candidate{}, err
	}
	zipURL := proxyURL + "/" + escapedModule + "/@v/" + escapedVersion + ".zip"
	reader, zipSize, err := newHTTPReaderAt(ctx, client, zipURL, maxZipSize)
	if err != nil {
		return candidate{}, fmt.Errorf("open %s ZIP: %w", version, err)
	}
	files, arches, err := inspectModuleZipReader(reader, zipSize)
	if err != nil {
		return candidate{}, fmt.Errorf("inspect %s: %w", version, err)
	}
	return candidate{Module: modulePath, Version: version, Architectures: arches, AsmFiles: files}, nil
}

func get(ctx context.Context, client *http.Client, endpoint string, maxBytes int64) ([]byte, error) {
	resp, err := doHTTPRequest(ctx, client, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("response is %d bytes (limit %d)", resp.ContentLength, maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func inspectModuleZip(data []byte) ([]string, []string, error) {
	return inspectModuleZipReader(bytes.NewReader(data), int64(len(data)))
}

func inspectModuleZipReader(reader io.ReaderAt, size int64) ([]string, []string, error) {
	zr, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, nil, err
	}
	type asmEntry struct {
		name string
		file *zip.File
	}
	asmFiles := make([]asmEntry, 0)
	goDirs := make(map[string]struct{})
	for _, file := range zr.File {
		name := file.Name
		at := strings.IndexByte(name, '@')
		if at < 0 {
			continue
		}
		rootSlash := strings.IndexByte(name[at:], '/')
		if rootSlash < 0 {
			continue
		}
		rootSlash += at
		if rootSlash == len(name)-1 {
			continue
		}
		rel := name[rootSlash+1:]
		if containsPathElement(rel, "testdata") {
			continue
		}
		switch path.Ext(rel) {
		case ".go":
			goDirs[path.Dir(rel)] = struct{}{}
		case ".s":
			if file.UncompressedSize64 > 0 {
				asmFiles = append(asmFiles, asmEntry{name: rel, file: file})
			}
		}
	}
	files := make([]string, 0, len(asmFiles))
	archSet := make(map[string]struct{})
	for _, asm := range asmFiles {
		if _, ok := goDirs[path.Dir(asm.name)]; !ok {
			continue
		}
		hasContent, err := zipAssemblyFileHasContent(asm.file)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", asm.name, err)
		}
		if !hasContent {
			continue
		}
		files = append(files, asm.name)
		archSet[inferAssemblyArchitecture(asm.name)] = struct{}{}
	}
	arches := make([]string, 0, len(archSet))
	for arch := range archSet {
		arches = append(arches, arch)
	}
	sort.Strings(files)
	sort.Strings(arches)
	return files, arches, nil
}

func zipAssemblyFileHasContent(file *zip.File) (bool, error) {
	if file.UncompressedSize64 > maxAsmProbeSize {
		// Keep unusually large files in the candidate set so the corpus stage can
		// validate them; discovery must not silently discard code it did not read.
		return true, nil
	}
	r, err := file.Open()
	if err != nil {
		return false, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxAsmProbeSize+1))
	if err != nil {
		return false, err
	}
	if len(data) > maxAsmProbeSize {
		return true, nil
	}
	return assemblySourceHasContent(data), nil
}

func assemblySourceHasContent(data []byte) bool {
	for i := 0; i < len(data); {
		switch {
		case data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n' || data[i] == '\f':
			i++
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '/':
			i += 2
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return true
			}
			i += end + 4
		default:
			return true
		}
	}
	return false
}

type remoteZipReaderAt struct {
	ctx             context.Context
	client          *http.Client
	endpoint        string
	cachedTail      []byte
	cachedDirectory []byte
	cacheMu         sync.Mutex
	cachedData      map[int64][]byte
	tailStart       int64
	directoryStart  int64
	size            int64
}

func newHTTPReaderAt(ctx context.Context, client *http.Client, endpoint string, maxSize int64) (io.ReaderAt, int64, error) {
	return newHTTPReaderAtWithTail(ctx, client, endpoint, maxSize, zipEOCDSize)
}

func newHTTPReaderAtWithTail(ctx context.Context, client *http.Client, endpoint string, maxSize, tailSize int64) (io.ReaderAt, int64, error) {
	if tailSize <= 0 {
		return nil, 0, errors.New("ZIP tail size must be positive")
	}
	resp, err := doHTTPRequest(ctx, client, http.MethodHead, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%s", resp.Status)
	}
	if resp.ContentLength <= 0 {
		return nil, 0, errors.New("ZIP response has no content length")
	}
	if resp.ContentLength > maxSize {
		return nil, 0, fmt.Errorf("ZIP is %d bytes (limit %d)", resp.ContentLength, maxSize)
	}
	size := resp.ContentLength
	if collector, modulePath := trafficContext(ctx); collector != nil {
		collector.setAdvertisedZIPBytes(modulePath, size)
	}
	if size <= zipSmallWholeLimit {
		tailSize = size
	}
	data, start, err := readZIPTail(ctx, client, endpoint, size, tailSize)
	if err != nil {
		return nil, 0, err
	}
	directoryStart, directoryEnd, parseErr := zipCentralDirectoryRange(data, start)
	if parseErr != nil && tailSize < zipMaxEOCDSearch {
		data, start, err = readZIPTail(ctx, client, endpoint, size, zipMaxEOCDSearch)
		if err != nil {
			return nil, 0, err
		}
		directoryStart, directoryEnd, parseErr = zipCentralDirectoryRange(data, start)
	}
	if parseErr != nil {
		return nil, 0, parseErr
	}
	if directoryStart < 0 || directoryEnd < directoryStart || directoryEnd > size {
		return nil, 0, fmt.Errorf("ZIP central directory range [%d,%d) is outside archive of %d bytes", directoryStart, directoryEnd, size)
	}
	cacheStart := directoryStart
	if eocdProbeStart := size - 1024; eocdProbeStart >= 0 && eocdProbeStart < cacheStart {
		cacheStart = eocdProbeStart
	}
	reader := &remoteZipReaderAt{
		ctx:            ctx,
		client:         client,
		endpoint:       endpoint,
		cachedTail:     data,
		cachedData:     make(map[int64][]byte),
		tailStart:      start,
		directoryStart: cacheStart,
		size:           size,
	}
	if cacheStart < start {
		reader.cachedDirectory, err = reader.readRange(cacheStart, start)
		if err != nil {
			return nil, 0, fmt.Errorf("read ZIP central directory: %w", err)
		}
	}
	return reader, size, nil
}

func readZIPTail(ctx context.Context, client *http.Client, endpoint string, size, tailSize int64) ([]byte, int64, error) {
	start := size - tailSize
	if start < 0 {
		start = 0
	}
	headers := make(http.Header)
	if start > 0 {
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", start, size-1))
	}
	resp, err := doHTTPRequest(ctx, client, http.MethodGet, endpoint, headers)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	wantStatus := http.StatusOK
	if start > 0 {
		wantStatus = http.StatusPartialContent
	}
	if resp.StatusCode != wantStatus {
		return nil, 0, fmt.Errorf("ZIP tail request returned %s", resp.Status)
	}
	wantBytes := size - start
	data, err := io.ReadAll(io.LimitReader(resp.Body, wantBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) != wantBytes {
		return nil, 0, fmt.Errorf("ZIP tail returned %d bytes, want %d", len(data), wantBytes)
	}
	return data, start, nil
}

func zipCentralDirectoryRange(tail []byte, tailStart int64) (int64, int64, error) {
	const (
		eocdSignature         = 0x06054b50
		zip64EOCDSignature    = 0x06064b50
		zip64LocatorSignature = 0x07064b50
	)
	for offset := len(tail) - zipEOCDSize; offset >= 0; offset-- {
		if binary.LittleEndian.Uint32(tail[offset:]) != eocdSignature {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(tail[offset+20:]))
		if offset+zipEOCDSize+commentLength != len(tail) {
			continue
		}
		directorySize := uint64(binary.LittleEndian.Uint32(tail[offset+12:]))
		directoryOffset := uint64(binary.LittleEndian.Uint32(tail[offset+16:]))
		if directorySize == uint64(^uint32(0)) || directoryOffset == uint64(^uint32(0)) {
			locatorOffset := offset - 20
			if locatorOffset < 0 || binary.LittleEndian.Uint32(tail[locatorOffset:]) != zip64LocatorSignature {
				return 0, 0, errors.New("ZIP64 end record is outside cached tail")
			}
			zip64Offset := int64(binary.LittleEndian.Uint64(tail[locatorOffset+8:]))
			zip64Relative := zip64Offset - tailStart
			if zip64Relative < 0 || zip64Relative+56 > int64(len(tail)) ||
				binary.LittleEndian.Uint32(tail[zip64Relative:]) != zip64EOCDSignature {
				return 0, 0, errors.New("ZIP64 end record is outside cached tail")
			}
			directorySize = binary.LittleEndian.Uint64(tail[zip64Relative+40:])
			directoryOffset = binary.LittleEndian.Uint64(tail[zip64Relative+48:])
		}
		if directoryOffset > uint64(^uint64(0)>>1) || directorySize > uint64(^uint64(0)>>1)-directoryOffset {
			return 0, 0, errors.New("ZIP central directory range overflows int64")
		}
		start := int64(directoryOffset)
		return start, start + int64(directorySize), nil
	}
	return 0, 0, errors.New("ZIP end-of-central-directory record not found")
}

func (r *remoteZipReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if offset < 0 || offset >= r.size || int64(len(p)) > r.size-offset {
		return 0, io.EOF
	}
	written := 0
	for written < len(p) {
		current := offset + int64(written)
		if current >= r.tailStart {
			written += copy(p[written:], r.cachedTail[current-r.tailStart:])
			continue
		}
		if current >= r.directoryStart && current < r.directoryStart+int64(len(r.cachedDirectory)) {
			written += copy(p[written:], r.cachedDirectory[current-r.directoryStart:])
			continue
		}
		blockStart := current - current%zipReadAhead
		r.cacheMu.Lock()
		block, ok := r.cachedData[blockStart]
		r.cacheMu.Unlock()
		if !ok {
			blockEnd := blockStart + zipReadAhead
			if blockEnd > r.tailStart {
				blockEnd = r.tailStart
			}
			var err error
			block, err = r.readRange(blockStart, blockEnd)
			if err != nil {
				return written, err
			}
			r.cacheMu.Lock()
			r.cachedData[blockStart] = block
			r.cacheMu.Unlock()
		}
		n := copy(p[written:], block[current-blockStart:])
		if n == 0 {
			return written, io.ErrUnexpectedEOF
		}
		written += n
	}
	return written, nil
}

func (r *remoteZipReaderAt) readRange(start, end int64) ([]byte, error) {
	headers := make(http.Header)
	headers.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end-1))
	resp, err := doHTTPRequest(r.ctx, r.client, http.MethodGet, r.endpoint, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("ZIP range request returned %s", resp.Status)
	}
	want := end - start
	data, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != want {
		return nil, fmt.Errorf("ZIP range returned %d bytes, want %d", len(data), want)
	}
	return data, nil
}

func doHTTPRequest(ctx context.Context, client *http.Client, method, endpoint string, headers http.Header) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= httpAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if headers != nil {
			req.Header = headers.Clone()
		}
		if req.Header.Get("Accept-Encoding") == "" {
			req.Header.Set("Accept-Encoding", "identity")
		}
		collector, modulePath := trafficContext(ctx)
		phase := trafficPhase(modulePath, method, endpoint, req.Header)
		if collector != nil {
			collector.addRequest(modulePath, phase)
		}
		resp, err := client.Do(req)
		if resp != nil && collector != nil {
			resp.Body = &trafficReadCloser{
				ReadCloser: resp.Body,
				collector:  collector,
				module:     modulePath,
				phase:      phase,
			}
		}
		if err == nil && !isTransientHTTPStatus(resp.StatusCode) {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s", resp.Status)
			if attempt == httpAttempts {
				return resp, nil
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
		}
		if attempt == httpAttempts {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * httpRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func isTransientHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func containsPathElement(name, element string) bool {
	for _, part := range strings.Split(name, "/") {
		if part == element {
			return true
		}
	}
	return false
}

func inferAssemblyArchitecture(name string) string {
	return discoverymeta.InferArchitecture(name)
}

// escapeProxyPath implements the uppercase escaping used by the Go module
// proxy protocol. Index entries are already valid module paths.
func escapeProxyPath(value string) (string, error) {
	if value == "" {
		return "", errors.New("empty module path or version")
	}
	var out strings.Builder
	for _, r := range value {
		switch {
		case r == '!':
			out.WriteString("!!")
		case r >= 'A' && r <= 'Z':
			out.WriteByte('!')
			out.WriteRune(r + ('a' - 'A'))
		default:
			out.WriteRune(r)
		}
	}
	return out.String(), nil
}
