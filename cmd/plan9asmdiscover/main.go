// Command plan9asmdiscover finds public Go modules that contain Plan 9
// assembly. It reads the official module index, resolves each distinct module
// to @latest, and inspects the cached module ZIP without executing module code.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultIndexURL    = "https://index.golang.org/index"
	defaultProxyURL    = "https://proxy.golang.org/cached-only"
	discoverySchema    = 2
	indexPageLimit     = 2000
	defaultScanLimit   = 2000
	defaultMaxZipSize  = 2 << 30
	defaultHTTPTimeout = 60 * time.Second
	zipDirectoryTail   = 8 << 20
	maxAsmProbeSize    = 8 << 20
	zipReadAhead       = 1 << 20
	httpAttempts       = 3
	httpRetryDelay     = 100 * time.Millisecond
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
	Pinned  bool   `json:"-"`
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

type discoveryReport struct {
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Since         string          `json:"since,omitempty"`
	NextSince     string          `json:"next_since,omitempty"`
	IndexEntries  int             `json:"index_entries"`
	UniqueModules int             `json:"unique_modules"`
	Skipped       int             `json:"skipped_previously_scanned,omitempty"`
	Scanned       []moduleVersion `json:"scanned"`
	Matched       []candidate     `json:"matched"`
	Failures      []scanFailure   `json:"failures,omitempty"`
	Audit         *auditSummary   `json:"audit,omitempty"`
}

type config struct {
	indexURL    string
	proxyURL    string
	since       string
	modules     []moduleVersion
	audit       bool
	auditTop    int
	limit       int
	workers     int
	maxZipSize  int64
	httpTimeout time.Duration
	seen        map[string]struct{}
}

type pathListFlag []string

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
	since := flag.String("since", "", "oldest index timestamp (RFC3339); empty starts at the beginning")
	limit := flag.Int("limit", defaultScanLimit, "maximum index records to inspect; 0 scans until the feed ends")
	workers := flag.Int("workers", 8, "concurrent module ZIP inspections")
	maxZipSize := flag.Int64("max-zip-bytes", defaultMaxZipSize, "maximum remote module ZIP size considered")
	httpTimeout := flag.Duration("http-timeout", defaultHTTPTimeout, "timeout for each index or proxy request")
	out := flag.String("out", "", "write JSON to this file instead of stdout")
	modulesFlag := flag.String("modules", "", "optional comma-separated module[@version] list or @file (skips module index)")
	audit := flag.Bool("audit", false, "parse and probe discovered .s files in-memory and emit frequency-ranked gap summary")
	auditTop := flag.Int("audit-top", 100, "maximum unsupported form gaps included in audit.top_gaps (0 = unlimited)")
	var seenReports pathListFlag
	flag.Var(&seenReports, "seen-report", "prior discovery report to skip (repeatable)")
	flag.Parse()
	seen, err := loadSeenReports(seenReports)
	if err != nil {
		fatal(err)
	}
	explicitModules, err := parseModuleSpecs(*modulesFlag)
	if err != nil {
		fatal(err)
	}

	cfg := config{
		indexURL:    *indexURL,
		proxyURL:    strings.TrimRight(*proxyURL, "/"),
		since:       *since,
		modules:     explicitModules,
		audit:       *audit,
		auditTop:    *auditTop,
		limit:       *limit,
		workers:     *workers,
		maxZipSize:  *maxZipSize,
		httpTimeout: *httpTimeout,
		seen:        seen,
	}
	if err := validateConfig(cfg); err != nil {
		fatal(err)
	}

	ctx := context.Background()
	client := &http.Client{Timeout: cfg.httpTimeout}
	report, err := discover(ctx, client, cfg)
	if err != nil {
		fatal(err)
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
	if cfg.since != "" {
		if _, err := time.Parse(time.RFC3339Nano, cfg.since); err != nil {
			return fmt.Errorf("invalid -since timestamp: %w", err)
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

func discover(ctx context.Context, client *http.Client, cfg config) (discoveryReport, error) {
	var modules []moduleVersion
	var nextSince string
	var indexCount int
	if len(cfg.modules) > 0 {
		modules = append([]moduleVersion(nil), cfg.modules...)
	} else {
		entries, cursor, err := readIndex(ctx, client, cfg.indexURL, cfg.since, cfg.limit)
		if err != nil {
			return discoveryReport{}, err
		}
		indexCount = len(entries)
		nextSince = cursor
		moduleSet := make(map[string]string, len(entries))
		for _, entry := range entries {
			moduleSet[entry.Path] = entry.Version
		}
		modules = make([]moduleVersion, 0, len(moduleSet))
		for modulePath, version := range moduleSet {
			modules = append(modules, moduleVersion{Path: modulePath, Version: version})
		}
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	uniqueModules := len(modules)
	modules, skipped := filterPreviouslyScanned(modules, cfg.seen)

	var auditor *auditCollector
	if cfg.audit {
		auditor = newAuditCollector()
	}
	matched, failures, scanned := inspectModulesWithAudit(ctx, client, cfg.proxyURL, modules, cfg.workers, cfg.maxZipSize, auditor)
	rep := discoveryReport{
		SchemaVersion: discoverySchema,
		GeneratedAt:   time.Now().UTC(),
		Since:         cfg.since,
		NextSince:     nextSince,
		IndexEntries:  indexCount,
		UniqueModules: uniqueModules,
		Skipped:       skipped,
		Scanned:       scanned,
		Matched:       matched,
		Failures:      failures,
	}
	if auditor != nil {
		rep.Audit = auditor.summarize(cfg.auditTop)
	}
	return rep, nil
}

func loadSeenReports(paths []string) (map[string]struct{}, error) {
	seen := make(map[string]struct{})
	for _, reportPath := range paths {
		data, err := os.ReadFile(reportPath)
		if err != nil {
			return nil, fmt.Errorf("read seen report %q: %w", reportPath, err)
		}
		var report discoveryReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("decode seen report %q: %w", reportPath, err)
		}
		for _, item := range report.Scanned {
			if item.Path == "" || item.Version == "" {
				return nil, fmt.Errorf("seen report %q contains an incomplete scanned version", reportPath)
			}
			seen[scanKey(item)] = struct{}{}
		}
		// Older reports did not contain the complete scanned set, but their
		// successful matches are still safe to reuse.
		for _, item := range report.Matched {
			if item.Module != "" && item.Version != "" {
				seen[scanKey(moduleVersion{Path: item.Module, Version: item.Version})] = struct{}{}
			}
		}
	}
	return seen, nil
}

func filterPreviouslyScanned(modules []moduleVersion, seen map[string]struct{}) ([]moduleVersion, int) {
	if len(seen) == 0 {
		return modules, 0
	}
	pending := make([]moduleVersion, 0, len(modules))
	skipped := 0
	for _, module := range modules {
		if _, ok := seen[scanKey(module)]; ok {
			skipped++
			continue
		}
		pending = append(pending, module)
	}
	return pending, skipped
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

func inspectModules(ctx context.Context, client *http.Client, proxyURL string, modules []moduleVersion, workers int, maxZipSize int64) ([]candidate, []scanFailure, []moduleVersion) {
	return inspectModulesWithAudit(ctx, client, proxyURL, modules, workers, maxZipSize, nil)
}

func inspectModulesWithAudit(ctx context.Context, client *http.Client, proxyURL string, modules []moduleVersion, workers int, maxZipSize int64, auditor *auditCollector) ([]candidate, []scanFailure, []moduleVersion) {
	tasks := make(chan moduleVersion)
	results := make(chan candidate)
	errorsOut := make(chan scanFailure)
	completed := make(chan moduleVersion)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for module := range tasks {
				item, scanned, err := inspectIndexedModuleWithAudit(ctx, client, proxyURL, module, maxZipSize, auditor)
				for _, version := range scanned {
					completed <- version
				}
				if err != nil {
					errorsOut <- scanFailure{Module: module.Path, Version: module.Version, Error: err.Error()}
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
	}()

	matched := make([]candidate, 0)
	failures := make([]scanFailure, 0)
	scannedSet := make(map[string]moduleVersion)
	for results != nil || errorsOut != nil || completed != nil {
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
	return matched, failures, scanned
}

func inspectIndexedModule(ctx context.Context, client *http.Client, proxyURL string, module moduleVersion, maxZipSize int64) (candidate, []moduleVersion, error) {
	return inspectIndexedModuleWithAudit(ctx, client, proxyURL, module, maxZipSize, nil)
}

func inspectIndexedModuleWithAudit(ctx context.Context, client *http.Client, proxyURL string, module moduleVersion, maxZipSize int64, auditor *auditCollector) (candidate, []moduleVersion, error) {
	if module.Version == "" {
		latestVersion, err := resolveLatest(ctx, client, proxyURL, module.Path)
		if err != nil {
			return candidate{}, nil, err
		}
		latest, err := inspectModuleVersionWithAudit(ctx, client, proxyURL, module.Path, latestVersion, maxZipSize, auditor)
		if err != nil {
			return candidate{}, nil, err
		}
		return latest, []moduleVersion{{Path: module.Path, Version: latestVersion}}, nil
	}
	if module.Pinned {
		pinned, err := inspectModuleVersionWithAudit(ctx, client, proxyURL, module.Path, module.Version, maxZipSize, auditor)
		if err != nil {
			return candidate{}, nil, fmt.Errorf("inspect pinned version %s: %w", module.Version, err)
		}
		return pinned, []moduleVersion{{Path: module.Path, Version: module.Version}}, nil
	}
	// First inspect the indexed version and retain its .s payloads when auditing
	// so if it is already @latest we audit in-memory without a second ZIP download.
	indexed, indexedSources, err := inspectModuleVersionCaptured(ctx, client, proxyURL, module.Path, module.Version, maxZipSize, auditor != nil)
	if err != nil {
		return candidate{}, nil, fmt.Errorf("inspect indexed version %s: %w", module.Version, err)
	}
	scanned := []moduleVersion{{Path: module.Path, Version: module.Version}}
	if len(indexed.AsmFiles) == 0 {
		return indexed, scanned, nil
	}
	latestVersion, err := resolveLatest(ctx, client, proxyURL, module.Path)
	if err != nil {
		return candidate{}, scanned, err
	}
	if latestVersion == module.Version {
		if auditor != nil {
			for _, src := range indexedSources {
				if len(src.data) > 0 {
					auditor.auditFile(module.Path, src.name, src.data)
				}
			}
		}
		return indexed, scanned, nil
	}
	latest, err := inspectModuleVersionWithAudit(ctx, client, proxyURL, module.Path, latestVersion, maxZipSize, auditor)
	if err != nil {
		return candidate{}, scanned, err
	}
	scanned = append(scanned, moduleVersion{Path: module.Path, Version: latestVersion})
	return latest, scanned, nil
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
	if err := json.Unmarshal(latestBody, &latest); err != nil || latest.Version == "" {
		return "", fmt.Errorf("decode @latest: %w", err)
	}
	return latest.Version, nil
}

func inspectModuleVersion(ctx context.Context, client *http.Client, proxyURL, modulePath, version string, maxZipSize int64) (candidate, error) {
	return inspectModuleVersionWithAudit(ctx, client, proxyURL, modulePath, version, maxZipSize, nil)
}

type capturedAsmSource struct {
	name string
	data []byte
}

func inspectModuleVersionCaptured(ctx context.Context, client *http.Client, proxyURL, modulePath, version string, maxZipSize int64, keepData bool) (candidate, []capturedAsmSource, error) {
	escapedModule, err := escapeProxyPath(modulePath)
	if err != nil {
		return candidate{}, nil, err
	}
	escapedVersion, err := escapeProxyPath(version)
	if err != nil {
		return candidate{}, nil, err
	}
	zipURL := proxyURL + "/" + escapedModule + "/@v/" + escapedVersion + ".zip"
	reader, zipSize, err := newHTTPReaderAt(ctx, client, zipURL, maxZipSize)
	if err != nil {
		return candidate{}, nil, fmt.Errorf("open %s ZIP: %w", version, err)
	}
	var captured []capturedAsmSource
	var collect func(name string, data []byte)
	if keepData {
		collect = func(name string, data []byte) {
			captured = append(captured, capturedAsmSource{name: name, data: data})
		}
	}
	files, arches, err := inspectModuleZipReaderWithCallback(reader, zipSize, collect)
	if err != nil {
		return candidate{}, nil, fmt.Errorf("inspect %s: %w", version, err)
	}
	return candidate{Module: modulePath, Version: version, Architectures: arches, AsmFiles: files}, captured, nil
}

func inspectModuleVersionWithAudit(ctx context.Context, client *http.Client, proxyURL, modulePath, version string, maxZipSize int64, auditor *auditCollector) (candidate, error) {
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
	files, arches, err := inspectModuleZipReaderWithAudit(reader, zipSize, modulePath, auditor)
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
	return inspectModuleZipReaderWithAudit(reader, size, "", nil)
}

func inspectModuleZipReaderWithAudit(reader io.ReaderAt, size int64, modulePath string, auditor *auditCollector) ([]string, []string, error) {
	var cb func(name string, data []byte)
	if auditor != nil {
		cb = func(name string, data []byte) {
			auditor.auditFile(modulePath, name, data)
		}
	}
	return inspectModuleZipReaderWithCallback(reader, size, cb)
}

func inspectModuleZipReaderWithCallback(reader io.ReaderAt, size int64, onAsm func(name string, data []byte)) ([]string, []string, error) {
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
	for _, asmFile := range asmFiles {
		if _, ok := goDirs[path.Dir(asmFile.name)]; !ok {
			continue
		}
		data, hasContent, err := readZipAssemblyBytes(asmFile.file)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", asmFile.name, err)
		}
		if !hasContent {
			continue
		}
		files = append(files, asmFile.name)
		archSet[inferAssemblyArchitecture(asmFile.name)] = struct{}{}
		if onAsm != nil && len(data) > 0 {
			onAsm(asmFile.name, data)
		}
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
	ctx        context.Context
	client     *http.Client
	endpoint   string
	cachedTail []byte
	cacheMu    sync.Mutex
	cachedData map[int64][]byte
	tailStart  int64
	size       int64
}

func newHTTPReaderAt(ctx context.Context, client *http.Client, endpoint string, maxSize int64) (io.ReaderAt, int64, error) {
	return newHTTPReaderAtWithTail(ctx, client, endpoint, maxSize, zipDirectoryTail)
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
	start := size - tailSize
	if start < 0 {
		start = 0
	}
	headers := make(http.Header)
	if start > 0 {
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", start, size-1))
	}
	resp, err = doHTTPRequest(ctx, client, http.MethodGet, endpoint, headers)
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
	return &remoteZipReaderAt{
		ctx:        ctx,
		client:     client,
		endpoint:   endpoint,
		cachedTail: data,
		cachedData: make(map[int64][]byte),
		tailStart:  start,
		size:       size,
	}, size, nil
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
		req.Header = headers.Clone()
		resp, err := client.Do(req)
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
	base := strings.TrimSuffix(path.Base(name), ".s")
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		if strings.HasSuffix(base, "_"+arch) {
			return arch
		}
	}
	return "unknown"
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
