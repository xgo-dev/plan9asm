package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/discoverymeta"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const discoveryReportSchema = 6

const (
	discoveryStatusPassed                  = "passed"
	discoveryStatusFailed                  = "failed"
	discoveryStatusNotApplicable           = "not_applicable"
	discoveryStatusSkippedInvalidSource    = "skipped_invalid_source"
	discoveryStatusSkippedSuperseded       = "skipped_superseded"
	discoveryStatusSkippedPrivateExtension = "skipped_private_extension"
)

type discoveryRecord struct {
	Kind          string   `json:"kind"`
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures,omitempty"`
	AsmFiles      []string `json:"asm_files,omitempty"`
}

type discoveryCandidate struct {
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures"`
	AsmFiles      []string `json:"asm_files"`
}

func (c discoveryCandidate) exactKey() string {
	return c.Module + "@" + c.Version
}

type discoveryCorpusConfig struct {
	LedgerPath       string
	RepoRoot         string
	Translator       string
	LLC              string
	Targets          []string
	FilterTargets    bool
	ShardIndex       int
	ShardCount       int
	CandidateTimeout time.Duration
	ReportPath       string
	// Defaults to a shard-owned cache. A caller may provide an existing shared
	// directory, which runDiscoveryCorpus must never remove.
	buildCache            string
	privateExtensionSkips map[string]discoveryPrivateExtensionSkip
	// Allows deterministic, offline orchestration tests; the CLI always uses
	// collectDiscoveryProvenance and cannot supply a claimed identity.
	captureProvenance func(discoveryCorpusConfig) (discoveryCorpusProvenance, error)
	runCandidate      func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error)
}

type discoveryExecutionPlan struct {
	ModulePath string
	Patterns   []string
	GoMod      string
}

type discoveryBuildConfiguration struct {
	BuildTags []string `json:"build_tags,omitempty"`
	Targets   []string `json:"targets"`
	AsmFiles  []string `json:"asm_files"`
}

type discoveryPackageGroup struct {
	Pattern  string
	AsmFiles []string
}

type discoveryTranslationUnit struct {
	Patterns []string
	AsmFiles []string
}

// A translator process owns LLVM objects for its whole lifetime. One package
// per process bounds the peak for modules with many independent assembly
// packages, while candidate-level accounting still covers every file.
func discoveryTranslationUnits(groups []discoveryPackageGroup) []discoveryTranslationUnit {
	units := make([]discoveryTranslationUnit, 0, len(groups))
	for _, group := range groups {
		if len(group.AsmFiles) == 0 {
			continue
		}
		units = append(units, discoveryTranslationUnit{
			Patterns: []string{group.Pattern},
			AsmFiles: append([]string(nil), group.AsmFiles...),
		})
	}
	return units
}

func validateDiscoveryTranslationUnits(units []discoveryTranslationUnit, expectedFiles []string) error {
	seen := make(map[string]bool, len(expectedFiles))
	for _, unit := range units {
		if len(unit.Patterns) != 1 || unit.Patterns[0] == "" || len(unit.AsmFiles) == 0 {
			return fmt.Errorf("discovery translation unit must contain one package and its assembly")
		}
		for _, file := range unit.AsmFiles {
			if seen[file] {
				return fmt.Errorf("duplicate discovery translation file %s", file)
			}
			seen[file] = true
		}
	}
	if !equalDiscoveryStrings(uniqueSortedDiscoveryStrings(expectedFiles), sortedDiscoverySet(seen)) {
		return fmt.Errorf("discovery translation units do not cover every applicable assembly file")
	}
	return nil
}

const (
	discoverySourceNotApplicableGoAssembler = "go_assembler_rejected_all_supported_targets"
	discoverySourceNotApplicableNoGoPackage = "no_current_go_package"
	discoverySourceNotApplicableGoBuild     = "go_build_rejected_package_target"
	discoverySourceNotApplicableAsmDecl     = "go_vet_asmdecl_rejected_target"
	discoverySourceNotApplicableNoSymbols   = "go_assembler_emits_no_symbols"
)

type discoverySourceNotApplicableItem struct {
	AsmFile  string   `json:"asm_file,omitempty"`
	AsmFiles []string `json:"asm_files,omitempty"`
	Targets  []string `json:"targets"`
	Kind     string   `json:"kind"`
	Reason   string   `json:"reason"`
}

type moduleDownloadInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
	GoMod   string `json:"GoMod"`
	Zip     string `json:"Zip"`
	Error   string `json:"Error"`
}

type discoveryCorpusResult struct {
	Module                    string                                `json:"module"`
	Version                   string                                `json:"version"`
	Status                    string                                `json:"status"`
	DiscoveredAsmFiles        []string                              `json:"discovered_asm_files"`
	ApplicableAsmFiles        []string                              `json:"applicable_asm_files"`
	BuildConfigurations       []discoveryBuildConfiguration         `json:"build_configurations,omitempty"`
	Patterns                  []string                              `json:"patterns,omitempty"`
	Translations              int                                   `json:"translations"`
	NotApplicableTranslations int                                   `json:"not_applicable_translations,omitempty"`
	NotApplicableItems        []matrixTargetNotApplicableItem       `json:"not_applicable_items,omitempty"`
	SourceNotApplicableItems  []discoverySourceNotApplicableItem    `json:"source_not_applicable_items,omitempty"`
	NotApplicableReason       string                                `json:"not_applicable_reason,omitempty"`
	InvalidSourceReason       string                                `json:"invalid_source_reason,omitempty"`
	InvalidSourceEvidence     []discoveryInvalidMachineCodeEvidence `json:"invalid_source_evidence,omitempty"`
	Superseded                *discoverySupersededSkip              `json:"superseded,omitempty"`
	PrivateExtension          *discoveryPrivateExtensionSkip        `json:"private_extension,omitempty"`
	Error                     string                                `json:"error,omitempty"`
}

type discoveryCorpusReport struct {
	SchemaVersion             int                       `json:"schema_version"`
	Partial                   bool                      `json:"partial,omitempty"`
	Provenance                discoveryCorpusProvenance `json:"provenance"`
	Targets                   []string                  `json:"targets,omitempty"`
	TargetFiltered            bool                      `json:"target_filtered,omitempty"`
	ShardIndex                int                       `json:"shard_index"`
	ShardCount                int                       `json:"shard_count"`
	CandidateTotal            int                       `json:"candidate_total"`
	EligibleCandidates        int                       `json:"eligible_candidates"`
	Selected                  int                       `json:"selected"`
	Passed                    int                       `json:"passed"`
	Failed                    int                       `json:"failed"`
	NotApplicable             int                       `json:"not_applicable"`
	SkippedInvalidSource      int                       `json:"skipped_invalid_source"`
	SkippedSuperseded         int                       `json:"skipped_superseded"`
	SkippedPrivateExtension   int                       `json:"skipped_private_extension"`
	Translations              int                       `json:"translations"`
	NotApplicableTranslations int                       `json:"not_applicable_translations"`
	Results                   []discoveryCorpusResult   `json:"results"`
}

func loadDiscoveryCandidates(root string) ([]discoveryCandidate, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat discovery ledger: %w", err)
	}
	var files []string
	if !info.IsDir() {
		files = []string{root}
	} else {
		files, err = filepath.Glob(filepath.Join(root, "records", "*.jsonl"))
		if err != nil {
			return nil, fmt.Errorf("list discovery ledger records: %w", err)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("discovery ledger %q contains no JSONL records", root)
	}
	sort.Strings(files)
	type candidateSets struct {
		candidate discoveryCandidate
		arches    map[string]bool
		asmFiles  map[string]bool
	}
	merged := make(map[string]*candidateSets)
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("open discovery records %s: %w", filePath, err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 32<<20)
		line := 0
		for scanner.Scan() {
			line++
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var record discoveryRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				file.Close()
				return nil, fmt.Errorf("decode discovery record %s:%d: %w", filePath, line, err)
			}
			if record.Kind != "matched" {
				continue
			}
			if err := validateDiscoveryRecord(record); err != nil {
				file.Close()
				return nil, fmt.Errorf("invalid discovery record %s:%d: %w", filePath, line, err)
			}
			key := record.Module + "@" + record.Version
			item := merged[key]
			if item == nil {
				item = &candidateSets{
					candidate: discoveryCandidate{Module: record.Module, Version: record.Version},
					arches:    make(map[string]bool),
					asmFiles:  make(map[string]bool),
				}
				merged[key] = item
			}
			for _, arch := range record.Architectures {
				item.arches[arch] = true
			}
			for _, asmFile := range record.AsmFiles {
				item.asmFiles[asmFile] = true
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("read discovery records %s: %w", filePath, err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close discovery records %s: %w", filePath, err)
		}
	}
	candidates := make([]discoveryCandidate, 0, len(merged))
	for _, item := range merged {
		for arch := range item.arches {
			item.candidate.Architectures = append(item.candidate.Architectures, arch)
		}
		for asmFile := range item.asmFiles {
			item.candidate.AsmFiles = append(item.candidate.AsmFiles, asmFile)
		}
		sort.Strings(item.candidate.Architectures)
		sort.Strings(item.candidate.AsmFiles)
		candidates = append(candidates, item.candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Module != candidates[j].Module {
			return candidates[i].Module < candidates[j].Module
		}
		return candidates[i].Version < candidates[j].Version
	})
	return candidates, nil
}

func validateDiscoveryRecord(record discoveryRecord) error {
	if record.Module == "" || strings.TrimSpace(record.Module) != record.Module || strings.ContainsAny(record.Module, "\r\n\t ") {
		return fmt.Errorf("invalid module %q", record.Module)
	}
	if record.Version == "" || strings.TrimSpace(record.Version) != record.Version || strings.ContainsAny(record.Version, "\r\n\t ") {
		return fmt.Errorf("invalid version %q", record.Version)
	}
	if len(record.AsmFiles) == 0 {
		return fmt.Errorf("%s@%s has no assembly files", record.Module, record.Version)
	}
	for _, asmFile := range record.AsmFiles {
		if asmFile == "" || strings.Contains(asmFile, "\\") || path.IsAbs(asmFile) || path.Clean(asmFile) != asmFile || strings.HasPrefix(asmFile, "../") || !strings.HasSuffix(asmFile, ".s") {
			return fmt.Errorf("%s@%s has unsafe assembly path %q", record.Module, record.Version, asmFile)
		}
	}
	return nil
}

func selectDiscoveryShard(candidates []discoveryCandidate, shardIndex, shardCount int) []discoveryCandidate {
	if shardCount <= 0 || shardIndex < 0 || shardIndex >= shardCount {
		return nil
	}
	selected := make([]discoveryCandidate, 0, len(candidates)/shardCount+1)
	for _, candidate := range candidates {
		if discoveryCandidateShard(candidate, shardCount) == shardIndex {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func discoveryCandidateShard(candidate discoveryCandidate, shardCount int) int {
	if shardCount <= 0 {
		return -1
	}
	sum := sha256.Sum256([]byte(candidate.exactKey()))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(shardCount))
}

func verifyDiscoveryCorpusReports(ledgerPath, reportsPath string, expectedTargets []string, source discoverySourceIdentity, repoRoot ...string) error {
	progress, err := collectDiscoveryProgress(ledgerPath, reportsPath, expectedTargets, source, 0, repoRoot...)
	if err != nil {
		return err
	}
	if progress.ReportedShards == 0 {
		return fmt.Errorf("no discovery shard reports found in %q", reportsPath)
	}
	if !progress.Complete {
		return fmt.Errorf("found %d discovery shard reports, want exactly %d complete; %d ledger matches pending", progress.ReportedShards, progress.ShardCount, progress.Pending)
	}
	if progress.Failed != 0 {
		return fmt.Errorf("discovery shards have %d failed candidates", progress.Failed)
	}
	return nil
}

// The passing gate and the progress view deliberately share every integrity
// check. Missing whole shards and genuine failures are useful progress, but
// incomplete, stale or mixed-input reports are never evidence of a pass.
func auditDiscoveryCorpusReports(
	ledgerPath, reportsPath string,
	expectedTargets []string,
	source discoverySourceIdentity,
	skips map[string]discoveryInvalidMachineCodeSkip,
	superseded map[string]discoverySupersededSkip,
	privateExtensions map[string]discoveryPrivateExtensionSkip,
	progress *discoveryProgress,
) error {
	ledgerSHA, err := discoveryLedgerFingerprint(ledgerPath)
	if err != nil {
		return err
	}
	candidates, err := loadDiscoveryCandidates(ledgerPath)
	if err != nil {
		return err
	}
	expected := make(map[string]discoveryCandidate, len(candidates))
	for _, candidate := range candidates {
		expected[candidate.exactKey()] = candidate
		progress.DiscoveredAsmFiles += len(candidate.AsmFiles)
	}
	progress.CandidateTotal = len(candidates)
	progress.LedgerSHA256 = ledgerSHA
	files, err := discoveryCorpusReportFiles(reportsPath)
	if err != nil && !(progress.ShardCount > 0 && errors.Is(err, os.ErrNotExist)) {
		return err
	}
	seenShards := make(map[int]string)
	partialShards := make(map[int]bool)
	seenCandidates := make(map[string]string, len(candidates))
	outcomes := make(map[string]discoveryCandidateProgress, len(candidates))
	shardCount := progress.ShardCount
	var provenance discoveryCorpusProvenance
	for _, filePath := range files {
		report, err := readDiscoveryCorpusReport(filePath)
		if err != nil {
			return err
		}
		if report.SchemaVersion != discoveryReportSchema {
			return fmt.Errorf("%s: unsupported discovery report schema %d", filePath, report.SchemaVersion)
		}
		if err := validateDiscoveryProvenance(report.Provenance, source, ledgerSHA); err != nil {
			return fmt.Errorf("%s: %w", filePath, err)
		}
		if len(seenShards) != 0 && report.Provenance != provenance {
			return fmt.Errorf("%s: mixed discovery source/toolchain provenance", filePath)
		}
		provenance = report.Provenance
		if err := validateDiscoveryCorpusAccounting(report); err != nil {
			return fmt.Errorf("%s: %w", filePath, err)
		}
		if len(report.Results) == 0 && (report.Translations != 0 || report.NotApplicableTranslations != 0) {
			return fmt.Errorf("%s: empty shard has nonzero translation counts", filePath)
		}
		if report.TargetFiltered {
			return fmt.Errorf("%s: target-filtered report cannot prove complete ledger coverage", filePath)
		}
		if !equalDiscoveryStrings(report.Targets, expectedTargets) {
			return fmt.Errorf("%s: targets %v do not match required matrix %v", filePath, report.Targets, expectedTargets)
		}
		if report.CandidateTotal != len(candidates) || report.EligibleCandidates != len(candidates) {
			return fmt.Errorf("%s: candidate totals are total=%d eligible=%d, want %d ledger matches", filePath, report.CandidateTotal, report.EligibleCandidates, len(candidates))
		}
		if report.ShardCount <= 0 || report.ShardIndex < 0 || report.ShardIndex >= report.ShardCount {
			return fmt.Errorf("%s: invalid shard %d/%d", filePath, report.ShardIndex, report.ShardCount)
		}
		if shardCount == 0 {
			shardCount = report.ShardCount
		} else if report.ShardCount != shardCount {
			return fmt.Errorf("%s: shard_count %d does not match %d", filePath, report.ShardCount, shardCount)
		}
		if previous, ok := seenShards[report.ShardIndex]; ok {
			return fmt.Errorf("duplicate discovery shard %d in %s and %s", report.ShardIndex, previous, filePath)
		}
		seenShards[report.ShardIndex] = filePath
		if len(report.Results) != report.Selected {
			return fmt.Errorf("%s: selected=%d but contains %d auditable results", filePath, report.Selected, len(report.Results))
		}
		if want := len(selectDiscoveryShard(candidates, report.ShardIndex, report.ShardCount)); report.Selected != want {
			if !report.Partial || report.Selected > want {
				return fmt.Errorf("%s: shard inventory has %d results, want %d ledger matches", filePath, report.Selected, want)
			}
		} else if report.Partial {
			return fmt.Errorf("%s: partial shard has a complete inventory", filePath)
		}
		for _, result := range report.Results {
			key := result.Module + "@" + result.Version
			switch result.Status {
			case discoveryStatusPassed:
				if result.Translations <= 0 || result.Error != "" {
					return fmt.Errorf("%s: passed result %s requires positive translations and no error", filePath, key)
				}
			case discoveryStatusFailed:
				if strings.TrimSpace(result.Error) == "" {
					return fmt.Errorf("%s: failed result %s has no diagnostic", filePath, key)
				}
			case discoveryStatusNotApplicable:
				if result.Translations != 0 || strings.TrimSpace(result.NotApplicableReason) == "" || result.Error != "" {
					return fmt.Errorf("%s: not-applicable result %s requires a reason, zero successful translations and no error", filePath, key)
				}
			case discoveryStatusSkippedInvalidSource:
				if result.Translations != 0 || result.NotApplicableTranslations != 0 || result.Error != "" ||
					result.InvalidSourceReason == "" || len(result.InvalidSourceEvidence) == 0 {
					return fmt.Errorf("%s: invalid-source skip %s lacks evidence or claims translations", filePath, key)
				}
			case discoveryStatusSkippedSuperseded:
				if result.Translations != 0 || result.NotApplicableTranslations != 0 || result.Error != "" ||
					result.Superseded == nil {
					return fmt.Errorf("%s: superseded skip %s lacks evidence or claims translations", filePath, key)
				}
			case discoveryStatusSkippedPrivateExtension:
				if err := validatePrivateExtensionResult(result); err != nil {
					return fmt.Errorf("%s: private-extension skip %s: %w", filePath, key, err)
				}
			}
			candidate, ok := expected[key]
			if !ok {
				return fmt.Errorf("%s: result %s is not a current ledger match", filePath, key)
			}
			if want := discoveryCandidateShard(candidate, report.ShardCount); want != report.ShardIndex {
				return fmt.Errorf("%s: result %s belongs to shard %d/%d, not %d", filePath, key, want, report.ShardCount, report.ShardIndex)
			}
			if previous, ok := seenCandidates[key]; ok {
				return fmt.Errorf("duplicate discovery result %s in %s and %s", key, previous, filePath)
			}
			if !equalDiscoveryStrings(result.DiscoveredAsmFiles, candidate.AsmFiles) {
				return fmt.Errorf("%s: result %s assembly inventory %v does not match ledger %v", filePath, key, result.DiscoveredAsmFiles, candidate.AsmFiles)
			}
			if result.Status == discoveryStatusSkippedInvalidSource {
				if !invalidSourceSkipMatchesResult(skips[key], result) {
					return fmt.Errorf("%s: result %s invalid-source skip differs from the pinned manifest", filePath, key)
				}
			}
			if result.Status == discoveryStatusSkippedSuperseded {
				if !supersededSkipMatchesResult(superseded[key], result) {
					return fmt.Errorf("%s: result %s supersession differs from the pinned manifest", filePath, key)
				}
			}
			if result.Status == discoveryStatusSkippedPrivateExtension {
				if !privateExtensionSkipMatchesResult(privateExtensions[key], result) {
					return fmt.Errorf("%s: result %s private-extension skip differs from the pinned manifest", filePath, key)
				}
			}
			seenCandidates[key] = filePath
			outcomes[key] = discoveryCandidateProgress{
				Module: result.Module, Version: result.Version, Status: result.Status,
				InvalidSourceReason:   result.InvalidSourceReason,
				InvalidSourceEvidence: append([]discoveryInvalidMachineCodeEvidence(nil), result.InvalidSourceEvidence...),
				Superseded:            result.Superseded,
				PrivateExtension:      result.PrivateExtension,
			}
		}
		progress.ReportedShards++
		if report.Partial {
			partialShards[report.ShardIndex] = true
			progress.PartialShards = append(progress.PartialShards, report.ShardIndex)
		} else if report.Failed == 0 {
			progress.PassedShards++
		} else {
			progress.FailedShards++
		}
		progress.Passed += report.Passed
		progress.Failed += report.Failed
		progress.NotApplicable += report.NotApplicable
		progress.SkippedInvalidSource += report.SkippedInvalidSource
		progress.SkippedSuperseded += report.SkippedSuperseded
		progress.SkippedPrivateExtension += report.SkippedPrivateExtension
		progress.Translations += report.Translations
		progress.NotApplicableTranslations += report.NotApplicableTranslations
	}
	progress.ShardCount = shardCount
	for shard := 0; shard < shardCount; shard++ {
		if _, ok := seenShards[shard]; !ok || partialShards[shard] {
			progress.PendingShards = append(progress.PendingShards, shard)
		}
	}
	sort.Ints(progress.PartialShards)
	for _, candidate := range candidates {
		outcome, ok := outcomes[candidate.exactKey()]
		if !ok {
			outcome = discoveryCandidateProgress{
				Module: candidate.Module, Version: candidate.Version, Status: "pending",
			}
			progress.Pending++
		}
		progress.Candidates = append(progress.Candidates, outcome)
	}
	if len(seenShards) > 0 {
		progress.Provenance = &provenance
	}
	progress.Complete = shardCount > 0 && len(progress.PendingShards) == 0 && progress.Pending == 0
	progress.Verified = progress.Complete && progress.Failed == 0
	finalLedgerSHA, err := discoveryLedgerFingerprint(ledgerPath)
	if err != nil {
		return err
	}
	if finalLedgerSHA != ledgerSHA {
		return fmt.Errorf("discovery ledger changed while reading reports")
	}
	return nil
}

func discoveryCorpusReportFiles(reportPath string) ([]string, error) {
	info, err := os.Stat(reportPath)
	if err != nil {
		return nil, fmt.Errorf("stat discovery reports: %w", err)
	}
	if !info.IsDir() {
		return []string{reportPath}, nil
	}
	var files []string
	err = filepath.WalkDir(reportPath, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "shard-") && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list discovery reports: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func readDiscoveryCorpusReport(reportPath string) (discoveryCorpusReport, error) {
	discoveryReportMu.RLock()
	defer discoveryReportMu.RUnlock()
	file, err := openDiscoveryReport(reportPath)
	if err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("open discovery report %s: %w", reportPath, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var report discoveryCorpusReport
	if err := decoder.Decode(&report); err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("decode discovery report %s: %w", reportPath, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("decode discovery report %s: %w", reportPath, err)
	}
	return report, nil
}

func equalDiscoveryStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func filterDiscoveryCandidatesForTargets(candidates []discoveryCandidate, targets []string) ([]discoveryCandidate, error) {
	filtered := make([]discoveryCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		files, err := discoverymeta.FilterAssemblyFiles(candidate.AsmFiles, targets)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			continue
		}
		candidate.AsmFiles = files
		candidate.Architectures = discoverymeta.ArchitectureHints(files)
		filtered = append(filtered, candidate)
	}
	return filtered, nil
}

func discoveryPackagePatterns(candidate discoveryCandidate) []string {
	return discoveryPackagePatternsForModule(candidate, candidate.Module)
}

func discoveryPackagePatternsForModule(candidate discoveryCandidate, modulePath string) []string {
	groups := discoveryPackageGroupsForModule(candidate, modulePath)
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, group.Pattern)
	}
	return out
}

func discoveryPackageGroupsForModule(candidate discoveryCandidate, modulePath string) []discoveryPackageGroup {
	filesByPattern := make(map[string][]string)
	for _, asmFile := range candidate.AsmFiles {
		dir := path.Dir(asmFile)
		pattern := modulePath
		if dir != "." {
			pattern += "/" + dir
		}
		filesByPattern[pattern] = append(filesByPattern[pattern], asmFile)
	}
	patterns := make([]string, 0, len(filesByPattern))
	for pattern := range filesByPattern {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	groups := make([]discoveryPackageGroup, 0, len(patterns))
	for _, pattern := range patterns {
		groups = append(groups, discoveryPackageGroup{
			Pattern:  pattern,
			AsmFiles: uniqueSortedDiscoveryStrings(filesByPattern[pattern]),
		})
	}
	return groups
}

func makeDiscoveryExecutionPlan(candidate discoveryCandidate, declaredModule string) (discoveryExecutionPlan, error) {
	if declaredModule == "" {
		declaredModule = candidate.Module
	}
	if strings.TrimSpace(declaredModule) != declaredModule || strings.ContainsAny(declaredModule, "\r\n\t ") {
		return discoveryExecutionPlan{}, fmt.Errorf("invalid declared module path %q", declaredModule)
	}
	goMod := fmt.Sprintf("module plan9asm.local/discovery\n\ngo 1.27\n\nrequire %s %s\n", declaredModule, candidate.Version)
	if declaredModule != candidate.Module {
		goMod += fmt.Sprintf("\nreplace %s => %s %s\n", declaredModule, candidate.Module, candidate.Version)
	}
	return discoveryExecutionPlan{
		ModulePath: declaredModule,
		Patterns:   discoveryPackagePatternsForModule(candidate, declaredModule),
		GoMod:      goMod,
	}, nil
}

func parseDeclaredModulePath(contents []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "module") || (len(line) > len("module") && line[len("module")] != ' ' && line[len("module")] != '\t') {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if rest == "" {
			return "", fmt.Errorf("empty module directive")
		}
		var modulePath string
		if rest[0] == '"' || rest[0] == '`' {
			if _, err := fmt.Sscanf(rest, "%q", &modulePath); err != nil {
				return "", fmt.Errorf("parse module directive %q: %w", line, err)
			}
		} else {
			modulePath = strings.Fields(rest)[0]
		}
		if modulePath == "" || strings.ContainsAny(modulePath, "\r\n\t ") {
			return "", fmt.Errorf("invalid module directive path %q", modulePath)
		}
		return modulePath, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("go.mod has no module directive")
}

func applicableDiscoveryAssemblyFiles(candidate discoveryCandidate, moduleDir string, targets []string) ([]string, error) {
	configs, err := discoveryBuildConfigurations(candidate, moduleDir, targets)
	if err != nil {
		return nil, err
	}
	var applicable []string
	for _, config := range configs {
		applicable = append(applicable, config.AsmFiles...)
	}
	sort.Strings(applicable)
	return applicable, nil
}

func discoveryBuildConfigurations(candidate discoveryCandidate, moduleDir string, targets []string) ([]discoveryBuildConfiguration, error) {
	return discoveryBuildConfigurationsWithEvidence(candidate, moduleDir, targets, nil)
}

func discoveryBuildConfigurationsWithEvidence(candidate discoveryCandidate, moduleDir string, targets []string, sourceNotApplicable *[]discoverySourceNotApplicableItem) ([]discoveryBuildConfiguration, error) {
	if moduleDir == "" {
		return nil, fmt.Errorf("%s: downloaded module has no directory", candidate.exactKey())
	}
	contexts := make([]build.Context, 0, len(targets))
	for _, target := range targets {
		goos, goarch, ok := strings.Cut(target, "/")
		if !ok || goos == "" || goarch == "" {
			return nil, fmt.Errorf("invalid discovery target %q", target)
		}
		ctx := build.Default
		ctx.GOOS = goos
		ctx.GOARCH = goarch
		ctx.Compiler = "gc"
		ctx.CgoEnabled = false
		contexts = append(contexts, ctx)
	}

	goFilesByDir := make(map[string][]string)
	invalidGoFilesByDir := make(map[string][]string)
	constraintTagsByFile := make(map[string][]string)
	configsByTargetAndTags := make(map[string]*discoveryBuildConfiguration)
	for _, asmFile := range candidate.AsmFiles {
		dirRel := path.Dir(asmFile)
		if discoveryDirIsIgnored(dirRel) {
			continue
		}
		nested, err := discoveryDirIsNestedModule(moduleDir, dirRel)
		if err != nil {
			return nil, err
		}
		if nested {
			continue
		}
		dir := filepath.Join(moduleDir, filepath.FromSlash(dirRel))
		goFiles, ok := goFilesByDir[dir]
		if !ok {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("read assembly package directory %s: %w", dir, err)
			}
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					continue
				}
				if _, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.PackageClauseOnly); parseErr != nil {
					invalidGoFilesByDir[dir] = append(invalidGoFilesByDir[dir], name)
					continue
				}
				goFiles = append(goFiles, name)
			}
			goFilesByDir[dir] = goFiles
		}
		if len(goFiles) == 0 {
			if sourceNotApplicable != nil {
				invalid := uniqueSortedDiscoveryStrings(invalidGoFilesByDir[dir])
				reason := "assembly directory contains no non-test Go source accepted by Go 1.27"
				if len(invalid) != 0 {
					reason += "; invalid .go files: " + strings.Join(invalid, ", ")
				}
				*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
					AsmFile: asmFile,
					Targets: uniqueSortedDiscoveryStrings(targets),
					Kind:    discoverySourceNotApplicableNoGoPackage,
					Reason:  reason,
				})
			}
			continue
		}
		fileNames := append([]string(nil), goFiles...)
		fileNames = append(fileNames, path.Base(asmFile))
		var customTags []string
		for _, fileName := range fileNames {
			fullPath := filepath.Join(dir, fileName)
			tags, ok := constraintTagsByFile[fullPath]
			if !ok {
				var err error
				tags, err = discoveryConstraintTags(fullPath)
				if err != nil {
					return nil, err
				}
				constraintTagsByFile[fullPath] = tags
			}
			customTags = append(customTags, tags...)
		}
		customTags = uniqueDiscoveryCustomTags(customTags, contexts)
		type contextMatch struct {
			context   build.Context
			target    string
			buildTags []string
		}
		matches := make([]contextMatch, 0, len(contexts))
		for i := range contexts {
			target := contexts[i].GOOS + "/" + contexts[i].GOARCH
			buildTags, ok, err := findDiscoveryBuildTags(
				contexts[i], dir, path.Base(asmFile), goFiles,
				customTags, constraintTagsByFile,
			)
			if err != nil {
				return nil, fmt.Errorf("classify assembly %s: %w", asmFile, err)
			}
			if !ok {
				continue
			}
			matches = append(matches, contextMatch{context: contexts[i], target: target, buildTags: buildTags})
		}
		matchedContexts := make([]build.Context, 0, len(matches))
		for _, match := range matches {
			matchedContexts = append(matchedContexts, match.context)
		}
		sourceTargets, restrictBySource, reason, err := inferUnsuffixedAssemblyTargetsDetailed(filepath.Join(moduleDir, filepath.FromSlash(asmFile)), matchedContexts)
		if err != nil {
			return nil, fmt.Errorf("classify assembly source %s: %w", asmFile, err)
		}
		if reason != "" && sourceNotApplicable != nil {
			var sourceTargetNames []string
			for _, match := range matches {
				sourceTargetNames = append(sourceTargetNames, match.target)
			}
			*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
				AsmFile: asmFile,
				Targets: uniqueSortedDiscoveryStrings(sourceTargetNames),
				Kind:    discoverySourceNotApplicableGoAssembler,
				Reason:  reason,
			})
		}
		for _, match := range matches {
			if restrictBySource && !sourceTargets[match.target] {
				continue
			}
			noSymbols, err := discoveryAssemblyObjectHasNoSymbols(
				filepath.Join(moduleDir, filepath.FromSlash(asmFile)),
				match.context.GOOS, match.context.GOARCH,
			)
			if err != nil {
				return nil, fmt.Errorf("inspect assembly object %s for %s: %w", asmFile, match.target, err)
			}
			if noSymbols {
				if sourceNotApplicable != nil {
					*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
						AsmFile: asmFile,
						Targets: []string{match.target},
						Kind:    discoverySourceNotApplicableNoSymbols,
						Reason:  "current Go assembler accepted the source but emitted no object symbols",
					})
				}
				continue
			}
			key := match.target + "\x00" + strings.Join(match.buildTags, ",")
			config := configsByTargetAndTags[key]
			if config == nil {
				config = &discoveryBuildConfiguration{
					BuildTags: append([]string(nil), match.buildTags...),
					Targets:   []string{match.target},
				}
				configsByTargetAndTags[key] = config
			}
			config.AsmFiles = append(config.AsmFiles, asmFile)
		}
	}
	// Targets can share one translator invocation only when both their build
	// tags and exact source-inferred assembly allowlist are identical.
	configsByShape := make(map[string]*discoveryBuildConfiguration)
	for _, config := range configsByTargetAndTags {
		config.AsmFiles = uniqueSortedDiscoveryStrings(config.AsmFiles)
		shape := strings.Join(config.BuildTags, ",") + "\x00" + strings.Join(config.AsmFiles, "\x00")
		group := configsByShape[shape]
		if group == nil {
			group = &discoveryBuildConfiguration{
				BuildTags: append([]string(nil), config.BuildTags...),
				AsmFiles:  append([]string(nil), config.AsmFiles...),
			}
			configsByShape[shape] = group
		}
		group.Targets = append(group.Targets, config.Targets...)
	}
	keys := make([]string, 0, len(configsByShape))
	for key := range configsByShape {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	configs := make([]discoveryBuildConfiguration, 0, len(keys))
	for _, key := range keys {
		config := configsByShape[key]
		config.Targets = uniqueSortedDiscoveryStrings(config.Targets)
		configs = append(configs, *config)
	}
	return configs, nil
}

func discoveryAssemblyObjectHasNoSymbols(filePath, goos, goarch string) (bool, error) {
	declaresSymbols, err := discoverySourceMentionsSymbolDirective(filePath)
	if err != nil {
		return false, err
	}
	if declaresSymbols {
		return false, nil
	}
	goRoot, err := gotoolchain.Root()
	if err != nil {
		return false, err
	}

	tempDir, err := os.MkdirTemp("", "plan9asm-asm-symbols-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tempDir)
	object := filepath.Join(tempDir, "source.o")
	asmArgs := []string{
		"tool", "asm", "-I", filepath.Dir(filePath),
		"-I", filepath.Join(goRoot, "pkg", "include"),
		"-o", object, filePath,
	}
	targetEnv := replaceEnv(os.Environ(), map[string]string{
		"GOOS": goos, "GOARCH": goarch,
		"GOTOOLCHAIN": "local", "GOWORK": "off",
	})
	asm := exec.Command("go", asmArgs...)
	asm.Env = targetEnv
	if _, err := asm.CombinedOutput(); err != nil {
		// This probe establishes no-symbol evidence only. Other classification
		// and build checks retain any Go-assembler failure as a real outcome.
		return false, nil
	}
	nm := exec.Command("go", "tool", "nm", object)
	nm.Env = targetEnv
	output, err := nm.CombinedOutput()
	lines := strings.TrimSpace(string(output))
	if strings.HasSuffix(lines, ": no symbols") {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Go object symbols: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return lines == "", nil
}

func discoverySourceMentionsSymbolDirective(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	const overlap = len("GLOBL") - 1
	chunk := make([]byte, 64<<10)
	block := make([]byte, 0, len(chunk)+overlap)
	var tail []byte
	for {
		n, readErr := file.Read(chunk)
		if n > 0 {
			block = append(block[:0], tail...)
			block = append(block, chunk[:n]...)
			for _, directive := range [][]byte{[]byte("TEXT"), []byte("GLOBL"), []byte("DATA")} {
				if bytes.Contains(block, directive) {
					return true, nil
				}
			}
			start := len(block) - overlap
			if start < 0 {
				start = 0
			}
			tail = append(tail[:0], block[start:]...)
		}
		if readErr == io.EOF {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

// inferUnsuffixedAssemblyTargets adds a source-level check only when Go's
// filename convention does not already identify an architecture. Go itself
// selects files by name and build tags; external packages sometimes omit both
// while containing unmistakably architecture-specific assembly. Asking the
// same Go assembler that will build the package prevents such x86 sources from
// being sent to ARM or Wasm translators without maintaining a second opcode
// taxonomy here.
func inferUnsuffixedAssemblyTargets(filePath string, contexts []build.Context) (map[string]bool, bool, error) {
	eligible, restrict, _, err := inferUnsuffixedAssemblyTargetsDetailed(filePath, contexts)
	return eligible, restrict, err
}

func inferUnsuffixedAssemblyTargetsDetailed(filePath string, contexts []build.Context) (map[string]bool, bool, string, error) {
	if explicitAssemblyFilenameArchitecture(path.Base(filePath)) != "" {
		return nil, false, "", nil
	}
	goRoot, err := gotoolchain.Root()
	if err != nil {
		return nil, false, "", err
	}
	eligible := make(map[string]bool, len(contexts))
	probed := make(map[string]struct {
		accepted   bool
		conclusive bool
	})
	acceptedAny := false
	conclusiveAny := false
	for _, ctx := range contexts {
		key := ctx.GOOS + "/" + ctx.GOARCH
		result, ok := probed[key]
		if !ok {
			accepted, conclusive := probeAssemblySourceForTarget(filePath, ctx.GOOS, ctx.GOARCH, goRoot)
			result = struct {
				accepted   bool
				conclusive bool
			}{accepted: accepted, conclusive: conclusive}
			probed[key] = result
		}
		if result.accepted || !result.conclusive {
			eligible[key] = true
		}
		acceptedAny = acceptedAny || result.accepted
		conclusiveAny = conclusiveAny || result.conclusive
	}
	if !acceptedAny && conclusiveAny && len(eligible) == 0 {
		// The source is a fixture, generated artifact, or assembly for a target
		// outside this repository's supported matrix. The current Go assembler
		// supplies stronger applicability evidence than an opcode guess: keep an
		// explicit empty allowlist instead of failing translation or silently
		// treating it as cross-architecture source.
		var rejectedTargets []string
		for target := range probed {
			rejectedTargets = append(rejectedTargets, target)
		}
		sort.Strings(rejectedTargets)
		return eligible, true, fmt.Sprintf("current Go assembler rejected unsuffixed source for every selected target: %s", strings.Join(rejectedTargets, ", ")), nil
	}
	if !conclusiveAny {
		// Usually a generated go_asm.h (or another build-generated include) was
		// unavailable. Keep every target visible instead of silently excluding it.
		return nil, false, "", nil
	}
	return eligible, true, "", nil
}

func explicitAssemblyFilenameArchitecture(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	for _, arch := range []string{
		"386", "amd64", "amd64p32", "arm", "arm64", "armbe", "arm64be",
		"loong64", "mips", "mipsle", "mips64", "mips64le", "mips64p32",
		"mips64p32le", "ppc", "ppc64", "ppc64le", "riscv", "riscv64",
		"s390", "s390x", "sparc", "sparc64", "wasm",
	} {
		if strings.HasSuffix(base, "_"+arch) {
			return arch
		}
	}
	return ""
}

func probeAssemblySourceForTarget(filePath, goos, goarch, goRoot string) (accepted, conclusive bool) {
	run := func(extraInclude string) ([]byte, error) {
		args := []string{"tool", "asm"}
		if extraInclude != "" {
			args = append(args, "-I", extraInclude)
		}
		args = append(args, "-I", filepath.Dir(filePath), "-I", filepath.Join(goRoot, "pkg", "include"), "-o", os.DevNull, filePath)
		cmd := exec.Command("go", args...)
		cmd.Env = replaceEnv(os.Environ(), map[string]string{
			"GOOS":        goos,
			"GOARCH":      goarch,
			"GOTOOLCHAIN": "local",
			"GOWORK":      "off",
		})
		return cmd.CombinedOutput()
	}
	output, err := run("")
	if err == nil {
		return true, true
	}
	message := strings.ToLower(string(output))
	if missingGoAsmHeader(message) {
		stubDir, stubErr := os.MkdirTemp("", "plan9asm-go-asm-header-")
		if stubErr != nil {
			return false, false
		}
		defer os.RemoveAll(stubDir)
		if stubErr := os.WriteFile(filepath.Join(stubDir, "go_asm.h"), nil, 0o600); stubErr != nil {
			return false, false
		}
		output, err = run(stubDir)
		if err == nil {
			return true, true
		}
		message = strings.ToLower(string(output))
	}
	for _, fragment := range []string{"no such file or directory", "cannot find", "could not find"} {
		if strings.Contains(message, fragment) {
			return false, false
		}
	}
	return false, true
}

func missingGoAsmHeader(message string) bool {
	message = strings.ToLower(message)
	if !strings.Contains(message, "go_asm.h") {
		return false
	}
	for _, fragment := range []string{"no such file or directory", "cannot find", "could not find"} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func discoveryConstraintTags(filePath string) ([]string, error) {
	if strings.HasSuffix(filePath, ".go") {
		return discoveryGoConstraintTags(filePath)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open build constraints %s: %w", filePath, err)
	}
	defer file.Close()
	set := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	inBlockComment := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/*") {
			inBlockComment = !strings.Contains(line, "*/")
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("parse build constraint %s: %w", filePath, err)
		}
		collectDiscoveryConstraintTags(expr, set)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read build constraints %s: %w", filePath, err)
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func discoveryGoConstraintTags(filePath string) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse Go build constraints %s: %w", filePath, err)
	}
	set := make(map[string]bool)
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			line := strings.TrimSpace(comment.Text)
			if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
				continue
			}
			expr, err := constraint.Parse(line)
			if err != nil {
				return nil, fmt.Errorf("parse build constraint %s: %w", filePath, err)
			}
			collectDiscoveryConstraintTags(expr, set)
		}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func collectDiscoveryConstraintTags(expr constraint.Expr, tags map[string]bool) {
	switch expr := expr.(type) {
	case *constraint.TagExpr:
		tags[expr.Tag] = true
	case *constraint.NotExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
	case *constraint.AndExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
		collectDiscoveryConstraintTags(expr.Y, tags)
	case *constraint.OrExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
		collectDiscoveryConstraintTags(expr.Y, tags)
	}
}

func uniqueDiscoveryCustomTags(tags []string, contexts []build.Context) []string {
	reserved := map[string]bool{
		// "ignore" conventionally marks generator inputs and other files that
		// are not part of any build. Enabling it globally also selects Go's own
		// ignored generator programs and produces packages that cannot compile.
		"ignore": true,
		"aix":    true, "android": true, "darwin": true, "dragonfly": true,
		"freebsd": true, "hurd": true, "illumos": true, "ios": true,
		"js": true, "linux": true, "netbsd": true, "openbsd": true,
		"plan9": true, "solaris": true, "unix": true, "wasip1": true,
		"windows": true, "zos": true,
		"386": true, "amd64": true, "amd64p32": true, "arm": true,
		"armbe": true, "arm64": true, "arm64be": true, "loong64": true,
		"mips": true, "mipsle": true, "mips64": true, "mips64le": true,
		"mips64p32": true, "mips64p32le": true, "ppc": true, "ppc64": true,
		"ppc64le": true, "riscv": true, "riscv64": true, "s390": true,
		"s390x": true, "sparc": true, "sparc64": true, "wasm": true,
		"cgo": true, "gc": true, "gccgo": true,
	}
	for _, ctx := range contexts {
		reserved[ctx.GOOS] = true
		reserved[ctx.GOARCH] = true
		reserved[ctx.Compiler] = true
		for _, tag := range ctx.ReleaseTags {
			reserved[tag] = true
		}
		for _, tag := range ctx.ToolTags {
			reserved[tag] = true
		}
	}
	set := make(map[string]bool)
	for _, tag := range tags {
		if tag != "" && !reserved[tag] {
			set[tag] = true
		}
	}
	out := make([]string, 0, len(set))
	for tag := range set {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedDiscoveryStrings(values []string) []string {
	out := uniqueDiscoveryStrings(values)
	sort.Strings(out)
	return out
}

func uniqueDiscoveryStrings(values []string) []string {
	set := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if set[value] {
			continue
		}
		set[value] = true
		out = append(out, value)
	}
	return out
}

func discoveryDirIsIgnored(dir string) bool {
	if dir == "." || dir == "" {
		return false
	}
	for _, elem := range strings.Split(filepath.ToSlash(dir), "/") {
		if elem == "testdata" || elem == "vendor" || strings.HasPrefix(elem, ".") || strings.HasPrefix(elem, "_") {
			return true
		}
	}
	return false
}

func discoveryDirIsNestedModule(moduleDir, dirRel string) (bool, error) {
	for dirRel != "." && dirRel != "" {
		_, err := os.Stat(filepath.Join(moduleDir, filepath.FromSlash(dirRel), "go.mod"))
		switch {
		case err == nil:
			return true, nil
		case os.IsNotExist(err):
			// Continue toward the root module.
		case err != nil:
			return false, fmt.Errorf("stat nested go.mod in %s: %w", dirRel, err)
		}
		dirRel = path.Dir(dirRel)
	}
	return false, nil
}

func runDiscoveryCorpus(cfg discoveryCorpusConfig) (runErr error) {
	if cfg.ShardCount <= 0 || cfg.ShardIndex < 0 || cfg.ShardIndex >= cfg.ShardCount {
		return fmt.Errorf("invalid discovery shard %d/%d", cfg.ShardIndex, cfg.ShardCount)
	}
	if cfg.CandidateTimeout <= 0 {
		return fmt.Errorf("candidate timeout must be positive")
	}
	// Candidate commands run in isolated module directories. Resolve paths
	// before provenance capture so the checked tools are also the executed
	// tools, regardless of the candidate's working directory or PATH.
	var err error
	cfg.RepoRoot, err = filepath.Abs(cfg.RepoRoot)
	if err != nil {
		return fmt.Errorf("resolve discovery repository: %w", err)
	}
	for _, path := range []*string{&cfg.Translator, &cfg.LLC} {
		if *path == "" { // Offline orchestration fixtures have no executables.
			continue
		}
		*path, err = resolveDiscoveryExecutable(*path)
		if err != nil {
			return err
		}
	}
	captureProvenance := collectDiscoveryProvenance
	if cfg.captureProvenance != nil {
		captureProvenance = cfg.captureProvenance
	}
	runCandidate := runDiscoveryCandidate
	if cfg.runCandidate != nil {
		runCandidate = cfg.runCandidate
	}
	provenance, err := captureProvenance(cfg)
	if err != nil {
		return fmt.Errorf("discovery provenance preflight: %w", err)
	}
	if provenance.Source.Dirty {
		fmt.Println("diagnostic-only discovery run: dirty source cannot satisfy aggregate verification")
	}
	allCandidates, err := loadDiscoveryCandidates(cfg.LedgerPath)
	if err != nil {
		return err
	}
	invalidSourceSkips, err := loadInvalidMachineCodeSkips(cfg.RepoRoot)
	if err != nil {
		return err
	}
	supersededSkips, err := loadSupersededSkips(cfg.RepoRoot, cfg.LedgerPath)
	if err != nil {
		return err
	}
	privateExtensionSkips, err := loadPrivateExtensionSkips(cfg.RepoRoot, cfg.LedgerPath)
	if err != nil {
		return err
	}
	cfg.privateExtensionSkips = privateExtensionSkips
	candidates := allCandidates
	if cfg.FilterTargets {
		candidates, err = filterDiscoveryCandidatesForTargets(allCandidates, cfg.Targets)
		if err != nil {
			return err
		}
	}
	selected := selectDiscoveryShard(candidates, cfg.ShardIndex, cfg.ShardCount)
	report := discoveryCorpusReport{
		SchemaVersion:      discoveryReportSchema,
		Provenance:         provenance,
		Targets:            append([]string(nil), cfg.Targets...),
		TargetFiltered:     cfg.FilterTargets,
		ShardIndex:         cfg.ShardIndex,
		ShardCount:         cfg.ShardCount,
		CandidateTotal:     len(allCandidates),
		EligibleCandidates: len(candidates),
		Partial:            len(selected) > 0,
		Results:            make([]discoveryCorpusResult, 0, len(selected)),
	}
	tmpRoot, err := os.MkdirTemp("", fmt.Sprintf("plan9asm-discovery-%02d-", cfg.ShardIndex))
	if err != nil {
		return err
	}
	defer func() {
		if err := removeDiscoveryCandidateWorkspace(tmpRoot); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("clean discovery shard workspace: %w", err))
		}
	}()
	// Reuse standard-library compilation within this shard. A caller-owned
	// cache can also be shared by parallel shards; only the shard-owned default
	// is discarded when this run returns.
	if cfg.buildCache == "" {
		cfg.buildCache = filepath.Join(tmpRoot, "build-cache")
	} else {
		if !filepath.IsAbs(cfg.buildCache) {
			return fmt.Errorf("discovery build cache must be an absolute path: %q", cfg.buildCache)
		}
		info, err := os.Stat(cfg.buildCache)
		if err != nil {
			return fmt.Errorf("stat discovery build cache: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("discovery build cache is not a directory: %q", cfg.buildCache)
		}
	}
	if report.Partial {
		// A runner can be canceled inside its first candidate. Publish an
		// auditable zero-result checkpoint before entering that long operation.
		if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
			return err
		}
	}
	checkpoint := func(completed int) error {
		if !report.Partial || completed%8 != 0 || completed >= len(selected) || cfg.ReportPath == "" {
			return nil
		}
		// Never publish a pass after a source, ledger or tool mutation.
		current, provenanceErr := captureProvenance(cfg)
		if provenanceErr != nil || current != provenance {
			report.Provenance.Invalidated = "source, ledger or tools changed during corpus run"
		}
		if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
			return err
		}
		if report.Provenance.Invalidated != "" {
			return fmt.Errorf("discovery provenance invalidated during checkpoint: %s (capture error: %v)", report.Provenance.Invalidated, provenanceErr)
		}
		return nil
	}
	for i, candidate := range selected {
		fmt.Printf("[%d/%d] %s\n", i+1, len(selected), candidate.exactKey())
		result := discoveryCorpusResult{
			Module:             candidate.Module,
			Version:            candidate.Version,
			DiscoveredAsmFiles: append([]string(nil), candidate.AsmFiles...),
		}
		candidateDir := filepath.Join(tmpRoot, fmt.Sprintf("candidate-%04d", i))
		if skip, ok := supersededSkips[candidate.exactKey()]; ok {
			result.Status = discoveryStatusSkippedSuperseded
			result.Superseded = &skip
			report.SkippedSuperseded++
			report.Results = append(report.Results, result)
			report.Selected++
			fmt.Printf("SKIP_SUPERSEDED %s: %s replaces it\n", candidate.exactKey(), skip.ReplacementModule+"@"+skip.ReplacementVersion)
			if err := checkpoint(i + 1); err != nil {
				return err
			}
			continue
		}
		if skip, ok := invalidSourceSkips[candidate.exactKey()]; ok {
			err := verifyInvalidMachineCodeCandidate(cfg, candidate, candidateDir, skip)
			if err == nil {
				result.Status = discoveryStatusSkippedInvalidSource
				result.InvalidSourceReason = skip.Reason
				result.InvalidSourceEvidence = append(result.InvalidSourceEvidence, skip.Evidence...)
				report.SkippedInvalidSource++
				fmt.Printf("SKIP_INVALID_SOURCE %s: %s\n", candidate.exactKey(), skip.Reason)
			} else {
				result.Status = discoveryStatusFailed
				result.Error = fmt.Sprintf("invalid-source skip proof failed: %v", err)
				report.Failed++
				fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", candidate.exactKey(), result.Error)
			}
			report.Results = append(report.Results, result)
			report.Selected++
			if err := checkpoint(i + 1); err != nil {
				return err
			}
			continue
		}
		matrix, patterns, buildConfigurations, runErr := runCandidate(cfg, candidate, candidateDir)
		applicableAsmFiles := discoveryConfigurationAsmFiles(buildConfigurations)
		result.Patterns = patterns
		result.ApplicableAsmFiles = applicableAsmFiles
		result.BuildConfigurations = buildConfigurations
		result.NotApplicableItems = append(result.NotApplicableItems, matrix.NotApplicableItems...)
		result.SourceNotApplicableItems = append(result.SourceNotApplicableItems, matrix.SourceNotApplicableItems...)
		if runErr != nil {
			result.Status = discoveryStatusFailed
			result.Error = runErr.Error()
			report.Failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", candidate.exactKey(), runErr)
		} else if matrix.PrivateExtension != nil {
			result.Status = discoveryStatusSkippedPrivateExtension
			result.PrivateExtension = matrix.PrivateExtension
			result.Translations = matrix.Success
			result.NotApplicableTranslations = matrix.NotApplicable
			report.SkippedPrivateExtension++
			report.Translations += matrix.Success
			report.NotApplicableTranslations += matrix.NotApplicable
			fmt.Printf("SKIP_PRIVATE_EXTENSION %s: %s on %s; other translations=%d\n",
				candidate.exactKey(), matrix.PrivateExtension.AsmFile,
				matrix.PrivateExtension.Target, matrix.Success)
		} else if len(applicableAsmFiles) == 0 || matrix.Success == 0 {
			result.Status = discoveryStatusNotApplicable
			if len(applicableAsmFiles) == 0 {
				result.NotApplicableReason = "no discovered assembly file belongs to a buildable Go package on the supported target matrix"
			} else {
				result.NotApplicableReason = "every target-selected assembly source has evidence-backed current-Go source or ABI incompatibility"
			}
			result.NotApplicableTranslations = matrix.NotApplicable
			report.NotApplicableTranslations += matrix.NotApplicable
			report.NotApplicable++
			fmt.Printf("NOT_APPLICABLE %s: discovered_files=%d\n", candidate.exactKey(), len(candidate.AsmFiles))
		} else {
			result.Status = discoveryStatusPassed
			result.Translations = matrix.Success
			result.NotApplicableTranslations = matrix.NotApplicable
			report.Passed++
			report.Translations += matrix.Success
			report.NotApplicableTranslations += matrix.NotApplicable
			fmt.Printf("PASS %s: applicable_files=%d translations=%d not_applicable_translations=%d targets=%d\n", candidate.exactKey(), len(applicableAsmFiles), matrix.Success, matrix.NotApplicable, matrix.TotalTargets)
		}
		report.Results = append(report.Results, result)
		report.Selected++
		if err := checkpoint(i + 1); err != nil {
			return err
		}
	}
	report.Partial = false
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		return err
	}
	finalProvenance, provenanceErr := captureProvenance(cfg)
	if provenanceErr != nil || finalProvenance != provenance {
		report.Provenance.Invalidated = "source, ledger or tools changed during corpus run"
	}
	if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
		return err
	}
	if report.Provenance.Invalidated != "" {
		return fmt.Errorf("discovery provenance invalidated: %s (capture error: %v)", report.Provenance.Invalidated, provenanceErr)
	}
	if report.Failed != 0 {
		return fmt.Errorf("discovery shard %d/%d failed: passed=%d failed=%d selected=%d", cfg.ShardIndex, cfg.ShardCount, report.Passed, report.Failed, report.Selected)
	}
	fmt.Printf(
		"discovery shard %d/%d passed: applicable=%d not_applicable=%d "+
			"skipped_invalid_source=%d skipped_superseded=%d "+
			"skipped_private_extension=%d translations=%d not_applicable_translations=%d\n",
		cfg.ShardIndex, cfg.ShardCount,
		report.Passed, report.NotApplicable,
		report.SkippedInvalidSource, report.SkippedSuperseded,
		report.SkippedPrivateExtension, report.Translations, report.NotApplicableTranslations,
	)
	return nil
}

func resolveDiscoveryExecutable(name string) (string, error) {
	resolved := name
	if !strings.ContainsAny(name, `/\`) && filepath.VolumeName(name) == "" {
		var err error
		resolved, err = exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("resolve discovery executable %q: %w", name, err)
		}
	}
	resolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve discovery executable %q: %w", name, err)
	}
	return resolved, nil
}

func validateDiscoveryCorpusAccounting(report discoveryCorpusReport) error {
	for _, count := range []int{
		report.CandidateTotal, report.EligibleCandidates, report.Selected,
		report.Passed, report.Failed, report.NotApplicable, report.SkippedInvalidSource,
		report.SkippedSuperseded, report.SkippedPrivateExtension,
		report.Translations, report.NotApplicableTranslations,
	} {
		if count < 0 {
			return fmt.Errorf("discovery report contains a negative count")
		}
	}
	classified := report.Passed + report.Failed + report.NotApplicable +
		report.SkippedInvalidSource + report.SkippedSuperseded + report.SkippedPrivateExtension
	if report.Selected != classified {
		return fmt.Errorf(
			"discovery report accounting mismatch: selected=%d classified=%d",
			report.Selected, classified,
		)
	}
	if len(report.Results) != 0 && len(report.Results) != report.Selected {
		return fmt.Errorf("discovery report result count mismatch: selected=%d results=%d", report.Selected, len(report.Results))
	}
	var passed, failed, notApplicable int
	var skippedInvalidSource, skippedSuperseded, skippedPrivateExtension int
	var translations, notApplicableTranslations int
	for _, result := range report.Results {
		if result.Translations < 0 || result.NotApplicableTranslations < 0 {
			return fmt.Errorf("%s@%s: negative translation counts", result.Module, result.Version)
		}
		switch result.Status {
		case discoveryStatusPassed:
			passed++
		case discoveryStatusFailed:
			failed++
		case discoveryStatusNotApplicable:
			notApplicable++
		case discoveryStatusSkippedInvalidSource:
			skippedInvalidSource++
			if err := validateInvalidSourceReportEvidence(result); err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
		case discoveryStatusSkippedSuperseded:
			skippedSuperseded++
			if result.Superseded == nil || result.Superseded.Module != result.Module ||
				result.Superseded.Version != result.Version || result.Translations != 0 ||
				result.NotApplicableTranslations != 0 || result.Error != "" ||
				len(result.ApplicableAsmFiles) != 0 || len(result.BuildConfigurations) != 0 ||
				len(result.InvalidSourceEvidence) != 0 || result.InvalidSourceReason != "" {
				return fmt.Errorf("%s@%s: invalid superseded skip", result.Module, result.Version)
			}
		case discoveryStatusSkippedPrivateExtension:
			skippedPrivateExtension++
			if err := validatePrivateExtensionResult(result); err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
		default:
			return fmt.Errorf("%s@%s: invalid discovery result status %q", result.Module, result.Version, result.Status)
		}
		if result.Status != discoveryStatusSkippedSuperseded && result.Superseded != nil {
			return fmt.Errorf("%s@%s: non-superseded result carries supersession", result.Module, result.Version)
		}
		if result.Status != discoveryStatusSkippedPrivateExtension && result.PrivateExtension != nil {
			return fmt.Errorf("%s@%s: non-private result carries private-extension skip", result.Module, result.Version)
		}
		translations += result.Translations
		notApplicableTranslations += result.NotApplicableTranslations
		if err := validateDiscoverySourceNotApplicableEvidence(result); err != nil {
			return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
		}
	}
	if len(report.Results) != 0 &&
		(passed != report.Passed || failed != report.Failed ||
			notApplicable != report.NotApplicable ||
			skippedInvalidSource != report.SkippedInvalidSource ||
			skippedSuperseded != report.SkippedSuperseded ||
			skippedPrivateExtension != report.SkippedPrivateExtension) {
		return fmt.Errorf("discovery report result status counts differ from summary")
	}
	if len(report.Results) != 0 && (translations != report.Translations || notApplicableTranslations != report.NotApplicableTranslations) {
		return fmt.Errorf("discovery report result translation counts are translations=%d not_applicable=%d, summary is translations=%d not_applicable=%d", translations, notApplicableTranslations, report.Translations, report.NotApplicableTranslations)
	}
	return nil
}

func validateDiscoverySourceNotApplicableEvidence(result discoveryCorpusResult) error {
	discovered := make(map[string]bool, len(result.DiscoveredAsmFiles))
	for _, asmFile := range result.DiscoveredAsmFiles {
		discovered[asmFile] = true
	}
	allowedKinds := map[string]bool{
		discoverySourceNotApplicableGoAssembler: true,
		discoverySourceNotApplicableNoGoPackage: true,
		discoverySourceNotApplicableGoBuild:     true,
		discoverySourceNotApplicableAsmDecl:     true,
		discoverySourceNotApplicableNoSymbols:   true,
	}
	for _, item := range result.SourceNotApplicableItems {
		files := append([]string(nil), item.AsmFiles...)
		if item.AsmFile != "" {
			files = append(files, item.AsmFile)
		}
		files = uniqueSortedDiscoveryStrings(files)
		valid := allowedKinds[item.Kind] && len(files) != 0 && len(item.Targets) != 0 && item.Reason != ""
		for _, asmFile := range files {
			valid = valid && discovered[asmFile]
		}
		for _, target := range item.Targets {
			goos, goarch, ok := strings.Cut(target, "/")
			valid = valid && ok && goos != "" && goarch != ""
		}
		if !valid {
			return fmt.Errorf("invalid source not-applicable evidence: kind=%q files=%v targets=%v", item.Kind, files, item.Targets)
		}
	}
	return nil
}

func discoveryConfigurationAsmFiles(configs []discoveryBuildConfiguration) []string {
	var files []string
	for _, config := range configs {
		files = append(files, config.AsmFiles...)
	}
	return uniqueSortedDiscoveryStrings(files)
}

func runDiscoveryCandidate(cfg discoveryCorpusConfig, candidate discoveryCandidate, workDir string) (result matrixReport, patterns []string, configurations []discoveryBuildConfiguration, runErr error) {
	// Own exactly this newly created candidate directory. Never delete a
	// caller's pre-existing workspace or the user's shared module cache.
	if err := os.Mkdir(workDir, 0755); err != nil {
		return matrixReport{}, nil, nil, err
	}
	defer func() {
		if err := removeDiscoveryCandidateWorkspace(workDir); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("clean candidate workspace: %w", err))
		}
	}()
	// Downloading metadata does not require the corpus build toolchain. Keep
	// this bootstrap workspace compatible with the root module's Go floor;
	// the later build plan still explicitly requires the current corpus Go.
	if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte("module plan9asm.local/discovery\n\ngo 1.20\n"), 0644); err != nil {
		return matrixReport{}, nil, nil, fmt.Errorf("write temporary go.mod: %w", err)
	}
	var env []string
	var download moduleDownloadInfo
	err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
		var err error
		env, err = discoveryCandidateEnvironment(ctx, workDir, os.Environ())
		if err != nil {
			return err
		}
		if cfg.buildCache != "" {
			env = replaceEnv(env, map[string]string{"GOCACHE": cfg.buildCache})
		}
		return retryDiscoveryGoNetwork(ctx, []time.Duration{time.Second, 3 * time.Second}, func() error {
			downloadJSON, commandErr := runCapturedCommandOutput(
				ctx,
				workDir,
				env,
				"go",
				"mod",
				"download",
				"-json",
				candidate.Module+"@"+candidate.Version,
			)
			download, err = resolveModuleDownload(
				downloadJSON,
				commandErr,
				filepath.Join(workDir, "module-source"),
			)
			if err != nil {
				return fmt.Errorf("download module: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		return matrixReport{}, nil, nil, err
	}
	var sourceNotApplicable []discoverySourceNotApplicableItem
	buildConfigurations, err := discoveryBuildConfigurationsWithEvidence(candidate, download.Dir, cfg.Targets, &sourceNotApplicable)
	if err != nil {
		return matrixReport{}, nil, nil, fmt.Errorf("classify discovered assembly: %w", err)
	}
	var privateExtension *discoveryPrivateExtensionSkip
	if skip, ok := cfg.privateExtensionSkips[candidate.exactKey()]; ok {
		filtered, active, err := filterPrivateExtensionConfigurations(buildConfigurations, skip)
		if err != nil {
			return matrixReport{}, nil, nil, err
		}
		if active {
			if err := verifyPrivateExtensionSource(download.Dir, skip); err != nil {
				return matrixReport{}, nil, nil, err
			}
			if err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
				return verifyPrivateExtensionGoAssembler(ctx, workDir, download.Dir, env, skip)
			}); err != nil {
				return matrixReport{}, nil, nil, err
			}
			buildConfigurations = filtered
			privateExtension = &skip
		}
	}
	if len(buildConfigurations) == 0 {
		return matrixReport{
			SourceNotApplicableItems: sourceNotApplicable,
			PrivateExtension:         privateExtension,
		}, nil, buildConfigurations, nil
	}
	declaredModule := candidate.Module
	if download.GoMod != "" {
		goModContents, err := os.ReadFile(download.GoMod)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("read downloaded go.mod: %w", err)
		}
		declaredModule, err = parseDeclaredModulePath(goModContents)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("read declared module path: %w", err)
		}
	}
	patternSet := make(map[string]bool)
	aggregate := matrixReport{
		SourceNotApplicableItems: sourceNotApplicable,
		PrivateExtension:         privateExtension,
	}
	runTargets := make(map[string]bool)
	executedBuildConfigurations := make([]discoveryBuildConfiguration, 0, len(buildConfigurations))
	invocationIndex := 0
	for _, buildConfiguration := range buildConfigurations {
		applicableCandidate := candidate
		applicableCandidate.AsmFiles = buildConfiguration.AsmFiles
		plan, err := makeDiscoveryExecutionPlan(applicableCandidate, declaredModule)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, err
		}
		if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte(plan.GoMod), 0644); err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("write exact module mapping: %w", err)
		}
		packageGroups := discoveryPackageGroupsForModule(applicableCandidate, plan.ModulePath)
		for _, target := range buildConfiguration.Targets {
			err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
				var targetAsmFiles []string
				var eligibleGroups []discoveryPackageGroup
				for _, group := range packageGroups {
					if err := runDiscoveryGoBuild(ctx, workDir, env, target, buildConfiguration.BuildTags, group.Pattern); err != nil {
						if isDiscoveryInfrastructureFailure(err) {
							return fmt.Errorf("verify current Go package %s for %s with build tags %v: %w", group.Pattern, target, buildConfiguration.BuildTags, err)
						}
						aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
							AsmFiles: append([]string(nil), group.AsmFiles...),
							Targets:  []string{target},
							Kind:     discoverySourceNotApplicableGoBuild,
							Reason:   limitDiscoveryEvidence(err.Error(), 8192),
						})
						continue
					}
					validAsmFiles := append([]string(nil), group.AsmFiles...)
					if err := runDiscoveryAsmDecl(ctx, workDir, env, target, buildConfiguration.BuildTags, []string{group.Pattern}); err != nil {
						rejected := discoveryAsmDeclRejectedFiles(validAsmFiles, err.Error())
						if len(rejected) == 0 {
							rejected = append(rejected, validAsmFiles...)
						}
						aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
							AsmFiles: append([]string(nil), rejected...),
							Targets:  []string{target},
							Kind:     discoverySourceNotApplicableAsmDecl,
							Reason:   limitDiscoveryEvidence(err.Error(), 8192),
						})
						validAsmFiles = subtractDiscoveryStrings(validAsmFiles, rejected)
					}
					if len(validAsmFiles) == 0 {
						continue
					}
					targetAsmFiles = append(targetAsmFiles, validAsmFiles...)
					eligibleGroups = append(eligibleGroups, discoveryPackageGroup{
						Pattern: group.Pattern, AsmFiles: validAsmFiles,
					})
				}
				if len(targetAsmFiles) == 0 {
					return nil
				}
				targetAsmFiles = uniqueSortedDiscoveryStrings(targetAsmFiles)
				executed := discoveryBuildConfiguration{
					BuildTags: append([]string(nil), buildConfiguration.BuildTags...),
					Targets:   []string{target},
					AsmFiles:  append([]string(nil), targetAsmFiles...),
				}
				executedBuildConfigurations = append(executedBuildConfigurations, executed)
				units := discoveryTranslationUnits(eligibleGroups)
				if err := validateDiscoveryTranslationUnits(units, targetAsmFiles); err != nil {
					return err
				}
				for _, unit := range units {
					patternSet[unit.Patterns[0]] = true
					targetCandidate := candidate
					targetCandidate.AsmFiles = unit.AsmFiles
					reportPath := filepath.Join(workDir, fmt.Sprintf("matrix-report-%04d.json", invocationIndex))
					outputIndex := invocationIndex
					invocation := makeDiscoveryTranslatorInvocation(
						workDir,
						plan.ModulePath,
						unit.Patterns,
						buildConfiguration.BuildTags,
						[]string{target},
						unit.AsmFiles,
						discoveryTargetOutputDirectory(workDir, outputIndex),
						cfg.RepoRoot,
						cfg.LLC,
						reportPath,
					)
					invocationIndex++
					if err := runCapturedCommand(ctx, invocation.Dir, env, cfg.Translator, invocation.Args...); err != nil {
						return fmt.Errorf("translate and compile package %s for %s with build tags %v: %w", unit.Patterns[0], target, buildConfiguration.BuildTags, err)
					}
					report, err := loadReport(reportPath)
					if err != nil {
						return err
					}
					if err := validateDiscoveryReport([]string{target}, targetCandidate, report); err != nil {
						return fmt.Errorf("package %s target %s build tags %v: %w", unit.Patterns[0], target, buildConfiguration.BuildTags, err)
					}
					runTargets[target] = true
					aggregate.TotalAsm += report.TotalAsm
					aggregate.Success += report.Success
					aggregate.NotApplicable += report.NotApplicable
					aggregate.Failed += report.Failed
					aggregate.NotApplicableItems = append(aggregate.NotApplicableItems, collectMatrixNotApplicableItems(report)...)
					if err := removeDiscoveryTargetOutput(workDir, outputIndex); err != nil {
						return fmt.Errorf("remove target %s generated output: %w", target, err)
					}
				}
				return nil
			})
			if err != nil {
				return matrixReport{}, sortedDiscoverySet(patternSet), executedBuildConfigurations, err
			}
		}
	}
	aggregate.TotalTargets = len(runTargets)
	return aggregate, sortedDiscoverySet(patternSet), executedBuildConfigurations, nil
}

func discoveryTargetOutputDirectory(workDir string, index int) string {
	return filepath.Join(workDir, "out", fmt.Sprintf("config-%04d", index))
}

func removeDiscoveryTargetOutput(workDir string, index int) error {
	return os.RemoveAll(discoveryTargetOutputDirectory(workDir, index))
}

func runDiscoveryOperation(timeout time.Duration, run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return run(ctx)
}

func discoveryCommandEnvironment(base []string) []string {
	// Direct GOPROXY fallback must not inherit a developer's URL rewrite to
	// SSH or block waiting for credentials to public source repositories.
	return replaceEnv(base, map[string]string{
		"CGO_ENABLED":         "0",
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_TERMINAL_PROMPT": "0",
		"GOFLAGS":             "-mod=mod",
		"GOTOOLCHAIN":         "local",
		"GOWORK":              "off",
	})
}

func discoveryCandidateEnvironment(ctx context.Context, workDir string, base []string) ([]string, error) {
	env := discoveryCommandEnvironment(base)
	output, err := runCapturedCommandOutput(ctx, workDir, env, "go", "env", "-json", "GOMODCACHE", "GOPROXY")
	if err != nil {
		return nil, fmt.Errorf("read shared module cache configuration: %w", err)
	}
	var shared struct{ GOMODCACHE, GOPROXY string }
	if err := json.Unmarshal(output, &shared); err != nil {
		return nil, fmt.Errorf("decode shared module cache configuration: %w", err)
	}
	if err := os.Mkdir(filepath.Join(workDir, "tmp"), 0700); err != nil {
		return nil, fmt.Errorf("create candidate temporary directory: %w", err)
	}
	return isolatedDiscoveryModuleEnvironment(env, workDir, shared.GOMODCACHE, shared.GOPROXY), nil
}

func isolatedDiscoveryModuleEnvironment(base []string, workDir, sharedCache, upstreamProxy string) []string {
	proxy := upstreamProxy
	if sharedCache != "" {
		cachePath := filepath.ToSlash(filepath.Join(sharedCache, "cache", "download"))
		if !strings.HasPrefix(cachePath, "/") {
			cachePath = "/" + cachePath
		}
		cacheURL := (&url.URL{Scheme: "file", Path: cachePath}).String()
		proxy = cacheURL
		if upstreamProxy != "" {
			proxy += "," + upstreamProxy
		}
	}
	return replaceEnv(base, map[string]string{
		"GOMODCACHE":  filepath.Join(workDir, "module-cache"),
		"GOCACHE":     filepath.Join(workDir, "build-cache"),
		"GOCACHEPROG": "",
		"GOTMPDIR":    filepath.Join(workDir, "tmp"),
		"TMPDIR":      filepath.Join(workDir, "tmp"),
		"TMP":         filepath.Join(workDir, "tmp"),
		"TEMP":        filepath.Join(workDir, "tmp"),
		"GOPROXY":     proxy,
		"GOFLAGS":     "-mod=mod -modcacherw",
	})
}

func removeDiscoveryCandidateWorkspace(workDir string) error {
	// Go normally extracts read-only module directories. Only walk this owned
	// candidate tree; WalkDir does not follow symlinks into any shared cache.
	if err := filepath.WalkDir(workDir, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(name, 0700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(workDir)
}

func resolveModuleDownload(downloadJSON []byte, commandErr error, extractDir string) (moduleDownloadInfo, error) {
	var download moduleDownloadInfo
	if err := json.Unmarshal(downloadJSON, &download); err != nil {
		if commandErr != nil {
			return moduleDownloadInfo{}, commandErr
		}
		return moduleDownloadInfo{}, fmt.Errorf("decode module download metadata: %w", err)
	}
	if download.Dir != "" {
		if info, err := os.Stat(download.Dir); err == nil && info.IsDir() {
			return download, nil
		}
	}
	if download.Zip != "" {
		if err := extractModuleZip(download.Zip, extractDir, download.Path, download.Version); err == nil {
			download.Dir = extractDir
			if download.GoMod == "" {
				download.GoMod = filepath.Join(extractDir, "go.mod")
			}
			return download, nil
		} else if commandErr == nil && download.Error == "" {
			return moduleDownloadInfo{}, fmt.Errorf("extract cached module ZIP: %w", err)
		}
	}
	if download.Error != "" {
		return moduleDownloadInfo{}, errors.New(download.Error)
	}
	if commandErr != nil {
		return moduleDownloadInfo{}, commandErr
	}
	return moduleDownloadInfo{}, errors.New("module download metadata contains neither a directory nor a usable ZIP")
}

func extractModuleZip(zipPath, destination, modulePath, version string) error {
	if err := module.Check(modulePath, version); err != nil {
		return fmt.Errorf("validate module version: %w", err)
	}
	// Module cache file names escape uppercase letters (for example, Upper
	// becomes !upper), but paths inside a module ZIP retain the canonical,
	// unescaped module path and version.
	prefix := modulePath + "@" + version + "/"
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	for _, file := range reader.File {
		name := filepath.ToSlash(file.Name)
		if !strings.HasPrefix(name, prefix) {
			return fmt.Errorf("module ZIP entry %q is outside expected prefix %q", file.Name, prefix)
		}
		relative := strings.TrimPrefix(name, prefix)
		if relative == "" {
			continue
		}
		clean := path.Clean(relative)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return fmt.Errorf("unsafe module ZIP path %q", file.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(clean))
		rel, err := filepath.Rel(destination, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe module ZIP path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular module ZIP entry %q", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		source, err := file.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			_, err = io.Copy(output, source)
		}
		closeOutputErr := error(nil)
		if output != nil {
			closeOutputErr = output.Close()
		}
		closeSourceErr := source.Close()
		if err != nil {
			return err
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeSourceErr != nil {
			return closeSourceErr
		}
	}
	return nil
}

func runDiscoveryGoBuild(ctx context.Context, dir string, env []string, target string, buildTags []string, pattern string) error {
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok || goos == "" || goarch == "" {
		return fmt.Errorf("invalid discovery target %q", target)
	}
	args := []string{"build"}
	if len(buildTags) != 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	args = append(args, pattern)
	targetEnv := replaceEnv(env, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        goos,
		"GOARCH":      goarch,
	})
	return retryDiscoveryGoNetwork(ctx, []time.Duration{time.Second, 3 * time.Second}, func() error {
		return runCapturedCommand(ctx, dir, targetEnv, "go", args...)
	})
}

// Downloading a module and building its dependencies can both encounter
// transient proxy failures. Retry only network diagnostics within the original
// operation deadline. Source, checksum, resource and toolchain errors need a
// different fix and must not be hidden behind repeated attempts.
func retryDiscoveryGoNetwork(ctx context.Context, delays []time.Duration, operation func() error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := operation()
		if err == nil || attempt >= len(delays) || !isDiscoveryRetryableNetworkFailure(err.Error()) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(delays[attempt]):
		}
	}
}

func isDiscoveryRetryableNetworkFailure(diagnostic string) bool {
	if !isDiscoveryGoBuildInfrastructureFailure(diagnostic) {
		return false
	}
	diagnostic = strings.ToLower(diagnostic)
	for _, marker := range []string{
		"too many requests",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"i/o timeout",
		"tls handshake timeout",
		"connection reset",
		"connection closed by",
		"temporary failure",
		"unexpected eof",
	} {
		if strings.Contains(diagnostic, marker) {
			return true
		}
	}
	return false
}

func isDiscoveryGoBuildInfrastructureFailure(diagnostic string) bool {
	diagnostic = strings.ToLower(diagnostic)
	// "unexpected EOF" is also the Go assembler's deterministic diagnostic
	// for a truncated source file. Do not retain that source failure as a
	// transient network retry merely because proxies use the same phrase.
	if strings.Contains(diagnostic, "unexpected eof") &&
		strings.Contains(diagnostic, ".s:") &&
		strings.Contains(diagnostic, "asm: assembly of") {
		return false
	}
	for _, marker := range []string{
		"captured output exceeds",
		"does not match go tool version",
		"context deadline exceeded",
		"i/o timeout",
		"tls handshake timeout",
		"temporary failure",
		"no such host",
		"connection refused",
		"connection reset",
		"connection closed by",
		"could not read from remote repository",
		"network is unreachable",
		"proxyconnect",
		"unexpected eof",
		"bad gateway",
		"service unavailable",
		"too many requests",
		"gateway timeout",
		"no space left on device",
		"signal: killed",
	} {
		if strings.Contains(diagnostic, marker) {
			return true
		}
	}
	return false
}

func isDiscoveryInfrastructureFailure(err error) bool {
	return err != nil && (errors.Is(err, errDiscoveryCommandOutputExceeded) ||
		isDiscoveryGoBuildInfrastructureFailure(err.Error()))
}

func runDiscoveryAsmDecl(ctx context.Context, dir string, env []string, target string, buildTags, patterns []string) error {
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok || goos == "" || goarch == "" {
		return fmt.Errorf("invalid discovery target %q", target)
	}
	args := []string{"vet", "-asmdecl"}
	if len(buildTags) != 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	args = append(args, patterns...)
	targetEnv := replaceEnv(env, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        goos,
		"GOARCH":      goarch,
	})
	_, err := runCapturedCommandOutput(ctx, dir, targetEnv, "go", args...)
	if err == nil {
		return nil
	}
	if isDiscoveryInfrastructureFailure(err) {
		return err
	}
	if ctx.Err() != nil {
		return err
	}
	if isDiscoveryAsmDeclABIMismatch(err.Error()) {
		return err
	}
	// go vet type-checks package tests before running asmdecl. Old modules can
	// have tests that no longer compile even though their production package
	// builds; retry against temporary module copies with only *_test.go files
	// emptied so unrelated diagnostics cannot hide an assembly ABI mismatch.
	// Go forbids overlays beneath GOMODCACHE, hence the explicit module copies.
	retryErr := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, dir, targetEnv, args, buildTags, patterns)
	if ctxErr := ctx.Err(); ctxErr != nil {
		if retryErr != nil {
			return retryErr
		}
		return fmt.Errorf("go vet -asmdecl: %w", ctxErr)
	}
	if retryErr != nil && isDiscoveryAsmDeclABIMismatch(retryErr.Error()) {
		return retryErr
	}
	if isDiscoveryInfrastructureFailure(retryErr) {
		return retryErr
	}
	return nil
}

type discoveryGoListPackage struct {
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
	Module       *struct {
		Path  string
		Dir   string
		GoMod string
	}
}

func runDiscoveryAsmDeclWithTestlessModuleCopies(ctx context.Context, dir string, env, vetArgs, buildTags, patterns []string) error {
	listArgs := []string{"list", "-json"}
	if len(buildTags) != 0 {
		listArgs = append(listArgs, "-tags="+strings.Join(buildTags, ","))
	}
	listArgs = append(listArgs, patterns...)
	output, err := runCapturedCommandOutput(ctx, dir, env, "go", listArgs...)
	if err != nil {
		return err
	}

	goModPath := filepath.Join(dir, "go.mod")
	goModData, err := os.ReadFile(goModPath)
	if err != nil {
		return err
	}
	parsedGoMod, err := modfile.Parse(goModPath, goModData, nil)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	packages := make([]discoveryGoListPackage, 0)
	for {
		var pkg discoveryGoListPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		packages = append(packages, pkg)
	}

	stages := make(map[string]string)
	hasTests := false
	for _, pkg := range packages {
		if len(pkg.TestGoFiles)+len(pkg.XTestGoFiles) == 0 {
			continue
		}
		hasTests = true
		if pkg.Module == nil || pkg.Module.Path == "" || pkg.Module.Dir == "" {
			return fmt.Errorf("cannot create testless asmdecl copy for package %s without module metadata", pkg.Dir)
		}
		stage := stages[pkg.Module.Dir]
		if stage == "" {
			stage, err = os.MkdirTemp("", "plan9asm-vet-module-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(stage)
			if err := copyDiscoveryModuleTree(pkg.Module.Dir, stage); err != nil {
				return err
			}
			stagedGoMod := filepath.Join(stage, "go.mod")
			if _, err := os.Stat(stagedGoMod); os.IsNotExist(err) {
				moduleGoMod, readErr := os.ReadFile(pkg.Module.GoMod)
				if readErr != nil {
					return readErr
				}
				if err := os.WriteFile(stagedGoMod, moduleGoMod, 0644); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if err := parsedGoMod.AddReplace(pkg.Module.Path, "", stage, ""); err != nil {
				return err
			}
			stages[pkg.Module.Dir] = stage
		}
		for _, fileName := range append(append([]string(nil), pkg.TestGoFiles...), pkg.XTestGoFiles...) {
			sourcePath := filepath.Join(pkg.Dir, fileName)
			relativePath, err := filepath.Rel(pkg.Module.Dir, sourcePath)
			if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
				return fmt.Errorf("test file %s is outside module %s", sourcePath, pkg.Module.Dir)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, parser.PackageClauseOnly)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(stage, relativePath), []byte("package "+parsed.Name.Name+"\n"), 0644); err != nil {
				return err
			}
		}
	}
	if !hasTests {
		return nil
	}
	formattedGoMod, err := parsedGoMod.Format()
	if err != nil {
		return err
	}
	modfilePath := filepath.Join(dir, ".plan9asm-vet.mod")
	if err := os.WriteFile(modfilePath, formattedGoMod, 0644); err != nil {
		return err
	}
	args := append([]string{"vet", "-modfile=" + modfilePath}, vetArgs[1:]...)
	_, err = runCapturedCommandOutput(ctx, dir, env, "go", args...)
	return err
}

func copyDiscoveryModuleTree(source, destination string) error {
	return filepath.Walk(source, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(source, sourcePath)
		if err != nil {
			return err
		}
		destinationPath := filepath.Join(destination, relativePath)
		if info.IsDir() {
			return os.MkdirAll(destinationPath, info.Mode().Perm()|0700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular module file %s", sourcePath)
		}
		contents, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		return os.WriteFile(destinationPath, contents, info.Mode().Perm()|0600)
	})
}

func isDiscoveryAsmDeclABIMismatch(diagnostic string) bool {
	diagnostic = strings.ToLower(diagnostic)
	if strings.Contains(diagnostic, "wrong argument size") || strings.Contains(diagnostic, "invalid offset") {
		return true
	}
	// asmdecl reports an invalid load/store width against an FP operand when
	// the declared Go parameter or result has a different ABI width. Keep the
	// FP requirement so generic assembler, dependency, and source diagnostics
	// continue into translation instead of being hidden as not applicable.
	return strings.Contains(diagnostic, ": invalid ") && strings.Contains(diagnostic, "(fp)")
}

func discoveryAsmDeclRejectedFiles(asmFiles []string, diagnostic string) []string {
	diagnostic = filepath.ToSlash(diagnostic)
	var rejected []string
	for _, asmFile := range asmFiles {
		asmFile = filepath.ToSlash(asmFile)
		if strings.Contains(diagnostic, asmFile+":") || strings.Contains(diagnostic, "/"+asmFile+":") {
			rejected = append(rejected, asmFile)
			continue
		}
		// The Go command sometimes shortens diagnostics to a package-local
		// basename. Only use that fallback when it identifies this file.
		if strings.Contains(diagnostic, path.Base(asmFile)+":") {
			rejected = append(rejected, asmFile)
		}
	}
	return uniqueSortedDiscoveryStrings(rejected)
}

func subtractDiscoveryStrings(values, removed []string) []string {
	removeSet := make(map[string]bool, len(removed))
	for _, value := range removed {
		removeSet[value] = true
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !removeSet[value] {
			out = append(out, value)
		}
	}
	return out
}

func limitDiscoveryEvidence(message string, maxBytes int) string {
	message = strings.TrimSpace(message)
	if maxBytes <= 0 || len(message) <= maxBytes {
		return message
	}
	return message[:maxBytes] + "\n... evidence truncated ..."
}

func collectMatrixNotApplicableItems(report matrixReport) []matrixTargetNotApplicableItem {
	var items []matrixTargetNotApplicableItem
	for _, target := range report.Targets {
		targetName := target.Goos + "/" + target.Goarch
		for _, item := range target.NotApplicableItems {
			items = append(items, matrixTargetNotApplicableItem{Target: targetName, targetNotApplicableItem: item})
		}
	}
	return items
}

func sortedDiscoverySet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func runCapturedCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	_, err := runCapturedCommandOutput(ctx, dir, env, name, args...)
	return err
}

const discoveryCommandOutputLimit = 8 << 20

var errDiscoveryCommandOutputExceeded = errors.New("captured output exceeds limit")

// Candidate tools can emit arbitrarily large diagnostics. Bound the capture
// while still draining both pipes so the child cannot block on a full pipe.
// A truncated command is an explicit failure, never a successful inspection.
type boundedDiscoveryCommandOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (output *boundedDiscoveryCommandOutput) Len() int {
	return output.buffer.Len()
}

func (output *boundedDiscoveryCommandOutput) Bytes() []byte {
	return output.buffer.Bytes()
}

func (output *boundedDiscoveryCommandOutput) String() string {
	return output.buffer.String()
}

func (output *boundedDiscoveryCommandOutput) Write(data []byte) (int, error) {
	length := len(data)
	available := discoveryCommandOutputLimit - output.Len()
	if length > available {
		output.truncated = true
		data = data[:available]
	}
	if _, err := output.buffer.Write(data); err != nil {
		return 0, err
	}
	return length, nil
}

func runCapturedCommandOutput(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var output boundedDiscoveryCommandOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(append([]string{name}, args...), " "), ctx.Err())
	}
	message := strings.TrimSpace(output.String())
	if len(message) > 64<<10 {
		message = "... output truncated ...\n" + message[len(message)-(64<<10):]
	}
	if output.truncated {
		return nil, fmt.Errorf("%s: %w %d bytes (command error: %v)\n%s",
			strings.Join(append([]string{name}, args...), " "),
			errDiscoveryCommandOutputExceeded,
			discoveryCommandOutputLimit,
			err,
			message,
		)
	}
	if err == nil {
		return output.Bytes(), nil
	}
	if message == "" {
		return nil, fmt.Errorf("%s: %w", strings.Join(append([]string{name}, args...), " "), err)
	}
	return output.Bytes(), fmt.Errorf("%s: %w\n%s", strings.Join(append([]string{name}, args...), " "), err, message)
}

func replaceEnv(base []string, replacements map[string]string) []string {
	out := make([]string, 0, len(base)+len(replacements))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok {
			if _, replace := replacements[key]; replace {
				continue
			}
		}
		out = append(out, item)
	}
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+replacements[key])
	}
	return out
}

func validateDiscoveryReport(targets []string, candidate discoveryCandidate, report matrixReport) error {
	if report.TotalTargets != len(targets) || len(report.Targets) != len(targets) {
		return fmt.Errorf("%s: target coverage changed: got total=%d reports=%d, want %d", candidate.exactKey(), report.TotalTargets, len(report.Targets), len(targets))
	}
	seen := make(map[string]bool, len(targets))
	totalAsm := 0
	totalSuccess := 0
	totalNotApplicable := 0
	for _, actual := range report.Targets {
		target := actual.Goos + "/" + actual.Goarch
		if seen[target] {
			return fmt.Errorf("%s: duplicate target report %s", candidate.exactKey(), target)
		}
		seen[target] = true
		if actual.Failed != 0 || actual.Success+actual.NotApplicable != actual.TotalAsm {
			return fmt.Errorf("%s: %s failed: success=%d not_applicable=%d failed=%d total=%d", candidate.exactKey(), target, actual.Success, actual.NotApplicable, actual.Failed, actual.TotalAsm)
		}
		if err := validateTargetNotApplicableEvidence(actual); err != nil {
			return fmt.Errorf("%s: %s: %w", candidate.exactKey(), target, err)
		}
		totalAsm += actual.TotalAsm
		totalSuccess += actual.Success
		totalNotApplicable += actual.NotApplicable
	}
	for _, target := range targets {
		if !seen[target] {
			return fmt.Errorf("%s: target %s was silently skipped", candidate.exactKey(), target)
		}
	}
	if totalAsm == 0 {
		return fmt.Errorf("%s: no assembly entered translation on the target matrix", candidate.exactKey())
	}
	observed := make(map[string]bool)
	for _, target := range report.Targets {
		for _, actualPath := range target.AsmFiles {
			actualPath = filepath.ToSlash(actualPath)
			for _, expectedPath := range candidate.AsmFiles {
				if actualPath == expectedPath || strings.HasSuffix(actualPath, "/"+expectedPath) {
					observed[expectedPath] = true
				}
			}
		}
	}
	var missing []string
	for _, expectedPath := range candidate.AsmFiles {
		if !observed[expectedPath] {
			missing = append(missing, expectedPath)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("%s: %d supported assembly files were not exercised: %v", candidate.exactKey(), len(missing), missing)
	}
	if report.TotalAsm != totalAsm || report.Success != totalSuccess || report.NotApplicable != totalNotApplicable || report.Failed != 0 || report.Success+report.NotApplicable != report.TotalAsm {
		return fmt.Errorf("%s: inconsistent matrix totals: success=%d not_applicable=%d failed=%d total=%d", candidate.exactKey(), report.Success, report.NotApplicable, report.Failed, report.TotalAsm)
	}
	return nil
}

func validateTargetNotApplicableEvidence(report targetReport) error {
	if report.NotApplicable != len(report.NotApplicableItems) {
		return fmt.Errorf("not-applicable accounting mismatch: count=%d items=%d", report.NotApplicable, len(report.NotApplicableItems))
	}
	asmFiles := make(map[string]bool, len(report.AsmFiles))
	for _, asmFile := range report.AsmFiles {
		asmFiles[asmFile] = true
	}
	for _, item := range report.NotApplicableItems {
		if item.Kind != targetNotApplicableGoTextArgSize || item.PkgPath == "" || item.AsmFile == "" || !asmFiles[item.AsmFile] || item.Symbol == "" || item.DeclaredArgSize == item.ExpectedArgSize || item.Reason == "" {
			return fmt.Errorf("invalid not-applicable evidence for %q: kind=%q symbol=%q declared=%d expected=%d", item.AsmFile, item.Kind, item.Symbol, item.DeclaredArgSize, item.ExpectedArgSize)
		}
	}
	return nil
}

func writeDiscoveryCorpusReport(reportPath string, report discoveryCorpusReport) error {
	if reportPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode discovery corpus report: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(reportPath), 0755); err != nil {
		return fmt.Errorf("create discovery report directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(reportPath), ".discovery-report-*")
	if err != nil {
		return fmt.Errorf("create temporary discovery report: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write discovery corpus report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close discovery corpus report: %w", err)
	}
	discoveryReportMu.Lock()
	err = publishDiscoveryReport(file.Name(), reportPath)
	discoveryReportMu.Unlock()
	if err != nil {
		return fmt.Errorf("publish discovery corpus report: %w", err)
	}
	return nil
}
