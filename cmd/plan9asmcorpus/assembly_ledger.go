package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

const assemblyLedgerFormat = "module-hashed-assembly-ledger-v1"

type assemblyLedgerShard struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

type assemblyLedgerManifest struct {
	Format               string                `json:"format"`
	SemanticSourceSHA256 string                `json:"semantic_source_sha256"`
	Progress             discoveryProgress     `json:"progress"`
	Shards               []assemblyLedgerShard `json:"shards"`
}

func validateAssemblyLedgerProgress(progress discoveryProgress) error {
	if progress.SchemaVersion != 1 || progress.ValidationKind != "translation_and_llvm22_object_compilation" {
		return fmt.Errorf("invalid assembly ledger progress schema or validation kind")
	}
	if !discoverySHA256Pattern.MatchString(progress.LedgerSHA256) {
		return fmt.Errorf("invalid assembly ledger scan fingerprint")
	}
	if !discoveryRevisionPattern.MatchString(progress.Source.Revision) ||
		!discoverySHA256Pattern.MatchString(progress.Source.SHA256) || progress.Source.Dirty {
		return fmt.Errorf("assembly ledger requires a clean, identified source")
	}
	classified := progress.Passed + progress.Failed + progress.NotApplicable +
		progress.SkippedInvalidSource + progress.SkippedSuperseded +
		progress.SkippedPrivateExtension
	if progress.CandidateTotal != len(progress.Candidates) ||
		progress.CandidateTotal != classified+progress.Pending {
		return fmt.Errorf("assembly ledger candidate counts do not balance")
	}
	if progress.Complete != (progress.ShardCount > 0 && progress.ReportedShards == progress.ShardCount && progress.Pending == 0) ||
		progress.Verified != (progress.Complete && progress.Failed == 0) {
		return fmt.Errorf("assembly ledger verified flag disagrees with candidate results")
	}
	if progress.ReportedShards > progress.ShardCount ||
		progress.ReportedShards-len(progress.PartialShards)+len(progress.PendingShards) != progress.ShardCount ||
		progress.PassedShards+progress.FailedShards+len(progress.PartialShards) != progress.ReportedShards {
		return fmt.Errorf("assembly ledger shard counts do not balance")
	}
	if classified > 0 && progress.Provenance == nil {
		return fmt.Errorf("assembly ledger outcomes lack report provenance")
	}
	if progress.Provenance != nil {
		if err := validateDiscoveryProvenance(*progress.Provenance, progress.Source, progress.LedgerSHA256); err != nil {
			return fmt.Errorf("assembly ledger outcomes: %w", err)
		}
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, candidate := range progress.Candidates {
		if candidate.Module == "" || !semver.IsValid(candidate.Version) {
			return fmt.Errorf("assembly ledger candidate has invalid module or version")
		}
		key := candidate.Module + "@" + candidate.Version
		if seen[key] {
			return fmt.Errorf("duplicate assembly ledger candidate %s", key)
		}
		seen[key] = true
		switch candidate.Status {
		case "pending", discoveryStatusPassed, discoveryStatusFailed,
			discoveryStatusNotApplicable, discoveryStatusSkippedInvalidSource,
			discoveryStatusSkippedSuperseded, discoveryStatusSkippedPrivateExtension:
			counts[candidate.Status]++
		default:
			return fmt.Errorf("assembly ledger candidate %s has invalid status %q", key, candidate.Status)
		}
		if candidate.Status == discoveryStatusSkippedInvalidSource {
			if strings.TrimSpace(candidate.InvalidSourceReason) == "" || len(candidate.InvalidSourceEvidence) == 0 {
				return fmt.Errorf("assembly ledger skip %s lacks reason or evidence", key)
			}
		} else if candidate.InvalidSourceReason != "" || len(candidate.InvalidSourceEvidence) != 0 {
			return fmt.Errorf("assembly ledger non-skip %s carries skip evidence", key)
		}
		if candidate.Status == discoveryStatusSkippedSuperseded {
			if candidate.Superseded == nil || candidate.Superseded.Module != candidate.Module || candidate.Superseded.Version != candidate.Version {
				return fmt.Errorf("assembly ledger supersession %s lacks matching evidence", key)
			}
		} else if candidate.Superseded != nil {
			return fmt.Errorf("assembly ledger non-superseded %s carries supersession", key)
		}
		if candidate.Status == discoveryStatusSkippedPrivateExtension {
			if candidate.PrivateExtension == nil || candidate.PrivateExtension.Module != candidate.Module ||
				candidate.PrivateExtension.Version != candidate.Version || candidate.PrivateExtension.Reason == "" {
				return fmt.Errorf("assembly ledger private extension %s lacks matching evidence", key)
			}
		} else if candidate.PrivateExtension != nil {
			return fmt.Errorf("assembly ledger non-private result %s carries private-extension evidence", key)
		}
	}
	if counts["pending"] != progress.Pending || counts[discoveryStatusPassed] != progress.Passed ||
		counts[discoveryStatusFailed] != progress.Failed ||
		counts[discoveryStatusNotApplicable] != progress.NotApplicable ||
		counts[discoveryStatusSkippedInvalidSource] != progress.SkippedInvalidSource ||
		counts[discoveryStatusSkippedSuperseded] != progress.SkippedSuperseded ||
		counts[discoveryStatusSkippedPrivateExtension] != progress.SkippedPrivateExtension {
		return fmt.Errorf("assembly ledger candidate statuses do not match summary")
	}
	return nil
}

func compareAssemblyLedgerCandidate(a, b discoveryCandidateProgress) int {
	if compared := strings.Compare(a.Module, b.Module); compared != 0 {
		return compared
	}
	return semver.Compare(a.Version, b.Version)
}

func validateAssemblyLedgerDestination(scanPath, outputDir string) error {
	scan, err := filepath.Abs(scanPath)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{scan, output}, {output, scan}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("assembly ledger destination overlaps scan ledger")
		}
	}
	return nil
}

// The scan ledger is an immutable test input. This separate, replaceable
// evidence snapshot is written only after the shard reports have been audited.
func writeAssemblyLedger(outputDir string, progress discoveryProgress, semanticSourceSHA string) error {
	if filepath.Base(filepath.Clean(outputDir)) != "assembly-ledger" {
		return fmt.Errorf("assembly ledger destination must be an explicit assembly-ledger directory")
	}
	if !discoverySHA256Pattern.MatchString(semanticSourceSHA) {
		return fmt.Errorf("invalid semantic source fingerprint")
	}
	if err := validateAssemblyLedgerProgress(progress); err != nil {
		return err
	}
	if info, err := os.Lstat(outputDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("assembly ledger destination is not a directory")
		}
		data, err := os.ReadFile(filepath.Join(outputDir, "manifest.json"))
		if err != nil {
			return fmt.Errorf("refuse to replace unrecognized assembly ledger: %w", err)
		}
		var existing assemblyLedgerManifest
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("refuse to replace invalid assembly ledger: %w", err)
		}
		if _, err := readAssemblyLedger(outputDir, existing.Progress.LedgerSHA256, existing.SemanticSourceSHA256); err != nil {
			return fmt.Errorf("refuse to replace invalid assembly ledger: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".assembly-ledger-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	recordsDir := filepath.Join(temporary, "records")
	if err := os.Mkdir(recordsDir, 0755); err != nil {
		return err
	}
	shards := map[byte][]discoveryCandidateProgress{}
	for _, candidate := range progress.Candidates {
		hash := sha256.Sum256([]byte(candidate.Module))
		shards[hash[0]] = append(shards[hash[0]], candidate)
	}
	manifest := assemblyLedgerManifest{
		Format:               assemblyLedgerFormat,
		SemanticSourceSHA256: semanticSourceSHA,
		Progress:             progress,
		Shards:               []assemblyLedgerShard{},
	}
	manifest.Progress.Candidates = nil
	for number := 0; number < 256; number++ {
		records := shards[byte(number)]
		if len(records) == 0 {
			continue
		}
		sort.Slice(records, func(i, j int) bool {
			return compareAssemblyLedgerCandidate(records[i], records[j]) < 0
		})
		var contents bytes.Buffer
		encoder := json.NewEncoder(&contents)
		for _, record := range records {
			if err := encoder.Encode(record); err != nil {
				return err
			}
		}
		name := fmt.Sprintf("%02x.jsonl", number)
		if err := os.WriteFile(filepath.Join(recordsDir, name), contents.Bytes(), 0644); err != nil {
			return err
		}
		checksum := sha256.Sum256(contents.Bytes())
		manifest.Shards = append(manifest.Shards, assemblyLedgerShard{
			Name: name, SHA256: fmt.Sprintf("%x", checksum), Count: len(records),
		})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	backup := temporary + ".previous"
	if _, err := os.Stat(outputDir); err == nil {
		if err := os.Rename(outputDir, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporary, outputDir); err != nil {
		if _, restoreErr := os.Stat(backup); restoreErr == nil {
			_ = os.Rename(backup, outputDir)
		}
		return err
	}
	return os.RemoveAll(backup)
}

func readAssemblyLedger(outputDir, scanSHA, semanticSourceSHA string) (discoveryProgress, error) {
	rootEntries, err := os.ReadDir(outputDir)
	if err != nil {
		return discoveryProgress{}, err
	}
	if len(rootEntries) != 2 || rootEntries[0].Name() != "manifest.json" ||
		rootEntries[1].Name() != "records" || !rootEntries[1].IsDir() {
		return discoveryProgress{}, fmt.Errorf("assembly ledger has unexpected root entries")
	}
	data, err := os.ReadFile(filepath.Join(outputDir, "manifest.json"))
	if err != nil {
		return discoveryProgress{}, err
	}
	var manifest assemblyLedgerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return discoveryProgress{}, err
	}
	if manifest.Format != assemblyLedgerFormat ||
		manifest.Progress.LedgerSHA256 != scanSHA ||
		manifest.SemanticSourceSHA256 != semanticSourceSHA {
		return discoveryProgress{}, fmt.Errorf("assembly ledger format or source/scan provenance is stale")
	}
	entries, err := os.ReadDir(filepath.Join(outputDir, "records"))
	if err != nil {
		return discoveryProgress{}, err
	}
	if len(entries) != len(manifest.Shards) {
		return discoveryProgress{}, fmt.Errorf("assembly ledger shard inventory does not match manifest")
	}
	progress := manifest.Progress
	progress.Candidates = []discoveryCandidateProgress{}
	for index, shard := range manifest.Shards {
		if len(shard.Name) != len("00.jsonl") || !strings.HasSuffix(shard.Name, ".jsonl") ||
			index >= len(entries) || entries[index].Name() != shard.Name || entries[index].IsDir() {
			return discoveryProgress{}, fmt.Errorf("invalid assembly ledger shard %q", shard.Name)
		}
		var number byte
		if _, err := fmt.Sscanf(shard.Name[:2], "%02x", &number); err != nil {
			return discoveryProgress{}, fmt.Errorf("invalid assembly ledger shard name %q", shard.Name)
		}
		contents, err := os.ReadFile(filepath.Join(outputDir, "records", shard.Name))
		if err != nil {
			return discoveryProgress{}, err
		}
		checksum := sha256.Sum256(contents)
		if fmt.Sprintf("%x", checksum) != shard.SHA256 {
			return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s checksum mismatch", shard.Name)
		}
		scanner := bufio.NewScanner(bytes.NewReader(contents))
		count := 0
		var previous discoveryCandidateProgress
		for scanner.Scan() {
			var candidate discoveryCandidateProgress
			if err := json.Unmarshal(scanner.Bytes(), &candidate); err != nil {
				return discoveryProgress{}, err
			}
			hash := sha256.Sum256([]byte(candidate.Module))
			if hash[0] != number || count > 0 && compareAssemblyLedgerCandidate(previous, candidate) >= 0 {
				return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s has wrong ownership or ordering", shard.Name)
			}
			progress.Candidates = append(progress.Candidates, candidate)
			previous = candidate
			count++
		}
		if err := scanner.Err(); err != nil {
			return discoveryProgress{}, err
		}
		if count != shard.Count {
			return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s count mismatch", shard.Name)
		}
	}
	if err := validateAssemblyLedgerProgress(progress); err != nil {
		return discoveryProgress{}, err
	}
	return progress, nil
}
