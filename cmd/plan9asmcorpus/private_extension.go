package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"golang.org/x/mod/module"
)

// A private-extension skip excludes one exact assembly file on one target.
// Other files and targets still go through translation and object compilation.
type discoveryPrivateExtensionSkip struct {
	Module       string   `json:"module"`
	Version      string   `json:"version"`
	AsmFile      string   `json:"asm_file"`
	Target       string   `json:"target"`
	SourceSHA256 string   `json:"source_sha256"`
	Opcode       string   `json:"opcode"`
	Reason       string   `json:"reason"`
	EvidenceURLs []string `json:"evidence_urls"`
}

type discoveryPrivateExtensionManifest struct {
	SchemaVersion int                             `json:"schema_version"`
	Skips         []discoveryPrivateExtensionSkip `json:"skips"`
}

func loadPrivateExtensionSkips(repoRoot, ledgerPath string) (map[string]discoveryPrivateExtensionSkip, error) {
	name := filepath.Join(repoRoot, "testdata", "corpus", "private-extensions.json")
	data, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest discoveryPrivateExtensionManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode private-extension manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported private-extension manifest schema %d", manifest.SchemaVersion)
	}
	candidates, err := loadDiscoveryCandidates(ledgerPath)
	if err != nil {
		return nil, err
	}
	known := make(map[string]discoveryCandidate, len(candidates))
	for _, candidate := range candidates {
		known[candidate.exactKey()] = candidate
	}
	skips := make(map[string]discoveryPrivateExtensionSkip, len(manifest.Skips))
	for _, skip := range manifest.Skips {
		key := skip.Module + "@" + skip.Version
		if _, duplicate := skips[key]; duplicate {
			return nil, fmt.Errorf("duplicate private-extension skip %s", key)
		}
		candidate, ok := known[key]
		if !ok || !containsDiscoveryString(candidate.AsmFiles, skip.AsmFile) {
			return nil, fmt.Errorf("%s: private-extension file %q is absent from scan ledger", key, skip.AsmFile)
		}
		if err := module.Check(skip.Module, skip.Version); err != nil {
			return nil, fmt.Errorf("%s: invalid module version: %w", key, err)
		}
		if !filepath.IsLocal(skip.AsmFile) || path.Clean(skip.AsmFile) != skip.AsmFile ||
			filepath.ToSlash(skip.AsmFile) != skip.AsmFile || !strings.HasSuffix(skip.AsmFile, ".s") {
			return nil, fmt.Errorf("%s: invalid private-extension assembly path %q", key, skip.AsmFile)
		}
		if err := validateTarget(skip.Target); err != nil {
			return nil, fmt.Errorf("%s: invalid private-extension target: %w", key, err)
		}
		if len(skip.SourceSHA256) != 64 {
			return nil, fmt.Errorf("%s: invalid private-extension source SHA-256", key)
		}
		if _, err := hex.DecodeString(skip.SourceSHA256); err != nil ||
			strings.ToLower(skip.SourceSHA256) != skip.SourceSHA256 {
			return nil, fmt.Errorf("%s: invalid private-extension source SHA-256", key)
		}
		word, err := strconv.ParseUint(skip.Opcode, 0, 32)
		if err != nil || fmt.Sprintf("0x%08x", word) != skip.Opcode {
			return nil, fmt.Errorf("%s: invalid private-extension opcode %q", key, skip.Opcode)
		}
		if strings.TrimSpace(skip.Reason) == "" || len(skip.EvidenceURLs) == 0 {
			return nil, fmt.Errorf("%s: private extension lacks reason or evidence", key)
		}
		for _, rawURL := range skip.EvidenceURLs {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return nil, fmt.Errorf("%s: invalid private-extension evidence URL %q", key, rawURL)
			}
		}
		skips[key] = skip
	}
	return skips, nil
}

func verifyPrivateExtensionSource(moduleDir string, skip discoveryPrivateExtensionSkip) error {
	if !filepath.IsLocal(skip.AsmFile) {
		return fmt.Errorf("private-extension assembly path is not local: %q", skip.AsmFile)
	}
	name := filepath.Join(moduleDir, filepath.FromSlash(skip.AsmFile))
	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read private-extension assembly %s: %w", skip.AsmFile, err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != skip.SourceSHA256 {
		return fmt.Errorf("private-extension source SHA-256 mismatch for %s: got %s", skip.AsmFile, got)
	}
	if !bytes.Contains(data, []byte("WORD $"+skip.Opcode)) {
		return fmt.Errorf("private-extension opcode %s is absent from %s", skip.Opcode, skip.AsmFile)
	}
	return nil
}

func verifyPrivateExtensionGoAssembler(
	ctx context.Context,
	workDir, moduleDir string,
	env []string,
	skip discoveryPrivateExtensionSkip,
) error {
	goos, goarch, ok := strings.Cut(skip.Target, "/")
	if !ok {
		return fmt.Errorf("invalid private-extension target %q", skip.Target)
	}
	source := filepath.Join(moduleDir, filepath.FromSlash(skip.AsmFile))
	object := filepath.Join(workDir, "private-extension-source.o")
	includeDir := filepath.Dir(source)
	goRoot, err := gotoolchain.Root()
	if err != nil {
		return err
	}
	goIncludeDir := filepath.Join(goRoot, "pkg", "include")
	targetEnv := replaceEnv(env, map[string]string{
		"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0",
	})
	err = runCapturedCommand(ctx, workDir, targetEnv, "go",
		"tool", "asm", "-I", includeDir, "-I", goIncludeDir,
		"-o", object, source)
	if err != nil {
		return fmt.Errorf(
			"current Go assembler rejects private-extension source %s on %s: %w",
			skip.AsmFile, skip.Target, err,
		)
	}
	if err := os.Remove(object); err != nil {
		return fmt.Errorf("remove private-extension proof object: %w", err)
	}
	return nil
}

func filterPrivateExtensionConfigurations(
	configs []discoveryBuildConfiguration,
	skip discoveryPrivateExtensionSkip,
) ([]discoveryBuildConfiguration, bool, error) {
	filtered := make([]discoveryBuildConfiguration, 0, len(configs)+1)
	active := false
	for _, config := range configs {
		if !containsDiscoveryString(config.Targets, skip.Target) || !containsDiscoveryString(config.AsmFiles, skip.AsmFile) {
			filtered = append(filtered, config)
			continue
		}
		if active {
			return nil, false, fmt.Errorf(
				"private-extension file %s on %s occurs in multiple build configurations",
				skip.AsmFile, skip.Target,
			)
		}
		active = true
		remainingFiles := subtractDiscoveryStrings(config.AsmFiles, []string{skip.AsmFile})
		if len(remainingFiles) != 0 {
			filtered = append(filtered, discoveryBuildConfiguration{
				BuildTags: append([]string(nil), config.BuildTags...),
				Targets:   []string{skip.Target},
				AsmFiles:  remainingFiles,
			})
		}
		remainingTargets := subtractDiscoveryStrings(config.Targets, []string{skip.Target})
		if len(remainingTargets) != 0 {
			filtered = append(filtered, discoveryBuildConfiguration{
				BuildTags: append([]string(nil), config.BuildTags...),
				Targets:   remainingTargets,
				AsmFiles:  append([]string(nil), config.AsmFiles...),
			})
		}
	}
	return filtered, active, nil
}

func privateExtensionSkipMatchesResult(skip discoveryPrivateExtensionSkip, result discoveryCorpusResult) bool {
	if skip.Module == "" || result.PrivateExtension == nil {
		return false
	}
	actual, err := json.Marshal(result.PrivateExtension)
	if err != nil {
		return false
	}
	want, err := json.Marshal(skip)
	return err == nil && bytes.Equal(actual, want)
}

func validatePrivateExtensionResult(result discoveryCorpusResult) error {
	skip := result.PrivateExtension
	if skip == nil || skip.Module != result.Module || skip.Version != result.Version ||
		result.Error != "" || !containsDiscoveryString(result.DiscoveredAsmFiles, skip.AsmFile) ||
		strings.TrimSpace(skip.Reason) == "" || skip.SourceSHA256 == "" || skip.Opcode == "" {
		return fmt.Errorf("invalid private-extension skip evidence")
	}
	expectedTranslations := 0
	for _, config := range result.BuildConfigurations {
		if containsDiscoveryString(config.Targets, skip.Target) && containsDiscoveryString(config.AsmFiles, skip.AsmFile) {
			return fmt.Errorf("private-extension file %s on %s was also claimed as translated", skip.AsmFile, skip.Target)
		}
		expectedTranslations += len(config.Targets) * len(config.AsmFiles)
	}
	if result.Translations+result.NotApplicableTranslations != expectedTranslations ||
		!equalDiscoveryStrings(result.ApplicableAsmFiles, discoveryConfigurationAsmFiles(result.BuildConfigurations)) {
		return fmt.Errorf("private-extension result does not account for every remaining applicable file and target")
	}
	return nil
}

func containsDiscoveryString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
