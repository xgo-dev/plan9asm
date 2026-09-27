package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type discoverySourceIdentity struct {
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
	Dirty    bool   `json:"dirty"`
}

// Keep this value comparable: every shard must describe the same inputs,
// including the actual translator binary, not merely the same candidate set.
type discoveryCorpusProvenance struct {
	Source             discoverySourceIdentity `json:"source"`
	LedgerSHA256       string                  `json:"ledger_sha256"`
	TranslatorSHA256   string                  `json:"translator_sha256"`
	TranslatorRevision string                  `json:"translator_revision"`
	TranslatorModified bool                    `json:"translator_modified"`
	TranslatorGo       string                  `json:"translator_go_version"`
	GoVersion          string                  `json:"go_version"`
	LLVMVersion        string                  `json:"llvm_version"`
	LLCBinarySHA256    string                  `json:"llc_binary_sha256"`
	Invalidated        string                  `json:"invalidated,omitempty"`
}

var (
	discoverySHA256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	discoveryRevisionPattern     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	discoveryGoVersionPattern    = regexp.MustCompile(`^go1\.27(?:\.[0-9]+)?$`)
	discoveryLLVMVersionPattern  = regexp.MustCompile(`(?m)\bLLVM version (22\.[0-9]+\.[0-9]+)(?:\s|$)`)
	discoveryLLVMIdentityPattern = regexp.MustCompile(`^22\.[0-9]+\.[0-9]+$`)
)

func discoveryGit(root string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read discovery source identity: git %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func collectDiscoverySource(root string) (discoverySourceIdentity, error) {
	var identity discoverySourceIdentity
	prefix, err := discoveryGit(root, "rev-parse", "--show-prefix")
	if err != nil {
		return identity, err
	}
	if strings.TrimSpace(prefix) != "" {
		return identity, fmt.Errorf("discovery provenance requires the repository root")
	}
	revision, err := discoveryGit(root, "rev-parse", "HEAD")
	if err != nil {
		return identity, err
	}
	identity.Revision = strings.TrimSpace(revision)
	listing, err := discoveryGit(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return identity, err
	}
	var files []string
	for _, name := range strings.Split(listing, "\x00") {
		if name != "" && !isAssemblyEvidence(name) {
			files = append(files, name)
		}
	}
	identity.SHA256, err = discoveryFilesFingerprint(root, files)
	if err != nil {
		return identity, err
	}
	state, err := discoveryGit(
		root, "status", "--porcelain", "--untracked-files=normal", "--",
		".", ":(exclude)testdata/discovery/assembly-ledger",
	)
	identity.Dirty = state != ""
	return identity, err
}

// Evidence updates do not change the translator or its test inputs. Both
// corpus report and persisted ledger source fingerprints exclude only this
// derived output; source files, the scan ledger and the Git revision remain
// bound to each report.
func isAssemblyEvidence(name string) bool {
	return strings.HasPrefix(name, "testdata/discovery/assembly-ledger/")
}

func collectDiscoverySemanticSourceSHA(root string) (string, error) {
	listing, err := discoveryGit(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return "", err
	}
	var files []string
	for _, name := range strings.Split(listing, "\x00") {
		if name != "" && !isAssemblyEvidence(name) {
			files = append(files, name)
		}
	}
	return discoveryFilesFingerprint(root, files)
}

func discoveryFilesFingerprint(root string, files []string) (string, error) {
	files = append([]string(nil), files...)
	sort.Strings(files)
	h := sha256.New()
	previous := ""
	for _, name := range files {
		if name == previous {
			continue
		}
		previous = name
		path := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		// Hash link text, never read an untracked link's external target.
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(h, "link:%d:%s:%d:%s", len(name), name, len(link), link)
			continue
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("non-regular provenance input %s", name)
		}
		fmt.Fprintf(h, "file:%d:%s:%d:", len(name), name, info.Size())
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		n, readErr := io.Copy(h, file)
		closeErr := file.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if n != info.Size() {
			return "", fmt.Errorf("provenance input changed while reading %s", name)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func discoveryLedgerFingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return discoveryFilesFingerprint(filepath.Dir(path), []string{filepath.Base(path)})
	}
	files, err := filepath.Glob(filepath.Join(path, "records", "*.jsonl"))
	if err != nil {
		return "", err
	}
	manifest := filepath.Join(path, "manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		files = append(files, manifest)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var relative []string
	for _, file := range files {
		name, err := filepath.Rel(path, file)
		if err != nil {
			return "", err
		}
		relative = append(relative, filepath.ToSlash(name))
	}
	if len(relative) == 0 {
		return "", fmt.Errorf("empty discovery ledger fingerprint")
	}
	return discoveryFilesFingerprint(path, relative)
}

func discoveryBinaryFingerprint(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func collectDiscoveryProvenance(cfg discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
	var p discoveryCorpusProvenance
	var err error
	p.Source, err = collectDiscoverySource(cfg.RepoRoot)
	if err != nil {
		return p, err
	}
	p.LedgerSHA256, err = discoveryLedgerFingerprint(cfg.LedgerPath)
	if err != nil {
		return p, err
	}
	p.TranslatorSHA256, err = discoveryBinaryFingerprint(cfg.Translator)
	if err != nil {
		return p, err
	}
	info, err := buildinfo.ReadFile(cfg.Translator)
	if err != nil {
		return p, fmt.Errorf("read translator build provenance: %w", err)
	}
	if info.Path != "github.com/xgo-dev/plan9asm/cmd/plan9asmll" {
		return p, fmt.Errorf("unexpected translator build path %q", info.Path)
	}
	p.TranslatorGo = info.GoVersion
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			p.TranslatorRevision = setting.Value
		case "vcs.modified":
			p.TranslatorModified = setting.Value == "true"
		}
	}
	if p.TranslatorRevision != p.Source.Revision || p.TranslatorModified != p.Source.Dirty {
		return p, fmt.Errorf("translator build does not match source revision/dirty state; rebuild plan9asmll with VCS metadata")
	}
	p.GoVersion, err = readDiscoveryGoVersion()
	if err != nil {
		return p, err
	}
	if !discoveryGoVersionPattern.MatchString(p.GoVersion) || p.TranslatorGo != p.GoVersion {
		return p, fmt.Errorf("discovery requires matching Go 1.27 tools, got go=%q translator=%q", p.GoVersion, p.TranslatorGo)
	}
	output, err := exec.Command(cfg.LLC, "--version").CombinedOutput()
	if err != nil {
		return p, fmt.Errorf("read LLVM toolchain provenance: %w: %s", err, output)
	}
	version := discoveryLLVMVersionPattern.FindSubmatch(output)
	if len(version) != 2 {
		return p, fmt.Errorf("discovery requires LLVM 22, got %q", strings.TrimSpace(string(output)))
	}
	p.LLVMVersion = string(version[1])
	llcPath, err := exec.LookPath(cfg.LLC)
	if err != nil {
		return p, err
	}
	p.LLCBinarySHA256, err = discoveryBinaryFingerprint(llcPath)
	if err != nil {
		return p, err
	}
	return p, nil
}

// Candidate builds intentionally disable toolchain auto-switching. Provenance
// must inspect that same local go command, or an auto-switched parent can claim
// a newer version while every candidate runs an older compiler from PATH.
func readDiscoveryGoVersion() (string, error) {
	cmd := exec.Command("go", "env", "GOVERSION")
	cmd.Env = replaceEnv(os.Environ(), map[string]string{"GOTOOLCHAIN": "local"})
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read Go toolchain provenance (local): %w: %s", err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func validateDiscoveryProvenance(p discoveryCorpusProvenance, source discoverySourceIdentity, ledgerSHA string) error {
	if !discoveryRevisionPattern.MatchString(p.Source.Revision) || !discoverySHA256Pattern.MatchString(p.Source.SHA256) ||
		!discoverySHA256Pattern.MatchString(p.LedgerSHA256) || !discoverySHA256Pattern.MatchString(p.TranslatorSHA256) ||
		!discoverySHA256Pattern.MatchString(p.LLCBinarySHA256) ||
		p.TranslatorRevision != p.Source.Revision || !discoveryGoVersionPattern.MatchString(p.GoVersion) ||
		p.TranslatorGo != p.GoVersion || !discoveryLLVMIdentityPattern.MatchString(p.LLVMVersion) {
		return fmt.Errorf("missing or invalid discovery source/toolchain provenance")
	}
	if p.Source.Dirty || p.TranslatorModified || p.Invalidated != "" {
		return fmt.Errorf("diagnostic-only discovery provenance: dirty or changed inputs cannot prove a frozen run")
	}
	// GitHub tests pull requests at a synthetic merge revision. Its tree may
	// be byte-for-byte identical to the branch head even though the revision
	// differs. Bind acceptance to the complete tracked-file fingerprint; the
	// translator must still identify the exact revision recorded by the run.
	if source.Dirty || p.Source.SHA256 != source.SHA256 || p.LedgerSHA256 != ledgerSHA {
		return fmt.Errorf("discovery provenance does not match current source and ledger")
	}
	return nil
}
