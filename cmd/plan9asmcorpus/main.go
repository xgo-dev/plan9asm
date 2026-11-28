package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type corpusManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Targets       []string          `json:"targets"`
	Libraries     []libraryManifest `json:"libraries"`
}

type libraryManifest struct {
	ID        string                       `json:"id"`
	Origin    string                       `json:"origin"`
	Issues    []string                     `json:"issues,omitempty"`
	Module    string                       `json:"module"`
	Version   string                       `json:"version"`
	Inventory map[string]expectedInventory `json:"inventory"`
}

type expectedInventory struct {
	AsmFiles int      `json:"asm_files"`
	Packages []string `json:"packages"`
}

type moduleInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

type commandInvocation struct {
	Dir  string
	Args []string
}

type matrixReport struct {
	Targets      []targetReport `json:"targets"`
	TotalTargets int            `json:"total_targets"`
	TotalAsm     int            `json:"total_asm"`
	Success      int            `json:"success"`
	Failed       int            `json:"failed"`
}

type targetReport struct {
	Goos        string   `json:"goos"`
	Goarch      string   `json:"goarch"`
	TotalPkgs   int      `json:"total_pkgs"`
	AsmPackages []string `json:"asm_packages"`
	TotalAsm    int      `json:"total_asm"`
	Success     int      `json:"success"`
	Failed      int      `json:"failed"`
}

var (
	issueURLPattern = regexp.MustCompile(`^https://github\.com/xgo-dev/llgo/issues/[1-9][0-9]*$`)
	idPattern       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

const (
	originLLGoIssue     = "llgo-issue"
	originEcosystemScan = "ecosystem-scan"
)

func main() {
	manifestPath := flag.String("manifest", "testdata/corpus/reported-libraries.json", "third-party library manifest")
	corpusDir := flag.String("corpus-dir", "testdata/corpus", "module used to resolve third-party libraries")
	repoRoot := flag.String("repo-root", ".", "plan9asm repository root")
	translator := flag.String("translator", "", "path to the plan9asmll binary")
	llc := flag.String("llc", "", "path to llc")
	suite := flag.String("suite", "all", "suite id to run, or all")
	checkLatest := flag.Bool("check-latest", true, "require each pinned module version to equal @latest")
	list := flag.Bool("list", false, "list suite ids as a JSON array and exit")
	flag.Parse()

	manifest, err := loadManifest(*manifestPath)
	check(err)
	if *list {
		ids := make([]string, 0, len(manifest.Libraries))
		for _, library := range manifest.Libraries {
			ids = append(ids, library.ID)
		}
		check(json.NewEncoder(os.Stdout).Encode(ids))
		return
	}
	if *translator == "" {
		check(errors.New("-translator is required"))
	}
	if *llc == "" {
		check(errors.New("-llc is required"))
	}

	libraries, err := selectLibraries(manifest.Libraries, *suite)
	check(err)
	for _, library := range libraries {
		check(runLibrary(manifest, library, *corpusDir, *repoRoot, *translator, *llc, *checkLatest))
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadManifest(path string) (corpusManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return corpusManifest{}, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var manifest corpusManifest
	if err := dec.Decode(&manifest); err != nil {
		return corpusManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return corpusManifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return corpusManifest{}, err
	}
	return manifest, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing manifest data: %w", err)
	}
	return errors.New("manifest contains more than one JSON value")
}

func validateManifest(manifest corpusManifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported manifest schema_version %d", manifest.SchemaVersion)
	}
	if len(manifest.Targets) == 0 {
		return errors.New("manifest has no targets")
	}
	targets := make(map[string]bool, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if err := validateTarget(target); err != nil {
			return err
		}
		if targets[target] {
			return fmt.Errorf("duplicate target %q", target)
		}
		targets[target] = true
	}
	if len(manifest.Libraries) == 0 {
		return errors.New("manifest has no libraries")
	}
	ids := make(map[string]bool, len(manifest.Libraries))
	modules := make(map[string]bool, len(manifest.Libraries))
	for _, library := range manifest.Libraries {
		if !idPattern.MatchString(library.ID) {
			return fmt.Errorf("invalid library id %q", library.ID)
		}
		if ids[library.ID] {
			return fmt.Errorf("duplicate library id %q", library.ID)
		}
		ids[library.ID] = true
		if library.Module == "" || library.Version == "" {
			return fmt.Errorf("library %q requires module and version", library.ID)
		}
		if modules[library.Module] {
			return fmt.Errorf("duplicate library module %q", library.Module)
		}
		modules[library.Module] = true
		switch library.Origin {
		case originLLGoIssue:
			if len(library.Issues) == 0 {
				return fmt.Errorf("library %q has no source issue", library.ID)
			}
		case originEcosystemScan:
			if len(library.Issues) != 0 {
				return fmt.Errorf("ecosystem-scan library %q must not claim a source issue", library.ID)
			}
		default:
			return fmt.Errorf("library %q has invalid origin %q", library.ID, library.Origin)
		}
		seenIssues := make(map[string]bool, len(library.Issues))
		for _, issue := range library.Issues {
			if !issueURLPattern.MatchString(issue) {
				return fmt.Errorf("library %q has invalid issue URL %q", library.ID, issue)
			}
			if seenIssues[issue] {
				return fmt.Errorf("library %q repeats source issue %q", library.ID, issue)
			}
			seenIssues[issue] = true
		}
		totalAsm := 0
		for target, inventory := range library.Inventory {
			if !targets[target] {
				return fmt.Errorf("library %q inventory has unknown target %q", library.ID, target)
			}
			if inventory.AsmFiles <= 0 {
				return fmt.Errorf("library %q target %q has non-positive asm_files", library.ID, target)
			}
			if len(inventory.Packages) == 0 || inventory.AsmFiles < len(inventory.Packages) {
				return fmt.Errorf("library %q target %q has inconsistent package/file inventory", library.ID, target)
			}
			if !sort.StringsAreSorted(inventory.Packages) {
				return fmt.Errorf("library %q target %q packages are not sorted", library.ID, target)
			}
			for i, pkg := range inventory.Packages {
				if pkg != library.Module && !strings.HasPrefix(pkg, library.Module+"/") {
					return fmt.Errorf("library %q target %q package %q is outside module", library.ID, target, pkg)
				}
				if i > 0 && inventory.Packages[i-1] == pkg {
					return fmt.Errorf("library %q target %q repeats package %q", library.ID, target, pkg)
				}
			}
			totalAsm += inventory.AsmFiles
		}
		if totalAsm == 0 {
			return fmt.Errorf("library %q contains no assembly on the target matrix", library.ID)
		}
	}
	return nil
}

func validateTarget(target string) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid target %q", target)
	}
	switch parts[1] {
	case "386", "amd64", "arm", "arm64", "wasm":
		return nil
	default:
		return fmt.Errorf("target %q uses unsupported Plan 9 architecture", target)
	}
}

func selectLibraries(libraries []libraryManifest, suite string) ([]libraryManifest, error) {
	if suite == "all" {
		return libraries, nil
	}
	for _, library := range libraries {
		if library.ID == suite {
			return []libraryManifest{library}, nil
		}
	}
	return nil, fmt.Errorf("unknown third-party library suite %q", suite)
}

func runLibrary(manifest corpusManifest, library libraryManifest, corpusDir, repoRoot, translator, llc string, checkLatest bool) error {
	fmt.Printf("== third-party library %s (%s@%s; %s) ==\n", library.ID, library.Module, library.Version, library.Origin)
	pinned, err := queryModule(corpusDir, library.Module)
	if err != nil {
		return fmt.Errorf("%s: resolve pinned module: %w", library.ID, err)
	}
	if pinned.Path != library.Module || pinned.Version != library.Version {
		return fmt.Errorf("%s: corpus go.mod resolves %s@%s, manifest requires %s@%s", library.ID, pinned.Path, pinned.Version, library.Module, library.Version)
	}
	if checkLatest {
		latest, err := queryModule(corpusDir, library.Module+"@latest")
		if err != nil {
			return fmt.Errorf("%s: resolve latest module: %w", library.ID, err)
		}
		if latest.Path != library.Module || latest.Version != library.Version {
			return fmt.Errorf("%s: latest version is %s@%s; update the pinned corpus and inventory from %s@%s", library.ID, latest.Path, latest.Version, library.Module, library.Version)
		}
		fmt.Printf("latest version confirmed: %s@%s\n", latest.Path, latest.Version)
	}
	if err := runCommand(corpusDir, "go", "mod", "download", library.Module+"@"+library.Version); err != nil {
		return fmt.Errorf("%s: download module: %w", library.ID, err)
	}
	tmpDir, err := os.MkdirTemp("", "plan9asm-third-party-"+library.ID+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	reportPath := filepath.Join(tmpDir, "report.json")
	outDir := filepath.Join(tmpDir, "out")
	invocation := makeTranslatorInvocation(corpusDir, library.Module, outDir, repoRoot, llc, reportPath)
	if err := runCommand(invocation.Dir, translator, invocation.Args...); err != nil {
		return fmt.Errorf("%s: translate and compile corpus: %w", library.ID, err)
	}
	report, err := loadReport(reportPath)
	if err != nil {
		return fmt.Errorf("%s: %w", library.ID, err)
	}
	if err := validateReport(manifest.Targets, library, report); err != nil {
		return err
	}
	if err := checkObjectArtifacts(outDir, report.Targets); err != nil {
		return fmt.Errorf("%s: %w", library.ID, err)
	}
	fmt.Printf("%s: all %d assembly translations passed across %d targets (LLVM objects verified)\n", library.ID, report.TotalAsm, report.TotalTargets)
	return nil
}

func makeTranslatorInvocation(corpusDir, modulePath, outDir, repoRoot, llc, reportPath string) commandInvocation {
	return commandInvocation{Dir: corpusDir, Args: []string{
		"-all-targets",
		"-patterns=" + modulePath + "/...",
		"-module-path=" + modulePath,
		"-out=" + outDir,
		"-compile",
		"-keep-obj",
		"-llc=" + llc,
		"-report=" + reportPath,
		"-repo-root=" + repoRoot,
		"-strict-load",
	}}
}

// Check each module's corresponding artifact while the isolated suite output
// exists. A successful report alone cannot prove all source files emitted IR.
func checkObjectArtifacts(outDir string, targets []targetReport) error {
	for _, target := range targets {
		dir := filepath.Join(outDir, target.Goos+"-"+target.Goarch)
		count := 0
		err := filepath.WalkDir(dir, func(path string, ent os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if ent.IsDir() || filepath.Ext(path) != ".ll" {
				return nil
			}
			obj := strings.TrimSuffix(path, ".ll") + ".o"
			info, err := os.Stat(obj)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return fmt.Errorf("empty or invalid object %s", obj)
			}
			count++
			return nil
		})
		if err != nil && !(errors.Is(err, os.ErrNotExist) && count == 0 && target.TotalAsm == 0) {
			return err
		}
		if count != target.TotalAsm {
			return fmt.Errorf("%s/%s emitted %d object files, expected %d", target.Goos, target.Goarch, count, target.TotalAsm)
		}
	}
	return nil
}

func queryModule(dir, query string) (moduleInfo, error) {
	cmd := exec.Command("go", "list", "-m", "-json", query)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return moduleInfo{}, fmt.Errorf("go list %s: %w: %s", query, err, strings.TrimSpace(stderr.String()))
	}
	var info moduleInfo
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		return moduleInfo{}, fmt.Errorf("decode go list %s: %w", query, err)
	}
	return info, nil
}

func runCommand(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadReport(path string) (matrixReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return matrixReport{}, fmt.Errorf("read report: %w", err)
	}
	var report matrixReport
	if err := json.Unmarshal(data, &report); err != nil {
		return matrixReport{}, fmt.Errorf("decode report: %w", err)
	}
	return report, nil
}

func validateReport(targets []string, library libraryManifest, report matrixReport) error {
	if report.TotalTargets != len(targets) || len(report.Targets) != len(targets) {
		return fmt.Errorf("%s: target coverage changed: got total=%d reports=%d, want %d", library.ID, report.TotalTargets, len(report.Targets), len(targets))
	}
	seen := make(map[string]bool, len(targets))
	totalAsm := 0
	totalSuccess := 0
	for _, actual := range report.Targets {
		target := actual.Goos + "/" + actual.Goarch
		if seen[target] {
			return fmt.Errorf("%s: duplicate target report %s", library.ID, target)
		}
		seen[target] = true
		expected := library.Inventory[target]
		packages := append([]string(nil), actual.AsmPackages...)
		sort.Strings(packages)
		if actual.TotalAsm != expected.AsmFiles || !equalStrings(packages, expected.Packages) {
			return fmt.Errorf("%s: %s assembly inventory changed: got files=%d packages=%v, want files=%d packages=%v", library.ID, target, actual.TotalAsm, packages, expected.AsmFiles, expected.Packages)
		}
		if actual.TotalPkgs != len(actual.AsmPackages) {
			return fmt.Errorf("%s: %s inconsistent package count: total_pkgs=%d asm_packages=%v", library.ID, target, actual.TotalPkgs, actual.AsmPackages)
		}
		if actual.Failed != 0 || actual.Success != actual.TotalAsm {
			return fmt.Errorf("%s: %s failed: success=%d failed=%d total=%d", library.ID, target, actual.Success, actual.Failed, actual.TotalAsm)
		}
		totalAsm += actual.TotalAsm
		totalSuccess += actual.Success
	}
	for _, target := range targets {
		if !seen[target] {
			return fmt.Errorf("%s: target %s was silently skipped", library.ID, target)
		}
	}
	if report.TotalAsm != totalAsm || report.Success != totalSuccess || report.Failed != 0 || report.Success != report.TotalAsm {
		return fmt.Errorf("%s: inconsistent matrix totals: success=%d failed=%d total=%d", library.ID, report.Success, report.Failed, report.TotalAsm)
	}
	return nil
}

func equalStrings(a, b []string) bool {
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
