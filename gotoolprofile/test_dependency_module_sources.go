package gotoolprofile

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

const TestDependencyModuleProtocol = "actual_go_test_dependency_module_sources_v2"

const TestModuleOriginalGoModOrigin = "original_zip_go_mod"

// TestModuleSource is portable source evidence, not an authorization to load
// arbitrary paths. The producer authenticates the Go download separately;
// the consumer derives its own actual Module/Replace directory and ZIP and
// compares their bytes. Offline replay relies on that frozen-run provenance.
// Neither an export nor an external assembly file is a candidate LLVM output.
type ModuleSourceSnapshot struct {
	Protocol      string                       `json:"protocol"`
	SourceModule  string                       `json:"source_module"`
	SourceVersion string                       `json:"source_version"`
	GoVersion     string                       `json:"go_version,omitempty"`
	ModuleSum     string                       `json:"module_sum,omitempty"`
	ZipSHA256     string                       `json:"zip_sha256,omitempty"`
	GoModSum      string                       `json:"go_mod_sum,omitempty"`
	GoModSHA256   string                       `json:"go_mod_sha256,omitempty"`
	GoModOrigin   string                       `json:"go_mod_origin,omitempty"`
	ProxyGoMod    *ProxyGoModProof             `json:"proxy_go_mod,omitempty"`
	Sources       map[string]string            `json:"sources"`
	Headers       map[string]string            `json:"selection_headers"`
	Directories   map[string][]TestSourceEntry `json:"directories"`
}

// This is a source artifact, not a test-package authorization. Existing test
// and instrumentation protocols continue to bind it through their own owners.
type TestModuleSource = ModuleSourceSnapshot

type TestSourceEntry struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
}

func (source ModuleSourceSnapshot) ID() string {
	if source.SourceModule == "" {
		return "stdlib@" + source.GoVersion
	}
	return source.SourceModule + "@" + source.SourceVersion
}

func testSourceLocalPath(name string) bool {
	return name != "." && name != "" && path.Clean(name) == name &&
		!path.IsAbs(name) && !strings.HasPrefix(name, "../") && !strings.Contains(name, "\\")
}

// ValidateTestModuleSource checks the compact witness shape and complete
// directory/header membership. It does not authenticate arbitrary recorded
// headers against a ZIP: VerifyTestModuleSource performs that byte comparison.
func ValidateTestModuleSource(source TestModuleSource) error {
	if source.Protocol != TestDependencyModuleProtocol || len(source.Directories) == 0 || len(source.Directories) > 4096 ||
		len(source.Sources) == 0 || len(source.Sources) > 65536 || len(source.Headers) > 32768 {
		return fmt.Errorf("missing bounded test dependency source-root inventory")
	}
	if source.SourceModule == "" {
		if _, err := goMinor(source.GoVersion); err != nil || source.SourceVersion != "" || source.ModuleSum != "" ||
			source.ZipSHA256 != "" || source.GoModSum != "" || source.GoModSHA256 != "" ||
			source.GoModOrigin != "" || source.ProxyGoMod != nil {
			return fmt.Errorf("stdlib dependency has a different source/tool role")
		}
	} else if module.Check(source.SourceModule, source.SourceVersion) != nil || source.GoVersion != "" ||
		!testDependencyH1(source.ModuleSum) || !testDependencyH1(source.GoModSum) ||
		!discoverySHA256Pattern.MatchString(source.ZipSHA256) || !discoverySHA256Pattern.MatchString(source.GoModSHA256) {
		return fmt.Errorf("external dependency lacks exact ZIP/module/mod source identity")
	}
	if err := validateTestModuleGoModOrigin(source); err != nil {
		return err
	}
	return ValidateSourceInventory(source.Inventory())
}

// Inventory is pure file membership evidence, not a test, ordinary or compiler
// permission. Each consuming role separately authenticates its root and graph.
func (source ModuleSourceSnapshot) Inventory() SourceInventory {
	return SourceInventory{Sources: source.Sources, Headers: source.Headers, Directories: source.Directories}
}

func ValidateSourceInventory(source SourceInventory) error {
	if len(source.Directories) == 0 || len(source.Directories) > 4096 || len(source.Sources) == 0 ||
		len(source.Sources) > 65536 || len(source.Headers) > 32768 {
		return fmt.Errorf("missing bounded source-root inventory")
	}
	if source.Directories["."] == nil {
		return fmt.Errorf("test dependency omits its actual source-root directory")
	}
	used := make(map[string]string)
	entryCount := 0
	for dir, entries := range source.Directories {
		if dir != "." && !testSourceLocalPath(dir) || entries == nil || len(entries) > 65536 {
			return fmt.Errorf("unsafe or unbounded test dependency directory")
		}
		if dir != "." {
			found := false
			for _, entry := range source.Directories[path.Dir(dir)] {
				found = found || entry.Name == path.Base(dir) && entry.Kind == "directory"
			}
			if !found {
				return fmt.Errorf("test dependency omits its complete ancestor membership")
			}
		}
		for i, entry := range entries {
			entryCount++
			if entryCount > 65536 {
				return fmt.Errorf("test dependency directory inventory exceeds its total entry bound")
			}
			if !testSourceLocalPath(entry.Name) || path.Base(entry.Name) != entry.Name ||
				i > 0 && entry.Name <= entries[i-1].Name || entry.Kind != "file" && entry.Kind != "directory" {
				return fmt.Errorf("noncanonical test dependency directory entry")
			}
			if entry.Kind == "directory" {
				if entry.SHA256 != "" {
					return fmt.Errorf("directory cannot impersonate dependency source bytes")
				}
				continue
			}
			file := path.Join(dir, entry.Name)
			if !discoverySHA256Pattern.MatchString(entry.SHA256) || source.Sources[file] != entry.SHA256 {
				return fmt.Errorf("test dependency entry/source digest disagrees")
			}
			used[file] = entry.SHA256
			if path.Ext(file) == ".go" || path.Ext(file) == ".s" {
				if _, found := source.Headers[file]; !found {
					return fmt.Errorf("test dependency omits a complete directory selection header")
				}
			}
		}
	}
	if !reflect.DeepEqual(used, source.Sources) {
		return fmt.Errorf("test dependency contains unrelated/unregistered source bytes")
	}
	for file, header := range source.Headers {
		if source.Sources[file] == "" || path.Ext(file) != ".go" && path.Ext(file) != ".s" || len(header) > 4<<20 {
			return fmt.Errorf("test dependency has an unbound or oversized selection header")
		}
	}
	return nil
}

func testDependencyH1(sum string) bool {
	// A canonical h1 is 44 base64 bytes after its prefix. The decoder also
	// rejects a same-length string that is not a SHA256 checksum.
	return validProxyGoModH1(sum)
}

// TestSelectionHeader preserves Go's leading-comment/blank-line semantics
// and the original package/import spelling without storing function bodies.
func TestSelectionHeader(file string, data []byte) (string, error) {
	var header string
	switch path.Ext(file) {
	case ".go":
		syntax, err := parser.ParseFile(token.NewFileSet(), file, data, parser.ImportsOnly)
		if err != nil {
			return "", err
		}
		end := syntax.Name.End()
		for _, decl := range syntax.Decls {
			if decl.End() > end {
				end = decl.End()
			}
		}
		header = string(data[:int(end)-1]) + "\n"
	case ".s":
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		inBlock := false
		var out strings.Builder
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if !inBlock && trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") {
				break
			}
			out.WriteString(line + "\n")
			if strings.HasPrefix(trimmed, "/*") {
				inBlock = true
			}
			if inBlock && strings.Contains(trimmed, "*/") {
				inBlock = false
			}
		}
		if err := scanner.Err(); err != nil {
			return "", err
		}
		header = out.String()
	default:
		return "", fmt.Errorf("not a Go/ASM dependency selection source")
	}
	lines := strings.Split(header, "\n")
	inBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inBlock {
			if strings.Contains(trimmed, "*/") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") {
			inBlock = !strings.Contains(trimmed, "*/")
			continue
		}
		if strings.HasPrefix(trimmed, "//") && !constraint.IsGoBuild(trimmed) && !constraint.IsPlusBuild(trimmed) && !strings.HasPrefix(trimmed, "//line ") {
			lines[i] = line[:strings.Index(line, "//")] + "//"
		}
	}
	return strings.Join(lines, "\n"), nil
}

// VerifyTestModuleSource compares the independent snapshot with real bytes.
// For a module, archive must be the actual Go-downloaded original ZIP, not an
// archive assembled from the snapshot. The caller checks Module/Replace and
// actual download h1/modh1 before invoking this routine.
func VerifyTestModuleSource(ctx context.Context, source TestModuleSource, root, archive string) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("test dependency source verification requires a live context")
	}
	if err := ValidateTestModuleSource(source); err != nil {
		return err
	}
	if err := VerifySourceInventory(ctx, source.Inventory(), root); err != nil {
		return err
	}
	if source.SourceModule == "" {
		if archive != "" {
			return fmt.Errorf("stdlib source cannot acquire a module ZIP role")
		}
		return nil
	}
	return verifyTestModuleZIP(ctx, source, archive)
}

func VerifySourceInventory(ctx context.Context, source SourceInventory, root string) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("source verification requires a live context")
	}
	if err := ValidateSourceInventory(source); err != nil {
		return err
	}
	resolved, err := sourcepath.Resolve(root)
	if err != nil || !filepath.IsAbs(root) || resolved != root {
		return fmt.Errorf("test dependency source root is missing or redirected")
	}
	for dir, wanted := range source.Directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil || len(entries) != len(wanted) {
			return fmt.Errorf("test dependency directory membership changed")
		}
		for i, entry := range entries {
			if entry.Name() != wanted[i].Name || entry.IsDir() != (wanted[i].Kind == "directory") ||
				!entry.IsDir() && !entry.Type().IsRegular() {
				return fmt.Errorf("test dependency has a changed or non-regular directory member")
			}
		}
	}
	for file, wanted := range source.Sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := CPPRegularSource(root, file)
		if err != nil {
			return err
		}
		data, err := readTestDependencySource(name)
		if err != nil || bytesSHA256(data) != wanted {
			return fmt.Errorf("test dependency original source bytes changed: %s", file)
		}
		if expected, found := source.Headers[file]; found {
			header, err := TestSelectionHeader(file, data)
			if err != nil || header != expected {
				return fmt.Errorf("test dependency recorded header differs from actual source bytes: %s", file)
			}
		}
	}
	return nil
}

func readTestDependencySource(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, fmt.Errorf("test dependency source exceeds its regular-file byte bound")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<20+1))
	if err != nil || len(data) > 64<<20 {
		return nil, fmt.Errorf("test dependency source changed beyond its byte bound")
	}
	return data, nil
}

func verifyTestModuleZIP(ctx context.Context, source TestModuleSource, archive string) error {
	before, err := FileSHA256(archive)
	if err != nil || before != source.ZipSHA256 {
		return fmt.Errorf("test dependency ZIP bytes changed")
	}
	sum, err := dirhash.HashZip(archive, dirhash.Hash1)
	if err != nil || sum != source.ModuleSum {
		return fmt.Errorf("test dependency ZIP h1 differs from actual Go download")
	}
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	prefix := source.ID() + "/"
	files := make(map[string]*zip.File)
	dirs := map[string]map[string]string{".": {}}
	optionalDirs := make(map[string]bool)
	for _, member := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasPrefix(member.Name, prefix) {
			return fmt.Errorf("test dependency ZIP has a different exact module identity")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(member.Name, prefix), "/")
		if name == "" {
			continue
		}
		if !testSourceLocalPath(name) {
			return fmt.Errorf("test dependency ZIP has an unsafe member")
		}
		if member.FileInfo().IsDir() {
			if optionalDirs[name] {
				return fmt.Errorf("test dependency ZIP repeats a directory marker")
			}
			optionalDirs[name] = true
			continue
		}
		if files[name] != nil || !member.Mode().IsRegular() {
			return fmt.Errorf("test dependency ZIP repeats or redirects a source member")
		}
		files[name] = member
		kind := "file"
		for current := name; current != "."; current = path.Dir(current) {
			dir := path.Dir(current)
			if dirs[dir] == nil {
				dirs[dir] = make(map[string]string)
			}
			if prior := dirs[dir][path.Base(current)]; prior != "" && prior != kind {
				return fmt.Errorf("test dependency ZIP has a directory/file conflict")
			}
			dirs[dir][path.Base(current)] = kind
			kind = "directory"
		}
	}
	for name := range optionalDirs {
		if files[name] != nil {
			return fmt.Errorf("test dependency ZIP member has conflicting source roles")
		}
	}
	if source.GoModOrigin == ProxyGoModProtocol && (files["go.mod"] != nil || optionalDirs["go.mod"]) {
		return fmt.Errorf("authenticated proxy metadata conflicts with an original ZIP go.mod member")
	}
	for dir, entries := range source.Directories {
		seen := make(map[string]bool)
		for _, entry := range entries {
			name := path.Join(dir, entry.Name)
			if dirs[dir][entry.Name] != entry.Kind && !(entry.Kind == "directory" && optionalDirs[name]) {
				return fmt.Errorf("test dependency directory is not complete original ZIP membership")
			}
			seen[entry.Name] = true
		}
		for name := range dirs[dir] {
			if !seen[name] {
				return fmt.Errorf("test dependency omitted an original ZIP directory member")
			}
		}
	}
	for file, expected := range source.Sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		member := files[file]
		if member == nil || member.UncompressedSize64 > 64<<20 {
			return fmt.Errorf("test dependency source is absent or too large in original ZIP")
		}
		stream, err := member.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, 64<<20+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || bytesSHA256(data) != expected {
			return fmt.Errorf("test dependency selected source differs from original ZIP bytes")
		}
		if file == "go.mod" {
			modSum, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			})
			if err != nil || modSum != source.GoModSum {
				return fmt.Errorf("test dependency original go.mod differs from authenticated proxy metadata")
			}
		}
		if header, found := source.Headers[file]; found {
			actual, err := TestSelectionHeader(file, data)
			if err != nil || actual != header {
				return fmt.Errorf("test dependency recorded header is not original ZIP content")
			}
		}
	}
	after, err := FileSHA256(archive)
	if err != nil || after != before {
		return fmt.Errorf("test dependency original ZIP changed during verification")
	}
	return nil
}

func SortTestModuleSources(sources []TestModuleSource) {
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID() < sources[j].ID() })
}
