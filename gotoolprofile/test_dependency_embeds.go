package gotoolprofile

import (
	"fmt"
	"go/build"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
)

const TestEmbedProtocol = "actual_go_test_dependency_embed_selection_v1"

// Every selected package carries a witness, including packages with no
// directives. These are source inputs, never assembly/object completion.
// The producer and consumer compare Directives with actual original bytes;
// offline replay relies on their authenticated frozen-source provenance.
type EmbedSelection struct {
	Protocol   string            `json:"protocol"`
	Directives map[string]string `json:"directives"`
	Patterns   []string          `json:"patterns"`
	Files      map[string]string `json:"files"`
}

type TestEmbedSelection = EmbedSelection

// Preserve only genuine line-comment directives, not lookalikes in strings
// or block comments. Pattern syntax is subsequently parsed by stock go/build.
func TestEmbedDirectives(file string, data []byte) (string, error) {
	if len(data) > 64<<20 {
		return "", fmt.Errorf("embed directive source exceeds its byte bound")
	}
	var lexer scanner.Scanner
	fset := token.NewFileSet()
	var scanErr error
	lexer.Init(fset.AddFile(file, -1, len(data)), data, func(_ token.Position, msg string) {
		if scanErr == nil {
			scanErr = fmt.Errorf("invalid original embed directive source: %s", msg)
		}
	}, scanner.ScanComments)
	var result strings.Builder
	for {
		_, kind, text := lexer.Scan()
		if kind == token.EOF {
			break
		}
		if kind != token.COMMENT || !strings.HasPrefix(text, "//go:embed") {
			continue
		}
		remainder := strings.TrimPrefix(text, "//go:embed")
		if remainder != "" {
			separator, _ := utf8.DecodeRuneInString(remainder)
			if !unicode.IsSpace(separator) {
				continue
			}
		}
		// Retain potential directives without guessing the toolchain's
		// whitespace rules. Stock go/build below decides the actual patterns.
		result.WriteString(text)
		result.WriteByte('\n')
	}
	return result.String(), scanErr
}

type testEmbedFileInfo string

func (name testEmbedFileInfo) Name() string       { return string(name) }
func (name testEmbedFileInfo) Size() int64        { return 0 }
func (name testEmbedFileInfo) Mode() os.FileMode  { return 0600 }
func (name testEmbedFileInfo) ModTime() time.Time { return time.Time{} }
func (name testEmbedFileInfo) IsDir() bool        { return false }
func (name testEmbedFileInfo) Sys() any           { return nil }

func testEmbedPatterns(pkg PackageProof, directives, headers map[string]string) ([]string, error) {
	ctx := build.Default
	ctx.JoinPath = path.Join
	ctx.UseAllFiles, ctx.CgoEnabled = true, false
	ctx.ReadDir = func(string) ([]fs.FileInfo, error) {
		var files []fs.FileInfo
		for _, file := range pkg.GoFiles {
			files = append(files, testEmbedFileInfo(path.Base(file)))
		}
		return files, nil
	}
	ctx.OpenFile = func(filename string) (io.ReadCloser, error) {
		file := path.Join(path.Dir(pkg.GoFiles[0]), path.Base(filename))
		header, present := headers[file]
		if !present {
			return nil, fmt.Errorf("embed source lacks its original selection/import header")
		}
		return io.NopCloser(strings.NewReader(header + directives[file] + "var _ string\n")), nil
	}
	selected, err := ctx.ImportDir(".", build.IgnoreVendor)
	if err != nil {
		return nil, fmt.Errorf("parse original embed directive grammar: %w", err)
	}
	patterns := append(append([]string(nil), selected.EmbedPatterns...), selected.TestEmbedPatterns...)
	sort.Strings(patterns)
	result := patterns[:0]
	for _, pattern := range patterns {
		if len(result) == 0 || pattern != result[len(result)-1] {
			result = append(result, pattern)
		}
	}
	return result, nil
}

func testEmbedBadName(name string) bool {
	return module.CheckFilePath(name) != nil || name == ".git" || name == ".hg" || name == ".svn" || name == ".bzr"
}

// Resolve stock-Go patterns over complete original directories. A missing
// subtree is unknown, not an empty match. Nested modules are explicit stops.
func resolveTestEmbedFiles(dir string, patterns []string, directories map[string][]string, sources map[string]string) (map[string]string, map[string]bool, error) {
	files, related := make(map[string]string), make(map[string]bool)
	entries := make(map[string]bool)
	var collect func(string) error
	collect = func(current string) error {
		if len(related) >= 4096 || len(entries) > 65536 {
			return fmt.Errorf("embed inventory exceeds its directory/member bound")
		}
		members, present := directories[current]
		if !present || members == nil {
			return fmt.Errorf("embed directory has incomplete original membership: %s", current)
		}
		related[current] = true
		for index, member := range members {
			if !testSourceLocalPath(member) || path.Base(member) != member || index > 0 && member <= members[index-1] {
				return fmt.Errorf("embed inventory contains noncanonical original membership")
			}
			name := path.Join(current, member)
			if testEmbedBadName(member) {
				continue
			}
			if len(entries) >= 65536 {
				return fmt.Errorf("embed inventory exceeds its member bound")
			}
			entries[name] = true
			if digest := sources[name]; digest != "" {
				if !discoverySHA256Pattern.MatchString(digest) || directories[name] != nil {
					return fmt.Errorf("embed inventory has conflicting original file/directory roles")
				}
			} else {
				if err := collect(name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if len(patterns) == 0 {
		return files, related, nil
	}
	if err := collect(dir); err != nil {
		return nil, nil, err
	}
	var descend func(string, bool) int
	descend = func(current string, all bool) int {
		count := 0
		for _, member := range directories[current] {
			if testEmbedBadName(member) || !all && (strings.HasPrefix(member, ".") || strings.HasPrefix(member, "_")) {
				continue
			}
			name := path.Join(current, member)
			if digest := sources[name]; digest != "" {
				files[name], count = digest, count+1
			} else if sources[path.Join(name, "go.mod")] == "" {
				count += descend(name, all)
			}
		}
		return count
	}
	checks := 0
	for _, pattern := range patterns {
		glob, all := pattern, false
		if strings.HasPrefix(glob, "all:") {
			glob, all = strings.TrimPrefix(glob, "all:"), true
		}
		if _, err := path.Match(glob, ""); err != nil || glob == "." || !fs.ValidPath(glob) {
			return nil, nil, fmt.Errorf("invalid embed pattern syntax")
		}
		count := 0
		for name := range entries {
			checks++
			if checks > 4<<20 {
				return nil, nil, fmt.Errorf("embed pattern replay exceeds its explicit matching-work bound")
			}
			rel := strings.TrimPrefix(name, dir+"/")
			if dir == "." {
				rel = name
			}
			matched, err := path.Match(glob, rel)
			if err != nil || !matched {
				continue
			}
			for ancestor := name; ancestor != dir; ancestor = path.Dir(ancestor) {
				if sources[path.Join(ancestor, "go.mod")] != "" {
					return nil, nil, fmt.Errorf("embed match crosses an original nested module")
				}
			}
			if digest := sources[name]; digest != "" {
				files[name], count = digest, count+1
				continue
			}
			matchedCount := descend(name, all)
			if matchedCount == 0 {
				return nil, nil, fmt.Errorf("embed directory contains no embeddable files")
			}
			count += matchedCount
		}
		if count == 0 {
			return nil, nil, fmt.Errorf("embed pattern has no original matching files")
		}
	}
	return files, related, nil
}

func ValidateTestEmbedSelection(pkg PackageProof, proof *TestEmbedSelection, view *ConsumerInput) (map[string]bool, error) {
	if view == nil || proof == nil || proof.Protocol != TestEmbedProtocol || proof.Directives == nil || proof.Files == nil ||
		len(proof.Directives) != len(pkg.GoFiles) || len(pkg.GoFiles) == 0 || len(proof.Files) > 65536 || len(proof.Patterns) > 65536 {
		return nil, fmt.Errorf("missing bounded actual test dependency embed source role")
	}
	for _, file := range pkg.GoFiles {
		directives, present := proof.Directives[file]
		if !present || len(directives) > 4<<20 || pkg.SourceSHA256[file] == "" {
			return nil, fmt.Errorf("embed directive is not bound to every selected original Go file")
		}
		parsed, err := TestEmbedDirectives(file, []byte(directives))
		if err != nil || parsed != directives {
			return nil, fmt.Errorf("noncanonical original embed directive witness")
		}
	}
	patterns, err := testEmbedPatterns(pkg, proof.Directives, view.Headers)
	if err != nil {
		return nil, err
	}
	if !equalDiscoveryStrings(patterns, proof.Patterns) {
		return nil, fmt.Errorf("actual embed patterns contradict original Go directives")
	}
	files, related, err := resolveTestEmbedFiles(path.Dir(pkg.GoFiles[0]), patterns, view.Directories, view.Sources)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(files, proof.Files) {
		return nil, fmt.Errorf("actual embedded file selection contradicts original membership/bytes")
	}
	return related, nil
}

// Caller authorization is still required: root and every view source/member
// must already be authenticated from the actual module ZIP or observed GOROOT.
// This additionally binds compact directives to their actual full-file bytes.
func VerifyTestEmbedDirectives(pkg PackageProof, proof *TestEmbedSelection, root string) error {
	for _, file := range pkg.GoFiles {
		filename, err := CPPRegularSource(root, file)
		if err != nil {
			return err
		}
		info, err := os.Stat(filename)
		if err != nil || info.Size() > 64<<20 {
			return fmt.Errorf("original embed source exceeds its byte bound")
		}
		data, err := os.ReadFile(filename)
		if err != nil || bytesSHA256(data) != pkg.SourceSHA256[file] {
			return fmt.Errorf("original embed directive source changed")
		}
		actual, err := TestEmbedDirectives(file, data)
		if err != nil || proof == nil || actual != proof.Directives[file] {
			return fmt.Errorf("recorded embed directives are not original source bytes")
		}
	}
	return nil
}

// Actual files/patterns come from the same driver load as PackageProof. This
// capture does not authenticate a root: callers must independently bind its
// complete original inventory/ZIP (or observed standard-library tool root).
func CaptureTestEmbedSelection(pkg PackageProof, root string, patterns, files []string) (*TestEmbedSelection, error) {
	if len(patterns) > 65536 || len(files) > 65536 || len(pkg.GoFiles) == 0 || len(pkg.GoFiles) > 32768 {
		return nil, fmt.Errorf("actual embed selection exceeds its source/pattern/file bound")
	}
	proof := &TestEmbedSelection{
		Protocol: TestEmbedProtocol, Directives: make(map[string]string), Files: make(map[string]string),
		Patterns: append([]string(nil), patterns...),
	}
	sort.Strings(proof.Patterns)
	for index, pattern := range proof.Patterns {
		if index > 0 && pattern == proof.Patterns[index-1] {
			return nil, fmt.Errorf("actual embed selection repeats a pattern")
		}
	}
	for _, file := range pkg.GoFiles {
		filename, err := CPPRegularSource(root, file)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(filename)
		if err != nil || info.Size() > 64<<20 {
			return nil, fmt.Errorf("actual embed Go source exceeds its byte bound")
		}
		data, err := os.ReadFile(filename)
		if err != nil || bytesSHA256(data) != pkg.SourceSHA256[file] {
			return nil, fmt.Errorf("actual embed source differs from selected Go bytes")
		}
		proof.Directives[file], err = TestEmbedDirectives(file, data)
		if err != nil || len(proof.Directives[file]) > 4<<20 {
			if err == nil {
				err = fmt.Errorf("actual embed directives exceed their byte bound")
			}
			return nil, err
		}
	}
	for _, file := range files {
		filename := file
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(root, filepath.FromSlash(file))
		}
		filename, err := sourcepath.Resolve(filename)
		if err != nil {
			return nil, fmt.Errorf("actual embed file has no canonical original source: %w", err)
		}
		name, err := filepath.Rel(root, filename)
		name = filepath.ToSlash(name)
		if err != nil || !testSourceLocalPath(name) || proof.Files[name] != "" {
			return nil, fmt.Errorf("actual embed file has a different/duplicate original root role: package=%s", pkg.PackagePath)
		}
		filename, err = CPPRegularSource(root, name)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(filename)
		if err != nil || info.Size() > 64<<20 {
			return nil, fmt.Errorf("actual embed file exceeds its byte bound")
		}
		proof.Files[name], err = FileSHA256(filename)
		if err != nil {
			return nil, err
		}
	}
	return proof, nil
}
