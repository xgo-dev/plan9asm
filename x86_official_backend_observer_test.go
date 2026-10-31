package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The overlay only adds an owned test. Go 1.20 needs it appended to an existing
// test file because its vet reads physical filenames. No original declaration
// is changed; all physical SDK files remain byte-identical. This observes Go's encoder;
// it grants no translator, object-decoder or native-entry permission.
func x86OriginalGoBackendOutput(t *testing.T, fixture, testRoot string) []byte {
	t.Helper()
	fixture, err := filepath.Abs(fixture)
	if err != nil || !strings.HasSuffix(fixture, "_test.go") {
		t.Fatal("invalid owned SDK backend fixture", fixture, err)
	}
	sdk := runtime.GOROOT()
	directory := filepath.Join(sdk, "src", "cmd", "internal", "obj", "x86")
	snapshot := func() map[string][32]byte {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		result := map[string][32]byte{}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				result[entry.Name()] = sha256.Sum256(data)
			}
		}
		return result
	}
	before := snapshot()
	fixtureBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	virtual := filepath.Join(directory, "plan9asm_"+filepath.Base(fixture))
	if _, err := os.Stat(virtual); !os.IsNotExist(err) {
		t.Fatal("SDK overlay must add a new test, never replace an existing file", virtual, err)
	}
	dir := t.TempDir()
	if strings.HasPrefix(runtime.Version(), "go1.20.") {
		virtual = filepath.Join(directory, "asm_test.go")
		original, err := os.ReadFile(virtual)
		if err != nil {
			t.Fatal(err)
		}
		fixture = filepath.Join(dir, "appended_test.go")
		if err := os.WriteFile(fixture, x86BackendAppendOriginalTest(t, original, fixtureBytes), 0600); err != nil {
			t.Fatal(err)
		}
		t.Log("GO120_VET_BOUNDARY default vet reads the physical original test; appended fixture compilation/execution is observed separately")
	}
	overlay := filepath.Join(dir, "overlay.json")
	data, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{virtual: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, data, 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(sdk, "bin", "go"), "test", "-p=1",
		"-overlay="+overlay, "cmd/internal/obj/x86", "-run", "^"+regexp.QuoteMeta(testRoot)+"$",
		"-count=1", "-timeout=90s", "-json")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOROOT="+sdk, "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	output, commandErr := runtimeOracleCombinedOutput(ctx, command)
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("original SDK source inventory changed during the test-only overlay")
	}
	for name, digest := range before {
		if after[name] != digest {
			t.Fatal("original SDK source bytes changed during the test-only overlay", name)
		}
	}
	if commandErr != nil || ctx.Err() != nil {
		t.Fatalf("actual Go backend source observer failed: %v / %v\n%s", commandErr, ctx.Err(), output)
	}
	t.Logf("ACTUAL_GO_BACKEND_SOURCE originalSDKGoFiles=%d fixtureSHA=%x outputSHA=%x",
		len(before), sha256.Sum256(fixtureBytes), sha256.Sum256(output))
	return output
}

// Append only owned declarations and missing imports. Keep every original
// declaration byte-identical, including tests not selected by the observer.
func x86BackendAppendOriginalTest(t *testing.T, original, fixture []byte) []byte {
	t.Helper()
	set := token.NewFileSet()
	parse := func(name string, source []byte) *ast.File {
		file, err := parser.ParseFile(set, name, source, 0)
		if err != nil || file.Name.Name != "x86" {
			t.Fatal("backend overlay requires original package x86", err)
		}
		return file
	}
	base, added := parse("original_test.go", original), parse("fixture_test.go", fixture)
	imports := map[string]string{}
	for _, item := range base.Imports {
		name := ""
		if item.Name != nil {
			name = item.Name.Name
		}
		imports[item.Path.Value] = name
	}
	var extra strings.Builder
	for _, item := range added.Imports {
		name := ""
		if item.Name != nil {
			name = item.Name.Name
		}
		if old, exists := imports[item.Path.Value]; exists {
			if old != name {
				t.Fatal("backend fixture changes an original import binding", item.Path.Value)
			}
			continue
		}
		if _, err := strconv.Unquote(item.Path.Value); err != nil {
			t.Fatal(err)
		}
		extra.WriteString("import " + name + " " + item.Path.Value + "\n")
	}
	point := set.Position(base.Name.End()).Offset
	result := append([]byte(nil), original[:point]...)
	result = append(result, []byte("\n"+extra.String())...)
	result = append(result, original[point:]...)
	originalEnd := len(result)
	for _, declaration := range added.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.IMPORT {
			continue
		}
		result = append(result, '\n')
		result = append(result, fixture[set.Position(declaration.Pos()).Offset:set.Position(declaration.End()).Offset]...)
		result = append(result, '\n')
	}
	combined := parse("combined_test.go", result)
	var originals []ast.Decl
	for _, declaration := range base.Decls {
		if group, ok := declaration.(*ast.GenDecl); !ok || group.Tok != token.IMPORT {
			originals = append(originals, declaration)
		}
	}
	index := 0
	for _, declaration := range combined.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.IMPORT {
			continue
		}
		if set.Position(declaration.End()).Offset > originalEnd {
			break
		}
		old := originals[index]
		if !bytes.Equal(original[set.Position(old.Pos()).Offset:set.Position(old.End()).Offset], result[set.Position(declaration.Pos()).Offset:set.Position(declaration.End()).Offset]) {
			t.Fatal("backend overlay changed an original declaration")
		}
		index++
	}
	if index != len(originals) {
		t.Fatal("backend overlay dropped original declarations", index, len(originals))
	}
	t.Logf("GO120_APPENDED_TEST_ORIGINAL_DECLARATIONS count=%d sourceSHA=%x overlaySHA=%x", index, sha256.Sum256(original), sha256.Sum256(result))
	return result
}
