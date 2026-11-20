package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Original Go compilation is the acceptance oracle. Additional ordinary Go
// declarations do not themselves grant caller memory or fixed-local backing.
func TestGoAMD64FrameSourceCompleteOrdinaryGoDeclarations(t *testing.T) {
	// Reuse only this root's owned compiler cache, not source identities.
	// Every case still executes actual Go and consumes its selected export.
	// Recent Go versions build objdump lazily, even for `go tool -n`.
	// Prepare only the compiler artifact before any bounded source lease;
	// each case still independently discovers and verifies the actual tool.
	goAMD64FramePrepareOwnedToolCache(t)

	for _, fixture := range []struct {
		name, imports, declarations string
	}{
		{"body", "", "func Reference(a uint64) uint64 { return a + 1 }"},
		{"values", "", "const Bias uint64 = 1\nvar Counter uint64"},
		{"unused-type", "", "type Record struct { Bytes []byte; Value uint64 }"},
		{"unused-interface", "", "type XOF interface { Read([]byte) (int, error); Clone() XOF }"},
		{"unused-function", "", "type Callback func([]byte) error"},
		{"unused-map", "", "type Cache map[string][]byte"},
		{"unused-channel", "", "type Queue chan []byte"},
		{"unused-float", "", "type Scalar float64"},
		{"unused-recursive", "", "type Node struct { Next *Node; Value uint64 }"},
		{"unused-generic", "", "type Box[T any] struct { Value T }"},
		{"unused-interface-alias", "", "type XOF = interface { Read([]byte) (int, error) }"},
		{"sdk-import", "import \"math/bits\"", "func Reference(a uint64) uint64 { return bits.RotateLeft64(a, 1) }"},
		{"unrelated-body-transport", "", "func Reference(a float64) float64 { return a + 1 }"},
		{"combined", "import \"math/bits\"", "const Bias = 1\nvar Counter uint64\nfunc Reference(a uint64) uint64 { return bits.RotateLeft64(a, Bias) }"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, request := goAMD64FrameSourceFixture(t)
			text := "package framefixture\n" + fixture.imports + "\nfunc Value(a uint64) uint64\n" + fixture.declarations + "\n"
			if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			env := append(append([]string(nil), request.Environment...),
				"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local",
				"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
			command := exec.CommandContext(ctx, request.GoBinary,
				"list", "-deps", "-export", "-compiled", "-json", "-mod=readonly", ".")
			command.Dir, command.Env = request.Directory, env
			output, diagnostics, err := runtimeOracleMachineOutput(ctx, command)
			if err != nil {
				t.Fatalf("original Go rejected complete ordinary source: %v\n%s\n%s", err, output, diagnostics)
			}
			var selected goAMD64FrameSelection
			exports := make(map[string]string)
			decoder := json.NewDecoder(bytes.NewReader(output))
			for {
				var member goAMD64FrameSelection
				if err := decoder.Decode(&member); err == io.EOF {
					break
				} else if err != nil || member.ImportPath == "" || len(member.Error)+len(member.DepsErrors) != 0 {
					t.Fatalf("original Go compiler graph is incomplete: %+v: %v", member, err)
				}
				exports[member.ImportPath] = member.Export
				if member.Module != nil && member.Module.Main {
					if selected.ImportPath != "" {
						t.Fatal("original Go selected more than one owned package")
					}
					selected = member
				}
			}
			if selected.ImportPath != "example.invalid/framefixture" || len(selected.CompiledGoFiles) != 1 || len(selected.SFiles) != 1 {
				t.Fatalf("original Go omitted the complete Go/ASM source pair: %+v", selected)
			}
			export, err := os.ReadFile(selected.Export)
			if err != nil || len(export) == 0 {
				t.Fatalf("original Go omitted compiled package/assembly export: %v", err)
			}
			t.Logf("ORIGINAL_GO_COMPLETE_FRAME_SOURCE role=%s go_sha=%x export_sha=%x", fixture.name,
				sha256.Sum256([]byte(text)), sha256.Sum256(export))
			set := token.NewFileSet()
			syntax, err := parser.ParseFile(set, filepath.Join(request.Directory, "value.go"), text, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			actualImporter := importer.ForCompiler(set, "gc", func(path string) (io.ReadCloser, error) {
				return os.Open(exports[path])
			})
			typed, err := (&types.Config{Importer: actualImporter, Sizes: types.SizesFor("gc", "amd64")}).Check(
				selected.ImportPath, set, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatalf("Go-accepted ordinary declarations lost original frame observation: %v", err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			function, found := source.functions[pkg.Path+".Value"]
			if !found || function.locals != 168 || function.args != 16 || function.transport != goAMD64FrameNumericTransport {
				t.Fatalf("complete source changed the independently captured numeric ASM frame: %+v", function)
			}
			if len(source.functions) != 1 || len(source.declarations) != 1 {
				t.Fatal("unrelated ordinary Go declarations became ASM frame capabilities")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
