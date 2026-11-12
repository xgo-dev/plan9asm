//go:build go1.27

package gotoolprofile

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

// Imported declarations must come from independently selected/exported Go
// sources. The outer observer's JSON/types are not a frame capability.
func TestAMD64DownloadedFrameOriginalImportGraphs(t *testing.T) {
	for _, variant := range []string{"import", "nested-import", "foreign", "nested-foreign"} {
		t.Run(variant, func(t *testing.T) {
			request, module, version := amd64DownloadedObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := captureAMD64DownloadedForTest(ctx, request, module, version)
			if err != nil {
				t.Fatal("actual original Go source/export control failed", err)
			}
			defer func() {
				if err := observed.Close(); err != nil {
					t.Error(err)
				}
			}()
			actual := observed.state.packages[request.PackagePath]
			set := token.NewFileSet()
			var syntax []*ast.File
			for _, name := range actual.GoFiles {
				file, err := parser.ParseFile(set, filepath.Join(request.Directory, name), nil, parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				syntax = append(syntax, file)
			}
			imports := importer.ForCompiler(set, "gc", func(path string) (io.ReadCloser, error) {
				if mapped, exists := actual.ImportMap[path]; exists {
					path = mapped
				}
				return os.Open(observed.state.packages[path].Export)
			})
			typed, err := (&types.Config{Importer: imports, Sizes: types.SizesFor("gc", "amd64")}).Check(
				request.PackagePath, set, syntax, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkg := plan9asm.GoPackage{Path: request.PackagePath, Types: typed, Syntax: syntax}
			source, err := plan9asm.CaptureGoAMD64DownloadedFrameSource(ctx, pkg, plan9asm.GoAMD64DownloadedFrameCaptureRequest{
				Original: plan9asm.GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
					Directory: request.Directory, AssemblyFile: "value_amd64.s", Target: request.Target,
					Environment: request.Environment},
				SourceModule: module, SourceVersion: version,
			})
			if err != nil {
				t.Fatal("actual original Go import graph lost independent frame capture", err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(request.Directory, "value_amd64.s"))
			if err != nil {
				t.Fatal(err)
			}
			expanded := strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := plan9asm.DeriveGoFuncABI0Signature(pkg.Path+".Value",
				typed.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := source.BindFixedLocal(ctx, pkg, file, plan9asm.Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: func(name string) string { return strings.Replace(name, "·", pkg.Path+".", 1) },
				Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig},
			})
			if err != nil {
				t.Fatal("independent imported source did not bind its actual frame", err)
			}
			fixture := amd64DownloadedLLVMFixture{request: request, pkg: pkg, file: file, options: bound, assembly: expanded}
			llc := amd64DownloadedLLVM22Tool(t, ctx, fixture, "llc")
			for _, api := range []string{"Translate", "Module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir := fixture.ir(t, api)
					for _, level := range []string{"-O0", "-O2"} {
						fixture.object(t, ctx, llc, ir, level)
					}
				})
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(variant, "foreign") {
				return
			}
			// Change bytes in a different module after successful capture. A
			// still-matching selected export or supplied type cannot hide them.
			foreign := observed.state.packages["example.invalid/foreign-observation"]
			name := filepath.Join(foreign.Dir, "shape.go")
			before, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(append([]byte(nil), before...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := source.Verify(ctx); err == nil {
				t.Fatal("changed foreign original source retained its frame observation")
			}
			if err := os.WriteFile(name, before, 0600); err != nil {
				t.Fatal(err)
			}
			if err := source.Verify(ctx); err == nil {
				t.Fatal("restored foreign bytes revived a revoked observation")
			}
		})
	}
}
