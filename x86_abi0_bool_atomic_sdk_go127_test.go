//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86ABI0BoolUnsafeImporter struct{}

func (x86ABI0BoolUnsafeImporter) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	return nil, fmt.Errorf("unexpected actual declaration fixture import %q", path)
}

// Complete untouched Go files supply actual types without executing cmd/go or
// manufacturing an SDK source/object observation token. This is pure source/
// declaration/IR evidence; actual selected graph/native observations are separate.
func x86ABI0BoolActualAtomicPackage(t *testing.T, path, arch string, files []string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(path), name))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual Go declaration source %s/%s bytes=%d sha256=%x", path, name, len(data), sha256.Sum256(data))
		file, err := parser.ParseFile(fset, name, data, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	config := types.Config{Importer: x86ABI0BoolUnsafeImporter{}, Sizes: types.SizesFor("gc", arch)}
	pkg, err := config.Check(path, fset, syntax, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: path, Types: pkg, Syntax: syntax}
}

func TestX86ABI0Mode32CanonicalBoolActualAtomicCompleteSourceNextContext(t *testing.T) {
	for _, row := range []struct {
		path, member, boundary string
		declarations           []string
		texts                  int
	}{
		{"internal/runtime/atomic", "atomic_386.s", "tail callee needs its independent CALL contract", []string{"stubs.go", "atomic_386.go", "unaligned.go"}, 42},
		{"sync/atomic", "asm.s", "tail target lacks its independent exact canonical declaration/transport", []string{"doc.go", "doc_32.go"}, 36},
	} {
		t.Run(row.path, func(t *testing.T) {
			pkg := x86ABI0BoolActualAtomicPackage(t, row.path, "386", row.declarations)
			source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(row.path), row.member))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("complete original assembly %s/%s bytes=%d sha256=%x", row.path, row.member, len(source), sha256.Sum256(source))
			file, err := ParseWithDefines(ArchAMD64, string(source), GoAssemblerDefines("linux", "386"))
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Funcs) != row.texts || len(file.Data) != 0 || len(file.Globl) != 0 {
				t.Fatal("complete actual assembly inventory changed", len(file.Funcs), len(file.Data), len(file.Globl))
			}
			resolve := testResolveSym(row.path)
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row.path == "internal/runtime/atomic" {
				if !x86ABI0NoArgumentVoidCallRole(sigs[resolve("·panicUnaligned")]) {
					t.Fatal("actual Go void declaration acquired a bool-return/outgoing contract")
				}
				// Complete typed-tail preparation proves Cas's own LOCK/CAS
				// predicate before aliases can forward it. Cas64's alignment
				// failure CALL still needs its independent whole-callee contract.
				if plan, err := prepareX86ABI0BoolCalls(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}); plan != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.boundary) {
					t.Fatal("complete original aliases borrowed an unclosed callee body", err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					published := false
					var err error
					if api == "text" {
						var ir string
						ir, err = Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
						published = ir != ""
					} else if api == "module" {
						var module llvm.Module
						module, err = TranslateModuleInContext(ctx, file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
						published = !module.IsNil()
						if published {
							defer module.Dispose()
						}
					} else {
						module, failure := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{GOARCH: "386", GOOS: "linux", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve})
						err = failure
						published = module != nil
						if module != nil && !module.Module.IsNil() {
							defer module.Module.Dispose()
						}
					}
					if published || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.boundary) {
						t.Fatal("complete source changed its genuine next unsupported contract", published, err)
					}
					t.Log("complete original source still Context, not SDK/object/runtime success:", err)
				})
			}
		})
	}
}

// These are the three complete original integer/pointer-CAS functions, not a
// claim that the entire atomic member has been translated.
func TestX86AMD64CanonicalBoolActualAtomicCasObjects(t *testing.T) {
	const path = "internal/runtime/atomic"
	pkg := x86ABI0BoolActualAtomicPackage(t, path, "amd64", []string{"stubs.go", "atomic_amd64.go", "unaligned.go"})
	original, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(path), "atomic_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(original), "TEXT ·Cas(SB)")
	end := strings.Index(string(original), "TEXT ·Casint32(SB)")
	if start < 0 || end <= start {
		t.Fatal("original integer-CAS function boundaries changed")
	}
	source := []byte("#include \"textflag.h\"\n" + string(original[start:end]))
	t.Logf("untouched integer-CAS source bytes=%d sha256=%x original-member=%x", len(source), sha256.Sum256(source), sha256.Sum256(original))
	file, err := ParseWithDefines(ArchAMD64, string(source), GoAssemblerDefines("linux", "amd64"))
	if err != nil || len(file.Funcs) != 3 || file.Funcs[0].Sym != "·Cas" || file.Funcs[1].Sym != "·Cas64" || file.Funcs[2].Sym != "·Casp1" {
		t.Fatal("complete original integer-CAS inventory changed", err)
	}
	resolve := testResolveSym(path)
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, string(source))
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var ir string
					var err error
					options := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						module, failure := TranslateModuleInContext(ctx, file, options)
						err = failure
						if !module.IsNil() {
							ir = module.String()
							module.Dispose()
						}
					case "Go":
						module, failure := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
							GOARCH: "amd64", GOOS: "linux", TargetTriple: triple, ResolveSym: resolve,
						})
						err = failure
						if module != nil && !module.Module.IsNil() {
							ir = module.Module.String()
							module.Module.Dispose()
						}
					}
					if err != nil || ir == "" {
						t.Fatal("original integer-CAS canonical result rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				})
			}
		})
	}
}
