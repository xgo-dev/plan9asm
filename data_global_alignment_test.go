package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Independent Go linker limits, not inferred from the implementation helper.
var dataGlobalAlignmentTargets = []struct {
	arch                    Arch
	goarch, goos, directory string
	triple                  string
	maximum                 int
}{
	{ArchAMD64, "386", "linux", "x86", "i386-unknown-linux-gnu", 32},
	{ArchAMD64, "amd64", "linux", "amd64", "x86_64-unknown-linux-gnu", 32},
	{ArchARM, "arm", "linux", "arm", "armv7-unknown-linux-gnueabihf", 8},
	{ArchARM64, "arm64", "linux", "arm64", "aarch64-unknown-linux-gnu", 32},
	{ArchWASM, "wasm", "js", "wasm", "wasm32-unknown-unknown", 32},
}

// Values immediately on either side of every alignment transition, including
// the odd/nonmultiple sizes for which the old divisibility heuristic fails.
var dataGlobalAlignmentSizes = []struct{ size, alignment int }{
	{1, 1}, {2, 2}, {3, 2}, {4, 4}, {5, 4}, {7, 4},
	{8, 8}, {9, 8}, {15, 8}, {16, 16}, {17, 16}, {23, 16},
	{24, 16}, {31, 16}, {32, 32}, {33, 32}, {63, 32}, {64, 32},
	{65, 32}, {127, 32}, {128, 32}, {129, 32}, {255, 32}, {256, 32}, {257, 32},
}

func dataGlobalAlignmentSource() string {
	var source strings.Builder
	for _, row := range dataGlobalAlignmentSizes {
		for _, role := range []string{"rw", "ro", "local"} {
			name, flags := fmt.Sprintf("asm_align_%s_n%d", role, row.size), 16
			if role == "ro" {
				flags |= 8
			} else if role == "local" {
				name += "<>"
			}
			fmt.Fprintf(&source, "DATA %s(SB)/1,$0xa5\nGLOBL %s(SB),%d,$%d\n", name, name, flags, row.size)
		}
	}
	return source.String()
}

func dataGlobalAlignmentResolve(name string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, "·"), "<>")
}

func TestDataGlobalAlignmentBothEmitters(t *testing.T) {
	for _, target := range dataGlobalAlignmentTargets {
		for _, route := range []string{"text", "direct"} {
			t.Run(target.goarch+"/"+route, func(t *testing.T) {
				file, err := Parse(target.arch, dataGlobalAlignmentSource())
				if err != nil {
					t.Fatal(err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				var module llvm.Module
				if route == "text" {
					var output strings.Builder
					err = emitDataGlobals(&output, file, dataGlobalAlignmentResolve)
					if err == nil {
						module, err = parseIRModuleInContext(ctx, output.String())
					}
				} else {
					module = ctx.NewModule("assembly-data")
					err = emitDataGlobalsModule(module, file, dataGlobalAlignmentResolve)
				}
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range dataGlobalAlignmentSizes {
					want := row.alignment
					if want > target.maximum {
						want = target.maximum
					}
					for _, role := range []string{"rw", "ro", "local"} {
						name := fmt.Sprintf("asm_align_%s_n%d", role, row.size)
						global := module.NamedGlobal(name)
						if global.IsNil() {
							t.Fatal("missing source global", name)
						}
						if global.Alignment() != want {
							t.Errorf("%s: LLVM definition alignment=%d, Go linker requires %d", name, global.Alignment(), want)
						}
					}
				}
			})
		}
	}
}

func TestDataGlobalAlignmentDoesNotChangeOtherStorageDomains(t *testing.T) {
	// Private ARM64 literal pools retain their existing separate heuristic.
	if bestAlign(17) != 1 || bestAlign(24) != 8 || bestAlign(32) != 16 {
		t.Fatal("assembly definitions changed private literal-pool alignment")
	}
	for _, target := range dataGlobalAlignmentTargets {
		for _, size := range []int64{1 << 20, 1<<20 + 1, 1<<40 + 17, 1<<63 - 1} {
			if got := goAssemblyDataAlignment(target.arch, size); got != int64(target.maximum) {
				t.Errorf("%s large size%d alignment=%d, want %d", target.goarch, size, got, target.maximum)
			}
		}
		width := 8
		if target.goarch == "386" || target.goarch == "arm" {
			width = 4
		}
		source := fmt.Sprintf("DATA holder<>(SB)/%d,$external(SB)\nGLOBL holder<>(SB),16,$17\nGLOBL empty<>(SB),16,$0\n", width)
		file, err := Parse(target.arch, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: dataGlobalAlignmentResolve})
		if err != nil {
			t.Fatal(err)
		}
		func() {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := parseIRModuleInContext(ctx, ir)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			external := module.NamedGlobal("external")
			if external.IsNil() || !external.IsDeclaration() || external.Alignment() != 0 {
				t.Fatal("undefined external acquired source-owned alignment")
			}
			if !module.NamedGlobal("empty").IsNil() {
				t.Fatal("empty definition acquired backing")
			}
		}()
	}
}

// Read the actual selected SDK's complete five-architecture min/max directory.
// Linked source fixtures below independently exercise the size-dependent rule.
func TestDataGlobalAlignmentOfficialLinkerLimits(t *testing.T) {
	root := testGOROOT(t)
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			directory := filepath.Join(root, "src", "cmd", "link", "internal", target.directory)
			constants := map[string]int{}
			if target.goarch != "wasm" {
				syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, "l.go"), nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				ast.Inspect(syntax, func(node ast.Node) bool {
					value, ok := node.(*ast.ValueSpec)
					if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
						return true
					}
					literal, ok := value.Values[0].(*ast.BasicLit)
					if ok && literal.Kind == token.INT {
						integer, err := strconv.Atoi(literal.Value)
						if err == nil {
							constants[value.Names[0].Name] = integer
						}
					}
					return true
				})
			}
			syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, "obj.go"), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			limits := map[string]int{}
			ast.Inspect(syntax, func(node ast.Node) bool {
				field, ok := node.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				key, ok := field.Key.(*ast.Ident)
				if !ok || key.Name != "Maxalign" && key.Name != "Minalign" {
					return true
				}
				if _, found := limits[key.Name]; found {
					t.Fatal("duplicate linker alignment field", key.Name)
				}
				switch value := field.Value.(type) {
				case *ast.Ident:
					limits[key.Name] = constants[value.Name]
				case *ast.BasicLit:
					limits[key.Name], err = strconv.Atoi(value.Value)
					if err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatal("unrecognized actual linker alignment expression")
				}
				return true
			})
			if limits["Maxalign"] != target.maximum || limits["Minalign"] != 1 || len(limits) != 2 {
				t.Fatalf("Go linker alignment directory changed: %+v", limits)
			}
		})
	}
}
