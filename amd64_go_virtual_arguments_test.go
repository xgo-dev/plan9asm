package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const amd64VirtualArgumentsPackage = "example.com/virtualargs"

const amd64VirtualArgumentsDeclarations = `package virtualargs
func CompareSlices(a, b []byte) int
func CompareStrings(a, b string) int
`

// Two independent public declarations share the complete private continuation.
// The fixture observes numerical lengths only: pointer identity transport must
// not be mistaken for permission to dereference, cast or expose those pointers.
const amd64VirtualArgumentsSource = `
TEXT ·CompareSlices<ABIInternal>(SB),4,$0-56
	MOVQ SI, DX
	MOVQ AX, SI
	JMP compareLengths<>(SB)

TEXT ·CompareStrings<ABIInternal>(SB),4,$0-40
	MOVQ AX, SI
	MOVQ DI, DX
	MOVQ CX, DI
	JMP compareLengths<>(SB)

TEXT compareLengths<>(SB),4,$0-0
	CMPQ BX, DX
	JEQ equal
	JLT less
	MOVQ $1, AX
	RET
less:
	MOVQ $-1, AX
	RET
equal:
	XORQ AX, AX
	RET
`

func amd64VirtualArgumentsRequest(t *testing.T, pkg GoPackage, source []byte, triple, api string, preprocessed bool,
	configure func(*GoModuleOptions),
) (string, error) {
	t.Helper()
	// This helper only translates supplied declarations in the current process.
	// It captures no stock-Go SDK, compiler archive, source lease or native ABI.
	return importedGlobalReadRequest(t, pkg, source, "amd64", triple, api, preprocessed, configure)
}

func amd64VirtualArgumentsRequireContext(t *testing.T, ir string, err error) {
	t.Helper()
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("virtual language arguments granted unrelated state: output=%t err=%v", ir != "", err)
	}
}

func TestGoModuleAMD64VirtualArgumentsCompleteContinuation(t *testing.T) {
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"public", "owned-context"} {
			for _, preprocessed := range []bool{false, true} {
				for _, linkedMain := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/preprocessed=%t/main=%t", triple, api, preprocessed, linkedMain), func(t *testing.T) {
						pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, amd64VirtualArgumentsDeclarations)
						if linkedMain {
							pkg.Path = "main" // Logical linked namespace, not Types.Path().
						}
						ir, err := amd64VirtualArgumentsRequest(t, pkg, []byte(amd64VirtualArgumentsSource), triple, api, preprocessed, nil)
						if err != nil || ir == "" {
							t.Fatal("actual loaded Go declarations did not initialize their virtual ABIInternal arguments", err)
						}
						for _, fragment := range []string{
							"extractvalue { ptr, i64, i64 } %arg0, 1",
							"extractvalue { ptr, i64, i64 } %arg1, 1",
							"extractvalue { ptr, i64 } %arg0, 1",
							"extractvalue { ptr, i64 } %arg1, 1",
						} {
							if !strings.Contains(ir, fragment) {
								t.Fatal("grouped LLVM parameters did not feed the original register leaves", fragment, ir)
							}
						}
						for _, name := range []string{"CompareSlices", "CompareStrings"} {
							found := false
							for _, line := range strings.Split(ir, "\n") {
								if strings.HasPrefix(line, "define i64 ") && strings.Contains(line, pkg.Path+"."+name) {
									found = strings.Count(line, "{ ptr, i64") == 2
								}
							}
							if !found {
								t.Fatal("public grouped Go signature was flattened, renamed or omitted", name, ir)
							}
						}
						if strings.Contains(ir, " nest ") || strings.Contains(ir, " swiftself ") || strings.Contains(ir, " noalias ") {
							t.Fatal("ordinary virtual parameters acquired hidden/native alias authority", ir)
						}
					})
				}
			}
		}
	}
}

func TestGoModuleAMD64VirtualArgumentsDeclaredWidths(t *testing.T) {
	for _, row := range []struct{ name, parameters, body, extraction string }{
		{"slice-length", "a []byte", "MOVQ BX,AX", "extractvalue { ptr, i64, i64 } %arg0, 1"},
		{"slice-capacity", "a []byte", "MOVQ CX,AX", "extractvalue { ptr, i64, i64 } %arg0, 2"},
		{"second-slice-length", "a,b []byte", "MOVQ SI,AX", "extractvalue { ptr, i64, i64 } %arg1, 1"},
		{"second-slice-capacity", "a,b []byte", "MOVQ R8,AX", "extractvalue { ptr, i64, i64 } %arg1, 2"},
		{"string-length", "a string", "MOVQ BX,AX", "extractvalue { ptr, i64 } %arg0, 1"},
		{"mixed-string-byte", "a string,b byte", "MOVBQZX CL,AX", ""},
		{"mixed-string-bool", "a string,b bool", "MOVBQZX CL,AX", ""},
		{"mixed-string-float32", "a string,b float32", "MOVL X0,AX", ""},
		{"mixed-string-float64", "a string,b float64", "MOVQ X0,AX", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry("+row.parameters+") uint64\n")
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\n" + row.body + "\nRET\n")
			ir, err := amd64VirtualArgumentsRequest(t, pkg, source, "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			if err != nil || ir == "" || row.extraction != "" && !strings.Contains(ir, row.extraction) {
				t.Fatal("the original grouped parameter leaf was not transported at its own width", err, ir)
			}
		})
	}
}

func TestGoModuleAMD64VirtualArgumentsDoNotGrantOtherState(t *testing.T) {
	for _, row := range []struct{ name, parameters, body string }{
		{"unused-GP", "a string", "MOVQ R11,AX"},
		{"unused-vector", "a string", "MOVQ X0,AX"},
		{"hidden-context", "a string", "MOVQ 8(DX),AX"},
		{"stack", "a string", "MOVQ (SP),AX"},
		{"ABI0-home", "a string", "MOVQ a+0(FP),AX"},
		{"unknown-FLAGS", "a string", "SETEQ AL\nMOVBQZX AL,AX"},
		{"pointer-not-NUM", "a string", "MOVQ AX,X0\nMOVQ X0,AX"},
		{"byte-upper", "a string,b byte", "MOVQ CX,AX"},
		{"bool-upper", "a string,b bool", "MOVQ CX,AX"},
		{"float32-upper", "a string,b float32", "MOVQ X0,AX"},
		{"whole-array-spill", "a [2]uint64", "MOVQ AX,AX"},
		{"bank-overflow-spill", "a,b,c,d,e,f,g,h,i,j uint64", "MOVQ AX,AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry("+row.parameters+") uint64\n")
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\n" + row.body + "\nRET\n")
			ir, err := amd64VirtualArgumentsRequest(t, pkg, source, "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			amd64VirtualArgumentsRequireContext(t, ir, err)
		})
	}
}

func TestGoModuleAMD64VirtualArgumentsNeedActualDeclarations(t *testing.T) {
	for _, mutation := range []string{"missing-syntax", "missing-function", "wrong-parameter", "wrong-result", "other-package"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
			declarations := map[string]string{
				"missing-function": "package virtualargs\nfunc Another(a []byte) uint64\n",
				"wrong-parameter":  "package virtualargs\nfunc Entry(a uint64) uint64\n",
				"wrong-result":     "package virtualargs\nfunc Entry(a []byte) uint32\n",
				"other-package":    "package foreign\nfunc Entry(a []byte) uint64\n",
			}
			pkg.Syntax = nil
			if replacement := declarations[mutation]; replacement != "" {
				pkg.Syntax = mustGoPackage(t, amd64VirtualArgumentsPackage, replacement).Syntax
			}
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nRET\n")
			ir, err := amd64VirtualArgumentsRequest(t, pkg, source, "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			amd64VirtualArgumentsRequireContext(t, ir, err)
		})
	}
}

func TestGoModuleAMD64VirtualArgumentsCannotLendToRawAPI(t *testing.T) {
	pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
	// Raw APIs still accept their existing low-level register model. This
	// independent scalar/SIMD observation invokes its complete byte proof,
	// where a grouped shape alone cannot initialize BX as a slice length.
	source := "TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nMOVQ AX,X15\nMOVQ X15,AX\nRET\n"
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			amd64VirtualArgumentsRequireContext(t, ir, err)
		})
	}
	t.Run("returned-signatures", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		resolve := testResolveSym(pkg.Path)
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", SourcePreprocessed: true, ResolveSym: resolve,
		})
		if err != nil || translated == nil {
			t.Fatal("complete GoModule source failed before the borrowing control", err)
		}
		defer translated.Module.Dispose()
		if err := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction); err != nil {
			t.Fatal("invalid virtual argument module", err)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym: resolve, Sigs: translated.Signatures})
		amd64VirtualArgumentsRequireContext(t, ir, err)
	})
}

func TestGoModuleAMD64VirtualArgumentsRecheckCallbacks(t *testing.T) {
	for _, mutation := range []string{"control", "syntax", "source", "resolver"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nRET\n")
			called := false
			ir, err := amd64VirtualArgumentsRequest(t, pkg, source, "x86_64-unknown-linux-gnu", "owned-context", true, func(options *GoModuleOptions) {
				resolve := options.ResolveSym
				options.ResolveSym = func(symbol string) string {
					if mutation == "resolver" && called {
						return "foreign.Entry"
					}
					return resolve(symbol)
				}
				options.KeepFunc = func(_, _ string) bool {
					called = true
					if mutation == "syntax" {
						ast.Inspect(pkg.Syntax[0], func(node ast.Node) bool {
							if ident, ok := node.(*ast.Ident); ok && ident.Name == "byte" {
								ident.Name = "uint64"
							}
							return true
						})
					} else if mutation == "source" {
						source[len(source)-1] = ' '
					}
					return true // No source or public entry is filtered out.
				}
			})
			if !called {
				t.Fatal("the real source callback was not reached")
			}
			if mutation == "control" {
				if err != nil || ir == "" {
					t.Fatal("unmodified virtual argument source failed", err)
				}
			} else {
				amd64VirtualArgumentsRequireContext(t, ir, err)
			}
		})
	}
}

type amd64VirtualArgumentCountingSizes struct {
	types.Sizes
	queries int
	onQuery func()
}

func (sizes *amd64VirtualArgumentCountingSizes) Sizeof(typ types.Type) int64 {
	sizes.queries++
	if sizes.onQuery != nil {
		sizes.onQuery()
	}
	return sizes.Sizes.Sizeof(typ)
}

func (sizes *amd64VirtualArgumentCountingSizes) Alignof(typ types.Type) int64 {
	sizes.queries++
	return sizes.Sizes.Alignof(typ)
}

func (sizes *amd64VirtualArgumentCountingSizes) Offsetsof(fields []*types.Var) []int64 {
	sizes.queries++
	return sizes.Sizes.Offsetsof(fields)
}

// Internal symbol/register operations consume the private immutable plan,
// not repeated full-package declaration observations. Complete boundaries
// still query the live supplied inputs and revoke the call after a mutation.
func TestGoModuleAMD64VirtualArgumentsBoundedInternalChecks(t *testing.T) {
	for _, mutation := range []string{"control", "syntax", "source"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nRET\n")
			file, err := Parse(ArchAMD64, string(source))
			if err != nil {
				t.Fatal(err)
			}
			sizes := &amd64VirtualArgumentCountingSizes{Sizes: types.SizesFor("gc", "amd64")}
			owner, err := bindAMD64GoVirtualArguments(pkg, file, source, sha256.Sum256(source),
				GoModuleOptions{GOARCH: "amd64", Sizes: sizes}, testResolveSym(pkg.Path))
			if err != nil || owner == nil || sizes.queries == 0 {
				t.Fatal("the complete declaration boundary was not observed", err, sizes.queries)
			}
			defer func() { owner.active = false }()
			entry := owner.entries[pkg.Path+".Entry"]
			if entry == nil {
				t.Fatal("actual declaration lost its private parameter plan")
			}
			sig := entry.signature
			sig.amd64GoArguments = entry
			sizes.queries = 0
			for count := 0; count < 100; count++ {
				if owner.resolveSymbol("·Entry") != sig.Name || !entry.valid(file.Funcs[0], sig, "amd64") {
					t.Fatal("internal immutable-plan check failed", count)
				}
			}
			if sizes.queries != 0 {
				t.Fatal("internal resolution repeated whole declaration/layout observations", sizes.queries)
			}
			if mutation == "syntax" {
				pkg.Syntax[0].Name.Name = "foreign"
			} else if mutation == "source" {
				source[len(source)-1] = ' '
			}
			err = owner.verify()
			if mutation == "control" {
				if err != nil || sizes.queries == 0 {
					t.Fatal("final boundary did not recheck live declarations", err, sizes.queries)
				}
			} else {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("final boundary accepted changed inputs", err)
				}
				pkg.Syntax[0].Name.Name = "virtualargs"
				source[len(source)-1] = '\n'
				if entry.valid(file.Funcs[0], sig, "amd64") {
					t.Fatal("restoring an invalidated source revived its old call-local role")
				}
			}
		})
	}
}

func TestGoModuleAMD64VirtualArgumentsFinalLayoutCallbacks(t *testing.T) {
	for _, mutation := range []string{"syntax", "source", "imports"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
			pkg.Imports = make(map[string]*types.Package)
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nRET\n")
			file, err := Parse(ArchAMD64, string(source))
			if err != nil {
				t.Fatal(err)
			}
			sizes := &amd64VirtualArgumentCountingSizes{Sizes: types.SizesFor("gc", "amd64")}
			owner, err := bindAMD64GoVirtualArguments(pkg, file, source, sha256.Sum256(source),
				GoModuleOptions{GOARCH: "amd64", Sizes: sizes}, testResolveSym(pkg.Path))
			if err != nil || owner == nil {
				t.Fatal("complete declaration boundary failed", err)
			}
			defer func() { owner.active = false }()
			called := false
			sizes.onQuery = func() {
				sizes.onQuery = nil // Mutate in the final layout query, not during capture.
				called = true
				switch mutation {
				case "syntax":
					pkg.Syntax[0].Name.Name = "foreign"
				case "source":
					source[len(source)-1] = ' '
				case "imports":
					pkg.Imports["foreign"] = types.NewPackage("foreign", "foreign")
				}
			}
			if err := owner.verify(); !called || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a final layout callback changed supplied inputs after their last observation", called, err)
			}
		})
	}
}

func TestGoModuleAMD64VirtualArgumentsReleaseCallInputs(t *testing.T) {
	for _, api := range []string{"public", "owned-context"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\nfunc Entry(a []byte) uint64\n")
			pkg.SourceSelection = new(GoSourceSelection) // No raw caller consumes this object.
			source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\nMOVQ BX,AX\nRET\n")
			options := GoModuleOptions{GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				SourcePreprocessed: true, ResolveSym: testResolveSym(pkg.Path)}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			var translated *GoModuleTranslation
			var err error
			if api == "public" {
				translated, err = TranslateGoModule(pkg, source, options)
			} else {
				translated, err = translateGoModuleInContext(ctx, pkg, source, options)
			}
			if err != nil || translated == nil {
				t.Fatal("complete virtual argument translation failed", err)
			}
			defer translated.Module.Dispose()
			if err := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction); err != nil {
				t.Fatal("invalid returned virtual argument module", err)
			}
			sig := translated.Signatures[pkg.Path+".Entry"]
			entry := sig.amd64GoArguments
			if entry == nil || entry.virtual == nil {
				t.Fatal("returned signatures lost their closed private-role tombstone")
			}
			owner := entry.virtual
			if owner.active || !errors.Is(owner.live(), ErrProbeNeedsContext) {
				t.Fatal("returned signature retained an active call-local role")
			}
			if !reflect.DeepEqual(owner.pkg, GoPackage{}) || owner.syntax != nil || owner.imports != nil ||
				owner.input != nil || owner.file != nil || owner.entries != nil || owner.symbols != nil ||
				owner.resolve != nil || owner.sizes != nil || owner.frameSizes != nil || entry.plan != nil || entry.declaration != nil {
				t.Fatal("closed signature retained owned package/types/syntax/source/plan/callback inputs")
			}
			if len(sig.Args) != 1 || sig.Args[0] != "{ ptr, i64, i64 }" || sig.Ret != I64 || len(sig.Frame.Params) != 3 {
				t.Fatal("releasing private call inputs changed the returned public language signature", sig)
			}
			file, err := Parse(ArchAMD64, string(source))
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: options.TargetTriple,
				ResolveSym: options.ResolveSym, Sigs: translated.Signatures})
			amd64VirtualArgumentsRequireContext(t, ir, err)
		})
	}
}
