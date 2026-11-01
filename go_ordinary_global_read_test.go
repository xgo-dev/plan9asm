package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const ordinaryGlobalReadPackage = "example.com/ordinaryglobals"

func ordinaryGlobalReadAssembly(prefix, comparison string) []byte {
	// PEXTRD makes the ordinary result observer consume the comparison's
	// numerical input. Neither branch may be discarded from source evidence.
	return []byte("TEXT ·view(SB),4,$0-4\n" + prefix + comparison + `
	JNZ enabled
	PXOR X0,X0
	JMP done
enabled:
	MOVL $7,AX
	MOVL AX,X0
done:
	PEXTRD $0,X0,AX
	MOVL AX,ret+0(FP)
	RET
`)
}

func ordinaryGlobalReadRequest(t *testing.T, pkg GoPackage, assembly []byte, arch, triple, api string) (string, error) {
	t.Helper()
	options := GoModuleOptions{GOOS: "linux", GOARCH: arch, Sizes: types.SizesFor("gc", arch),
		TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path)}
	var translated *GoModuleTranslation
	var err error
	if api == "public" {
		translated, err = TranslateGoModule(pkg, assembly, options)
	} else {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		translated, err = translateGoModuleInContext(ctx, pkg, assembly, options)
		if translated != nil {
			defer translated.Module.Dispose()
			return translated.Module.String(), err
		}
		return "", err
	}
	if translated == nil {
		return "", err
	}
	defer translated.Module.Dispose()
	return translated.Module.String(), err
}

func TestGoModuleOrdinaryGlobalReadMutableBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				for _, initial := range []string{"false", "true"} {
					// Like math/big.hasADX, initialization calls Go code and is not
					// an assembly DATA declaration or permission to fold a value.
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage, `package ordinaryglobals
var hasADX = feature()
func feature() bool { return `+initial+` }
func view() uint32
`)
					ir, err := ordinaryGlobalReadRequest(t, pkg,
						ordinaryGlobalReadAssembly("", "CMPB ·hasADX(SB),$0\n"), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("real same-package mutable bool needs no SDK capture: initial=%s output=%t err=%v", initial, ir != "", err)
					}
					if !strings.Contains(ir, "load volatile i8, ptr @\""+ordinaryGlobalReadPackage+".hasADX\"") ||
						!strings.Contains(ir, "icmp eq i8") || !strings.Contains(ir, "br i1") {
						t.Fatalf("typed global lost its exact mutable byte read or conditional branches:\n%s", ir)
					}
					declaration := false
					for _, line := range strings.Split(ir, "\n") {
						if strings.HasPrefix(line, "@\""+ordinaryGlobalReadPackage+".hasADX\" = ") {
							declaration = strings.Contains(line, " = external global ")
						}
					}
					if !declaration {
						t.Fatalf("Go-defined storage was replaced by a local DATA/constant or lost its external declaration:\n%s", ir)
					}
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalReadDoesNotGrantOtherStorage(t *testing.T) {
	for _, row := range []struct {
		name, declaration, prefix, comparison string
	}{
		{"wider-than-bool", "var hasADX bool", "", "CMPW ·hasADX(SB),$0\n"},
		{"past-bool", "var hasADX bool", "", "CMPB ·hasADX+1(SB),$0\n"},
		{"negative-offset", "var hasADX bool", "", "CMPB ·hasADX-1(SB),$0\n"},
		{"unknown-symbol", "var hasADX bool", "", "CMPB ·unknown(SB),$0\n"},
		{"pointer-storage", "var hasADX *byte", "", "CMPB ·hasADX(SB),$0\n"},
		{"string-header", "var hasADX string", "", "CMPB ·hasADX(SB),$0\n"},
		{"slice-header", "var hasADX []byte", "", "CMPB ·hasADX(SB),$0\n"},
		{"function-value", "var hasADX func()", "", "CMPB ·hasADX(SB),$0\n"},
		{"function-symbol", "func hasADX()", "", "CMPB ·hasADX(SB),$0\n"},
		{"blank-field", "var hasADX struct { _ byte; flag bool }", "", "CMPB ·hasADX(SB),$0\n"},
		{"struct-padding", "var hasADX struct { flag bool; word uint64 }", "", "CMPB ·hasADX+1(SB),$0\n"},
		{"cross-padding", "var hasADX struct { flag bool; word uint64 }", "", "CMPW ·hasADX(SB),$0\n"},
		{"write-not-read", "var hasADX bool", "MOVB $1,·hasADX(SB)\n", "CMPB ·hasADX(SB),$0\n"},
		{"rmw-not-read", "var hasADX bool", "INCB ·hasADX(SB)\n", "CMPB ·hasADX(SB),$0\n"},
		{"address-not-pointer", "var hasADX bool", "LEAQ ·hasADX(SB),DX\nMOVB (DX),CL\n", "CMPB ·hasADX(SB),$0\n"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+row.declaration+"\nfunc view() uint32\n")
				ir, err := ordinaryGlobalReadRequest(t, pkg, ordinaryGlobalReadAssembly(row.prefix, row.comparison),
					"amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("ordinary read declaration expanded storage authority: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalReadNeedsRealDeclarations(t *testing.T) {
	for _, mutation := range []string{"missing-types", "missing-syntax", "missing-var-declaration", "different-var-type"} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(mutation+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\nvar hasADX bool\nfunc view() uint32\n")
				switch mutation {
				case "missing-types":
					pkg.Types = nil
				case "missing-syntax":
					pkg.Syntax = nil
				case "missing-var-declaration":
					pkg.Syntax = mustGoPackage(t, ordinaryGlobalReadPackage,
						"package ordinaryglobals\nfunc view() uint32\n").Syntax
				case "different-var-type":
					pkg.Syntax = mustGoPackage(t, ordinaryGlobalReadPackage,
						"package ordinaryglobals\nvar hasADX *byte\nfunc view() uint32\n").Syntax
				}
				ir, err := ordinaryGlobalReadRequest(t, pkg, ordinaryGlobalReadAssembly("", "CMPB ·hasADX(SB),$0\n"),
					"amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || err == nil {
					t.Fatalf("unmatched/absent typed source acquired a read extent: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalReadDoesNotLendToRawAPI(t *testing.T) {
	pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
		"package ordinaryglobals\nvar hasADX bool\nfunc view() uint32\n")
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPI(t,
				string(ordinaryGlobalReadAssembly("", "CMPB ·hasADX(SB),$0\n")), pkg,
				"amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("raw API borrowed a GoModule storage declaration: output=%t err=%v", ir != "", err)
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalReadKeepsLogicalNamespaceSeparate(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		for _, api := range []string{"public", "owned-context"} {
			name := "no-global-candidate"
			assembly := []byte("TEXT ·view(SB),4,$0-4\nMOVL $7,AX\nMOVL AX,ret+0(FP)\nRET\n")
			if candidate {
				name = "typed-global-candidate"
				assembly = ordinaryGlobalReadAssembly("", "CMPB ·hasADX(SB),$0\n")
			}
			t.Run(name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\nvar hasADX bool\nfunc view() uint32\n")
				pkg.Path = "main" // LLGo's linked namespace, not Types.Path().
				ir, err := ordinaryGlobalReadRequest(t, pkg, assembly, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" || !strings.Contains(ir, "@main.view(") {
					t.Fatalf("typed package ownership was confused with its linked namespace: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalReadCostQueryPreservesOtherOwners(t *testing.T) {
	for _, row := range []struct {
		name, declarations, source string
		unboundWrite               bool
	}{
		{"ordinary-write", "var cell uint64\nfunc view()",
			"TEXT ·view(SB),4,$0-0\nMOVQ $7,·cell(SB)\nRET\n", true},
		{"emitted-globl", "var cell uint64\nfunc view() uint32",
			"GLOBL ·cell(SB),8,$8\n" + string(ordinaryGlobalReadAssembly("", "CMPQ ·cell(SB),$0\n")), false},
		{"emitted-data", "var cell uint64\nfunc view() uint32",
			"DATA ·cell(SB)/8,$7\nGLOBL ·cell(SB),8,$8\n" + string(ordinaryGlobalReadAssembly("", "CMPQ ·cell(SB),$0\n")), false},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+row.declarations+"\n")
				if row.unboundWrite {
					file, err := Parse(ArchAMD64, row.source)
					if err != nil {
						t.Fatal(err)
					}
					query := pkg
					query.Syntax = nil // A noncandidate needs no new declaration audit.
					sizes := &ordinaryGlobalReadCountingSizes{Sizes: types.SizesFor("gc", "amd64")}
					binding, err := bindGoReadOnlyStorage(query, file, sizes, "amd64", testResolveSym(pkg.Path))
					if binding != nil || err != nil || sizes.visits != 0 {
						t.Fatalf("noncandidate acquired storage or inspected its layout: binding=%t visits=%d err=%v", binding != nil, sizes.visits, err)
					}
				}
				ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(row.source), "amd64", "x86_64-unknown-linux-gnu", api)
				if row.unboundWrite {
					// Native emission is not numerical-source authority. The old
					// whole-function checker must still reject this unowned SB write.
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("cost query lent authority to an unowned MOV write: output=%t err=%v", ir != "", err)
					}
					return
				}
				if err != nil || ir == "" {
					t.Fatalf("a noncandidate or existing storage owner was intercepted: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

type ordinaryGlobalReadCountingSizes struct {
	types.Sizes
	visits int
}

func (sizes *ordinaryGlobalReadCountingSizes) Sizeof(typ types.Type) int64 {
	sizes.visits++
	if sizes.visits > 256 {
		panic("test stopped an unbounded layout traversal")
	}
	return sizes.Sizes.Sizeof(typ)
}

func TestGoModuleOrdinaryGlobalReadZeroWidthLayoutIsBounded(t *testing.T) {
	// The physical object is one byte. Traversing each zero-width element
	// would take 2^40 visits; the counting Sizes stops the old implementation
	// deterministically without turning this regression into a timeout test.
	typ := types.NewStruct([]*types.Var{
		types.NewVar(0, nil, "Z", types.NewArray(types.NewArray(types.NewStruct(nil, nil), 1<<20), 1<<20)),
		types.NewVar(0, nil, "Flag", types.Typ[types.Bool]),
	}, nil)
	sizes := &ordinaryGlobalReadCountingSizes{Sizes: types.SizesFor("gc", "amd64")}
	size, spans, _, err := goReadOnlyLayout(typ, sizes)
	if err != nil || size != 1 || len(spans) != 1 || spans[0] != [2]int64{0, 1} || sizes.visits > 128 {
		t.Fatalf("zero-width repetitions were expanded: size=%d spans=%v visits=%d err=%v", size, spans, sizes.visits, err)
	}
}
