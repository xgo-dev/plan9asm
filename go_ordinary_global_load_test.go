package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

type ordinaryGlobalLoadCase struct {
	op                       string
	readBits, writeBits      int
	signed, mode64, highByte bool
}

// Independent complete scalar MOV/extension inventory, not a production-spec
// iteration. MOVD/MOVDQ2Q are Go source aliases for the MOVQ GP grammar.
func ordinaryGlobalLoadCases(arch string) []ordinaryGlobalLoadCase {
	var result []ordinaryGlobalLoadCase
	for _, row := range []ordinaryGlobalLoadCase{
		{op: "MOVB", readBits: 8, writeBits: 8},
		{op: "MOVW", readBits: 16, writeBits: 16},
		{op: "MOVL", readBits: 32, writeBits: 32},
		{op: "MOVQ", readBits: 64, writeBits: 64, mode64: true},
		{op: "MOVD", readBits: 64, writeBits: 64, mode64: true},
		{op: "MOVDQ2Q", readBits: 64, writeBits: 64, mode64: true},
		{op: "MOVBWSX", readBits: 8, writeBits: 16, signed: true},
		{op: "MOVBWZX", readBits: 8, writeBits: 16},
		{op: "MOVBLSX", readBits: 8, writeBits: 32, signed: true},
		{op: "MOVBLZX", readBits: 8, writeBits: 32},
		{op: "MOVBQSX", readBits: 8, writeBits: 64, signed: true, mode64: true},
		{op: "MOVBQZX", readBits: 8, writeBits: 64, mode64: true},
		{op: "MOVWLSX", readBits: 16, writeBits: 32, signed: true},
		{op: "MOVWLZX", readBits: 16, writeBits: 32},
		{op: "MOVWQSX", readBits: 16, writeBits: 64, signed: true, mode64: true},
		{op: "MOVWQZX", readBits: 16, writeBits: 64, mode64: true},
		{op: "MOVLQSX", readBits: 32, writeBits: 64, signed: true, mode64: true},
		{op: "MOVLQZX", readBits: 32, writeBits: 64},
		{op: "MOVSWW", readBits: 16, writeBits: 16, signed: true},
		{op: "MOVZWW", readBits: 16, writeBits: 16},
		{op: "MOVB", readBits: 8, writeBits: 8, highByte: true},
	} {
		if arch == "386" && row.mode64 {
			continue
		}
		if arch == "386" && row.op == "MOVLQZX" {
			row.writeBits = 32
		}
		result = append(result, row)
	}
	return result
}

func ordinaryGlobalLoadSource(arch string) (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("var words [5]uint64\n")
	for index, row := range ordinaryGlobalLoadCases(arch) {
		name := fmt.Sprintf("load%d", index)
		fmt.Fprintf(&declarations, "func %s() uint64\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\n", name)
		if arch == "386" {
			source.WriteString("MOVL $0x89abcdef,AX\n")
		} else {
			source.WriteString("MOVQ $0x1234567889abcdef,AX\n")
		}
		register := "AX"
		if row.highByte {
			register = "AH"
		}
		// Deliberately unaligned and spanning adjacent array elements. The
		// declaration supplies numerical bytes, never an alignment assertion.
		fmt.Fprintf(&source, "%s ·words+1(SB),%s\n", row.op, register)
		if arch == "386" {
			source.WriteString("MOVL AX,ret+0(FP)\nMOVL $0,ret+4(FP)\nRET\n")
		} else {
			source.WriteString("MOVQ AX,ret+0(FP)\nRET\n")
		}
	}
	return source.String(), declarations.String()
}

func TestGoModuleOrdinaryGlobalLoadCompleteFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := ordinaryGlobalLoadSource(target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"public", "owned-context"} {
				t.Run(api, func(t *testing.T) {
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
					ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete typed integer loads need no SDK capture", err)
					}
					if got := strings.Count(ir, "load volatile "); got != len(ordinaryGlobalLoadCases(target.arch)) {
						t.Fatalf("lost exact mutable reads: got %d, want %d", got, len(ordinaryGlobalLoadCases(target.arch)))
					}
					for _, row := range ordinaryGlobalLoadCases(target.arch) {
						if !strings.Contains(ir, fmt.Sprintf("load volatile i%d,", row.readBits)) {
							t.Fatal("source width widened or disappeared", row.op, row.readBits)
						}
					}
					compileLLVMToObject(t, llc, target.triple, "ordinary-global-load.ll", "ordinary-global-load.o", ir)
				})
			}
		})
	}
}

func ordinaryGlobalLoadBoundarySource(body string) []byte {
	// The SIMD extraction makes the complete source observer mandatory even
	// when the attempted load's value is overwritten before the final return.
	return []byte("TEXT ·view(SB),4,$0-4\nMOVL $7,AX\n" + body +
		"\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n")
}

func TestGoModuleOrdinaryGlobalLoadRejectsOtherAuthority(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"past-object", "var words [5]uint64", "MOVQ ·words+33(SB),AX"},
		{"negative-offset", "var words [5]uint64", "MOVB ·words-1(SB),AX"},
		{"padding", "var words struct { A byte; B uint64 }", "MOVB ·words+1(SB),AX"},
		{"cross-padding", "var words struct { A byte; B uint64 }", "MOVW ·words(SB),AX"},
		{"blank-field", "var words struct { _ uint64; B uint64 }", "MOVQ ·words(SB),AX"},
		{"pointer", "var words *uint64", "MOVQ ·words(SB),AX"},
		{"pointer-array", "var words [5]*uint64", "MOVQ ·words(SB),AX"},
		{"slice", "var words []uint64", "MOVQ ·words(SB),AX"},
		{"string", "var words string", "MOVQ ·words(SB),AX"},
		{"function", "var words func()", "MOVQ ·words(SB),AX"},
		{"unknown", "var words [5]uint64", "MOVQ ·missing(SB),AX"},
		{"foreign", "var words [5]uint64", "MOVQ foreign.words(SB),AX"},
		{"write", "var words [5]uint64", "MOVQ ·words(SB),AX\nMOVQ AX,·words(SB)"},
		{"rmw", "var words [5]uint64", "MOVQ ·words(SB),AX\nINCQ ·words(SB)"},
		{"address", "var words [5]uint64", "LEAQ ·words(SB),DX\nMOVQ (DX),AX"},
		{"raw", "var words [5]uint64", "BYTE $0x48\nBYTE $0x8b\nBYTE $0x05\nLONG $0\nMOVQ ·words(SB),AX"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+row.declaration+"\nfunc view() uint32\n")
				ir, err := ordinaryGlobalReadRequest(t, pkg, ordinaryGlobalLoadBoundarySource(row.body),
					"amd64", "x86_64-unknown-linux-gnu", api)
				rejected := errors.Is(err, ErrProbeNeedsContext)
				if row.name == "raw" {
					// This is invalid literal placement, rejected by the decoder
					// before any named storage role, not missing caller context.
					rejected = err != nil && strings.Contains(err.Error(), "RIP-relative literal [7,15) is outside directive group")
				}
				if ir != "" || !rejected {
					t.Fatalf("load declaration lent other authority: output=%t err=%v", ir != "", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalLoadRetainsDeclarationAndRawAPIBoundaries(t *testing.T) {
	source, declarations := ordinaryGlobalLoadSource("amd64")
	for _, mutation := range []string{"missing-types", "missing-syntax", "changed-type", "missing-variable"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			switch mutation {
			case "missing-types":
				pkg.Types = nil
			case "missing-syntax":
				pkg.Syntax = nil
			case "changed-type":
				pkg.Syntax = mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+strings.Replace(declarations, "[5]uint64", "[5]*uint64", 1)).Syntax
			case "missing-variable":
				pkg.Syntax = mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+strings.Replace(declarations, "var words [5]uint64", "", 1)).Syntax
			}
			ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "amd64", "x86_64-unknown-linux-gnu", "public")
			if ir != "" || err == nil {
				t.Fatal("unmatched typed declarations acquired numerical storage", err)
			}
		})
	}
	pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
	for _, api := range []string{"text", "module"} {
		t.Run("raw-"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("raw API inherited GoModule global declarations", err)
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalLoadBindingRemainsLive(t *testing.T) {
	source, declarations := ordinaryGlobalLoadSource("amd64")
	for _, mutation := range []string{"source", "syntax", "resolver", "raw-read", "write-read", "grouped-source"} {
		t.Run(mutation, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			wrongResolver := false
			resolve := func(symbol string) string {
				if wrongResolver && strings.Contains(symbol, "words") {
					return "foreign.words"
				}
				return testResolveSym(pkg.Path)(symbol)
			}
			binding, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", "amd64"), "amd64", resolve)
			if err != nil || binding == nil {
				t.Fatal("complete load did not bind its real declared storage", err)
			}
			ins := file.Funcs[0].Instrs[2]
			if binding.readFor(ins, "amd64") == nil {
				t.Fatal("exact typed source read has no per-instruction fact")
			}
			switch mutation {
			case "grouped-source":
				ins.Args = append([]Operand(nil), ins.Args...)
				ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Sym: "·words(SB)", Off: 1}}
				read := binding.readFor(ins, "amd64")
				if read == nil || !reflect.DeepEqual(read.operand, ins.Args[0]) || read.width != 1 {
					t.Fatal("grouped SB source lost its exact operand/width")
				}
				return
			case "source":
				binding.file.Funcs[0].Instrs[2].Args[0].Sym = "·words+39(SB)"
			case "syntax":
				pkg.Syntax[0].Name.Name = "foreign"
			case "resolver":
				wrongResolver = true
			case "raw-read":
				ins.x86Encoded = true
				if binding.readFor(ins, "amd64") != nil {
					t.Fatal("raw instruction borrowed a named read")
				}
				return
			case "write-read":
				ins.Args[0], ins.Args[1] = ins.Args[1], ins.Args[0]
				if binding.readFor(ins, "amd64") != nil {
					t.Fatal("write borrowed a read fact")
				}
				return
			}
			if err := binding.verify(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed producer remained usable", err)
			}
		})
	}
}
