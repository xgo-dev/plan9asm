package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent of the production descriptor: these are the six real opcodes
// and Go's MOVOA spelling of MOVO, for both yxmov directions.
var x86LegacyMoveNativeOracle = []struct {
	name, native string
	aligned      bool
}{
	{"MOVOU", "movdqu", false},
	{"MOVOA", "movdqa", true},
	{"MOVO", "movdqa", true},
	{"MOVUPS", "movups", false},
	{"MOVAPS", "movaps", true},
	{"MOVUPD", "movupd", false},
	{"MOVAPD", "movapd", true},
}

func TestX86LegacyMoveNativeAddressForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		source.WriteString("GLOBL ·data(SB),8,$64\n")
		declarations.WriteString("var data [64]byte\n")
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86LegacyMoveNativeOracle {
			for index, address := range []string{"(AX)", "16(AX)(CX*2)", "·data+16(SB)", "(FS)", "(GS)"} {
				name := fmt.Sprintf("%s%d", strings.ToLower(row.name), index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s index+%d(FP),CX\n%s %s,X1\n%s X1,%s\nRET\n",
					name, word*2, move, move, word, row.name, address, row.name, address)
				fmt.Fprintf(&declarations, "func %s(p *byte,index uintptr)\n", name)
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range x86LegacyMoveNativeOracle {
					for _, segment := range []string{"fs", "gs"} {
						for _, operands := range []string{"%" + segment + ":($1), $0", "$0, %" + segment + ":($1)"} {
							if !strings.Contains(ir, "asm sideeffect \""+row.native+" "+operands+"\"") {
								t.Errorf("lost original %s native segment/direction: %s", row.name, operands)
							}
						}
					}
				}
				compileLLVMToObject(t, llc, target.triple, "legacy-addresses.ll", "legacy-addresses.o", ir)
			})
		}
	}
}

func TestX86LegacyMoveNativeUnboundAddressFailsBeforeEmission(t *testing.T) {
	for _, row := range x86LegacyMoveNativeOracle {
		for _, operands := range []string{"(AX),X0", "X0,(AX)"} {
			original := x86YMMReadSource(t, row.name+" "+operands)
			for _, bits := range []int{32, 64} {
				for _, unbound := range []bool{false, true} {
					ins := original
					ins.x86AddressBits, ins.x86UnboundAddressOverride = bits, unbound
					var output strings.Builder
					ctx := &amd64Ctx{goarch: "amd64", b: &output}
					known, term, err := ctx.lowerLegacyPackedMove(ins.Op, ins)
					if !known || term || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 || ctx.tmp != 0 {
						t.Fatalf("unbound native address emitted partial IR: %s %d %t: %v", ins.Raw, bits, unbound, err)
					}
				}
			}
		}
	}
}

func TestX86LegacyMoveNativeOwnISA(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86LegacyMoveNativeOracle {
			for _, operands := range []string{"(AX),X0", "X0,(AX)"} {
				ins := x86YMMReadSource(t, row.name+" "+operands)
				want := "+sse2"
				if row.name == "MOVUPS" || row.name == "MOVAPS" {
					want = "+sse"
				}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); got != want {
					t.Errorf("%s %s: source ISA=%q want=%q", arch, ins.Raw, got, want)
				}
			}
		}
	}
}

func x86LegacyMoveNativeSource(arch, name, op string, store, dead bool) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	source := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n%s p+0(FP),AX\n%s out+%d(FP),BX\nSTC\n", name, word*2, move, move, word)
	if store {
		source += "MOVOU (BX),X1\n" + op + " X1,(AX)\n"
	} else {
		source += op + " (AX),X1\n"
		if !dead {
			source += "MOVOU X1,(BX)\n"
		}
	}
	return source + "SETCS 16(BX)\nRET\n"
}

func TestX86LegacyMoveNativeThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86LegacyMoveNativeOracle {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				var source, declarations strings.Builder
				for index, store := range []bool{false, true} {
					name := fmt.Sprintf("view%d", index)
					source.WriteString(x86LegacyMoveNativeSource(target.arch, "·"+name, row.name, store, false))
					fmt.Fprintf(&declarations, "func %s(p, out *byte)\n", name)
				}
				goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						for _, instruction := range []string{row.native + " ($1), $0", row.native + " $0, ($1)"} {
							if !strings.Contains(ir, "asm sideeffect \""+instruction+"\"") {
								t.Errorf("missing original observable native instruction %q", instruction)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "legacy-native.ll", "legacy-native.o", ir)
					})
				}
			})
		}
	}
}
