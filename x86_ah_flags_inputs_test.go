package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86AHFlagsCompleteGoFormsAndEffects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}",
		"{ALAHF, ynone, Px, opBytes{0x9f}}",
		"{ASAHF, ynone, Px, opBytes{0x9e, 00, 0x86, 0xe0, 0x50, 0x9d}}",
	} {
		if !strings.Contains(string(data), row) {
			t.Fatal("actual Go complete AH/FLAGS row changed", row)
		}
	}
	const observed = x86ByteFlagCF | x86ByteFlagPF | x86ByteFlagAF | x86ByteFlagZF | x86ByteFlagSF
	for _, arch := range []string{"386", "amd64"} {
		code := x86PackedShiftActualGoBytes(t, arch, "TEXT flags(SB),4,$0-0\nLAHF\nSAHF\nRET\n")
		if !bytes.Equal(code, []byte{0x9f, 0x9e, 0xc3}) {
			t.Fatalf("%s actual original AH/FLAGS bytes changed: %x", arch, code)
		}
		for _, op := range []string{"LAHF", "SAHF"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op)
				before := ins
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 1 || !effect.requiresResultProof || effect.dynamicMemory {
					t.Fatal("complete AH/FLAGS family lacks its typed implicit byte effect", effect, known, err)
				}
				operand := effect.operands[0]
				if operand.index != -1 || operand.operand.Kind != OpReg || operand.operand.Reg != AH ||
					operand.width != 1 || operand.read != (op == "SAHF") || operand.write != (op == "LAHF") {
					t.Fatal("implicit AH must be exactly the high byte, never AL or the full AX", operand)
				}
				if op == "LAHF" && (effect.flagsRead != observed || effect.flagsDefined != 0 || effect.flagsKilled != 0) ||
					op == "SAHF" && (effect.flagsRead != 0 || effect.flagsDefined != observed || effect.flagsKilled != observed) {
					t.Fatal("five flag transfers must not consume, create or kill OF", effect)
				}
				if !reflect.DeepEqual(ins, before) {
					t.Fatal("AH/FLAGS effect changed its original instruction")
				}
			})
		}
	}
}

func x86AHFlagsCompleteSource(arch string) (string, string) {
	smallResult, mixedResult := 8, 16
	if arch == "386" {
		smallResult, mixedResult = 4, 12
	}
	return fmt.Sprintf(`TEXT ·AHLoad(SB),4,$0-12
MOVL a+0(FP),AX
MOVL b+4(FP),BX
CMPL AX,BX
LAHF
MOVBLZX AH,AX
MOVL AX,ret+8(FP)
RET
TEXT ·AHStoreAndLoad(SB),4,$0-%d
MOVW flags+0(FP),AX
SAHF
LAHF
MOVBLZX AH,AX
MOVL AX,ret+%d(FP)
RET
TEXT ·AHPreserveOF(SB),4,$0-%d
MOVW flags+0(FP),AX
MOVL a+4(FP),BX
MOVL b+8(FP),CX
ADDL CX,BX
SAHF
SETOS DL
LAHF
MOVBLZX AH,AX
MOVBLZX DL,DX
SHLL $8,DX
ORL DX,AX
MOVL AX,ret+%d(FP)
RET
TEXT ·AHByteOnly(SB),4,$0-%d
MOVB flags+0(FP),AH
SAHF
LAHF
MOVBLZX AH,AX
MOVL AX,ret+%d(FP)
RET
`, smallResult+4, smallResult, mixedResult+4, mixedResult, smallResult+4, smallResult), `func AHLoad(a,b uint32) uint32
func AHStoreAndLoad(flags uint16) uint32
func AHPreserveOF(flags uint16,a,b uint32) uint32
func AHByteOnly(flags uint8) uint32
`
}

func TestX86AHFlagsCompleteSourceFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86AHFlagsCompleteSource(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete AH/FLAGS source lost its numerical proof", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, []string{"AHLoad", "AHStoreAndLoad", "AHPreserveOF", "AHByteOnly"})
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86AHFlagsVoidInputsCannotBorrowImplementationState(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, valid, unknown string }{
			{"all-five-flags", "MOVL $0,AX\nCMPL AX,AX\nLAHF", "LAHF"},
			{"carry-is-not-all-flags", "MOVL $0,AX\nCMPL AX,AX\nCLC\nLAHF", "CLC\nLAHF"},
			{"undefined-AF", "MOVL $0,AX\nCMPL AX,AX\nLAHF", "MOVL $0,AX\nTESTL AX,AX\nLAHF"},
			{"only-AH-is-read", "MOVB $7,AH\nSAHF\nLAHF", "MOVB $7,AL\nSAHF\nLAHF"},
			{"unknown-AH", "MOVB $7,AH\nSAHF", "SAHF"},
			{"OF-is-not-created", "MOVL $0,AX\nCMPL AX,AX\nSAHF\nSETOS AL", "MOVB $7,AH\nSAHF\nSETOS AL"},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				valid := "TEXT ·Value(SB),4,$0-0\n" + row.valid + "\nRET\n"
				unknown := "TEXT ·Value(SB),4,$0-0\n" + row.unknown + "\nRET\n"
				goAssemblerOracleOutput(t, target.arch, valid+strings.ReplaceAll(unknown, "Value", "Unknown"), "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, valid, "func Value()", target.arch, target.triple, api); err != nil || ir == "" {
						t.Fatal("independent initialized AH/FLAGS control rejected", api, err)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, unknown, "func Value()", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Error("AH/FLAGS input borrowed implementation state", api, err)
					}
				}
			})
		}
	}
}

func TestX86AHFlagsRejectsNonGoFormats(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"LAHF", "SAHF"} {
			for _, tail := range []string{" AX", " $1", ".Z", ".W"} {
				t.Run(arch+"/"+op+tail, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-0\n" + op + tail + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch], api)
						if err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal(fmt.Sprintf("malformed %s%s became a context query: %v", op, tail, err))
						}
					}
				})
			}
		}
	}
}

func TestX86AHFlagsNumericalBytesAreNotCanonicalBoolWitnesses(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("canonical AH/FLAGS objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			before := [16]uint8{2, 0, 0, 1}
			load := x86ScalarLaneInstruction(t, "LAHF")
			store := x86ScalarLaneInstruction(t, "SAHF")
			want := before
			want[0] = 0
			if after := x86RegisterCanonicalBytesAfter(load, before, target.arch); after != want {
				t.Fatal("LAHF retained canonical AH or revoked an unrelated GP byte", after)
			}
			if after := x86RegisterCanonicalBytesAfter(store, before, target.arch); after != before {
				t.Fatal("SAHF changed a canonical GP byte without a GP output", after)
			}
			prefix := "TEXT ·Value(SB),4,$0-1\nMOVL $0,BX\nCMPL BX,BX\nSETEQ AH\n"
			finish := "MOVB AH,ret+0(FP)\nRET\n"
			for _, body := range []string{"", "SAHF\n"} {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, prefix+body+finish)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, prefix+body+finish, "func Value() bool", target.arch, target.triple, api)
					// Both modes now have the independent ordinary ABI0 bool
					// role. SETcc supplies the actual 0/1 byte; SAHF preserves it.
					if err != nil || ir == "" {
						t.Fatal("SETcc's known canonical AH was lost without a GP overwrite", api, body, err)
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			}
			for _, body := range []string{
				prefix + "LAHF\n" + finish,
				strings.Replace(prefix, "SETEQ AH\n", "", 1) + finish,
				prefix + "MOVB $2,AH\n" + finish,
			} {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, body)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, body, "func Value() bool", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("unknown or noncanonical AH retained a canonical bool witness", api, err)
					}
				}
			}
		})
	}
}
