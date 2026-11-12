package plan9asm

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func x86AbsSignIndependentFeatures(bits, width int, legacy, evex bool) string {
	features := []string{"+avx"}
	if legacy {
		features = []string{"+sse2", "+ssse3"}
	} else if evex {
		features = []string{"+avx512f"}
		if bits < 32 {
			features = append(features, "+avx512bw")
		}
		if width < 64 {
			features = append(features, "+avx512vl")
		}
	} else if width == 32 {
		features = []string{"+avx2"}
	}
	sort.Strings(features)
	return strings.Join(features, ",")
}

func TestX86PackedAbsSignIsolatedCompleteISAProfiles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedAbsSignOracleRows() {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				evex := !row.legacy && !row.sign && (row.bits == 64 || row.width == 64 || row.mode == "merge" || row.mode == "zero" || row.source == "broadcast")
				want := x86AbsSignIndependentFeatures(row.bits, row.width, row.legacy, evex)
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); got != want {
					t.Fatal("isolated complete original ISA profile borrowed a sibling, lost a carrier or added AVX512 to a lesser form", got, want)
				}
			})
		}
	}
}

func TestX86PackedAbsSignLowBankPhysicalGenerationISAProfiles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for bitsIndex, suffix := range []string{"B", "W", "D", "Q"} {
			for _, evex := range []bool{false, true} {
				if bitsIndex == 3 && !evex {
					continue
				}
				for width, bank := range []string{"X", "Y", "Z"} {
					if width == 2 && !evex {
						continue
					}
					for _, memory := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/VPABS%s/%s/EVEX=%t/memory=%t", arch, suffix, bank, evex, memory), func(t *testing.T) {
							modrm := byte(0xd0) // destination2, source0 or (AX).
							if memory {
								modrm = 0x10
							}
							code := []byte{0xc4, 0xe2, 0x79 | byte(width)<<2, 0x1c + byte(bitsIndex), modrm}
							if evex {
								p1 := byte(0x7d)
								if bitsIndex == 3 {
									p1 |= 0x80
								}
								code = []byte{0x62, 0xf2, p1, 0x08 | byte(width)<<5, 0x1c + byte(bitsIndex), modrm}
							}
							ins := x86RawMoveObservedInstruction(t, arch, code)
							want := x86AbsSignIndependentFeatures(8<<bitsIndex, 16<<width, false, evex)
							if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); got != want {
								t.Fatal("low-bank unmasked physical EVEX cannot be inferred from a VEX-looking named operand list", got, want)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86PackedAbsSignISAProfilesRejectMalformedOrForeignGeneration(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, instruction := range []string{"PABSB Y0,X1", "PSIGND X0,Y1", "VPABSB X0,Y1", "VPABSW.Z X0,X1", "VPSIGNB Z0,Z1,Z2", "VPABSQ X0,K0,X1"} {
			ins := x86ScalarLaneInstruction(t, instruction)
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}); got != "" {
				t.Fatal("malformed ABS/sign form acquired an ISA profile", instruction, got)
			}
		}
		for _, instruction := range []string{"PABSB X0,X1", "PSIGNW X0,X1", "VPSIGND X0,X1,X2"} {
			ins := x86ScalarLaneInstruction(t, instruction)
			ins.x86PackedAbsEVEX = true
			if _, known, err := x86PackedAbsSignProperties(ins.Op, ins, arch); !known || err == nil ||
				inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}) != "" {
				t.Fatal("a foreign physical EVEX tag created an unsupported generation", instruction, err)
			}
		}
	}
}

// No MOVOU, AVX zero or other sibling supplies a native XMM register class.
// PSIGN's data is initialized by its existing pure self-XOR transfer; PABS
// has no old destination input. These are actual Go/LLVM native objects.
func TestX86PackedAbsSignMinimalLegacyNativeCarrierObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("isolated native ABS/sign carriers require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			move, word := "MOVQ", goWordSize(target.arch)
			if target.arch == "386" {
				move = "MOVL"
			}
			for index, row := range x86AbsSignAlignmentRows()[:6] {
				fmt.Fprintf(&source, "TEXT ·Isolated%d(SB),4,$0-%d\n%s input+0(FP),BX\n", index, word, move)
				if row.sign {
					source.WriteString("PXOR X0,X0\n")
				}
				source.WriteString(row.instruction() + "\nRET\n")
				fmt.Fprintf(&declarations, "func Isolated%d(input *byte)\n", index)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("isolated complete native family lost actual pointer/data inputs", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "isolated-abs-sign.ll", "isolated-abs-sign.o", body)
					}
				})
			}
		})
	}
}
