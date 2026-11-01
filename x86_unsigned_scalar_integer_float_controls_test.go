package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86UnsignedScalarIntegerFloatCompleteMinimalNativeProfiles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86UnsignedScalarIntegerFloatRows(arch) {
			instruction := x86ScalarLaneInstruction(t, row.instruction())
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{instruction}}); got != "+avx512f" {
				t.Fatal("an isolated unsigned scalar conversion borrowed a sibling's ISA or an unneeded VL profile", arch, row.instruction(), got)
			}
		}
	}
}

func TestX86UnsignedScalarIntegerFloatInvalidControlGrammarMatchesGo(t *testing.T) {
	for _, member := range x86UnsignedScalarIntegerFloatOracle {
		bad := []string{
			member.op + ".SAE CX,X0,X1", member.op + ".Z CX,X0,X1",
			member.op + ".BCST (BX),X0,X1", member.op + " CX,X0,K1,X1",
			member.op + " X0,X0,X1", member.op + " $7,X0,X1",
			member.op + " CX,Y0,X1", member.op + " CX,X0,Y1",
		}
		if member.rounding {
			bad = append(bad, member.op+".RN_SAE (BX),X0,X1")
		} else {
			bad = append(bad, member.op+".RN_SAE CX,X0,X1")
		}
		for index, instruction := range bad {
			t.Run(fmt.Sprint(member.op, "/", index), func(t *testing.T) {
				goAssemblerOracleOutput(t, "amd64", "TEXT rejected(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
				assertX86ScalarIntegerFloatRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
			})
		}
	}
}

// Private format objects retain the complete original table and original
// source independently of initialized programs. They grant no public success.
func TestX86UnsignedScalarIntegerFloatUnboundFormatsKeepContextAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original unsigned scalar format objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			for index, row := range x86UnsignedScalarIntegerFloatRows(target.arch) {
				if row.source == "FP" {
					continue // No invented FP frame for a bare format witness.
				}
				fmt.Fprintf(&source, "TEXT ·UnsignedFormat%d(SB),4,$0-0\n%s\nRET\n", index, row.instruction())
			}
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			ir := x86ScalarFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				compileLLVMToObject(t, llc, target.triple, "unsigned-original-formats.ll", "unsigned-original-formats.o", text)
			}
		})
	}
}
