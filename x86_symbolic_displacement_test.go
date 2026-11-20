package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86SymbolicDisplacementsRequireConstants(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, body := range []string{
			"CMPB ·flag+OFFSET(SB),$1",
			"CMPW ·flag-OFFSET(SB),$1",
			"CMPL ·flag+(OFFSET+4)(SB),$1",
			"TESTB $1,·flag+OFFSET+4(SB)",
			"TESTW $1,·flag-OFFSET+4(SB)",
			"TESTL $1,·flag<>+OFFSET(SB)",
			"MOVL ·flag+OFFSET(SB),AX",
			"MOVL AX,·flag+OFFSET(SB)",
			"LEAL ·flag+OFFSET(SB),AX",
			"MOVL $·flag+OFFSET(SB),AX",
		} {
			t.Run(target.triple+"/"+body, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-0\n" + body + "\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", false)
				goAssemblerOracleOutput(t, target.arch, "#define OFFSET 8\n"+source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if err := ProbeInstruction(ArchAMD64, target.arch, file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("unresolved symbol displacement is not contextual: %v", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "OFFSET") {
							t.Fatalf("unresolved offset became an external symbol or lost its diagnostic: %v (IR bytes=%d)", err, len(ir))
						}
					})
				}
			})
		}
	}
}

func TestX86ResolvedSymbolCompareDisplacementsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []string{"CMPB", "CMPW", "CMPL", "CMPQ", "TESTB", "TESTW", "TESTL", "TESTQ"} {
			if target.arch == "386" && strings.HasSuffix(opcode, "Q") {
				continue // There is no Q-width Go encoder row in mode32.
			}
			t.Run(target.triple+"/"+opcode, func(t *testing.T) {
				operands := "·flag<>+OFFSET(SB),$1"
				if strings.HasPrefix(opcode, "TEST") {
					operands = "$1,·flag<>+OFFSET(SB)"
				}
				source := "#define OFFSET (2*4)\nDATA ·flag<>+8(SB)/8,$17\nGLOBL ·flag<>(SB),8,$16\n" +
					"TEXT ·view(SB),4,$0-0\n" + opcode + " " + operands + "\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view()\n", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatalf("resolved source lost its translation: %v", err)
						}
						compileLLVMToObject(t, llc, target.triple, "symbol-offset.ll", "symbol-offset.o", ir)
					})
				}
			})
		}
	}
}
