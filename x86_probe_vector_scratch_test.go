package plan9asm

import (
	"errors"
	"testing"
)

func TestX86ProbeDoesNotBorrowDeclaredVectorScratch(t *testing.T) {
	for _, body := range []string{
		"VADDSUBPD X2,X9,X2", "VADDSUBPD Y2,Y15,Y2",
		"VCVTTPS2DQ X2,X2", "SQRTSS X2,X2",
		"VPMOVB2M Z6,K1", "VROUNDSS $7,X2,X9,X2",
	} {
		t.Run("unknown/"+body, func(t *testing.T) {
			source := "TEXT probe(SB),4,$0-0\n" + body + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 {
				t.Fatal("the independent official source fixture must parse completely", err)
			}
			fn := file.Funcs[0]
			sig := FuncSig{Name: fn.Sym, Ret: Void}
			if !x86TypedFPResultNeedsProof(fn, sig, "amd64") {
				t.Fatal("the fixture must exercise an existing mandatory numerical-input route")
			}
			if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("the strict source audit must keep the original entry unknown", err)
			}
			instruction := fn.Instrs[1]
			for _, api := range []string{"instruction", "sequence"} {
				t.Run(api, func(t *testing.T) {
					var err error
					if api == "instruction" {
						err = ProbeInstruction(ArchAMD64, "amd64", instruction)
					} else {
						err = ProbeInstructionSequence(ArchAMD64, "amd64", []Instr{instruction})
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("a synthetic probe borrowed ordinary codegen's scratch realization", err)
					}
				})
			}
		})
	}
	// Preserve old grammar-only positives as well as genuinely source-defined
	// sequences. Probe success remains IR-generation evidence, not execution.
	for _, body := range []string{"MOVL $7,AX", "PXOR X0,X0", "PUNPCKLQDQ X0,X0", "UNDEF",
		"SHLL $4,BX", "VPCMPEQB X2,X9,X2",
		"PXOR X0,X0\nVADDSUBPD X0,X0,X1"} {
		t.Run("existing-positive/"+body, func(t *testing.T) {
			source := "TEXT probe(SB),4,$0-0\n" + body + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			instructions := file.Funcs[0].Instrs[1 : len(file.Funcs[0].Instrs)-1]
			if err := ProbeInstructionSequence(ArchAMD64, "amd64", instructions); err != nil {
				t.Fatal("an existing or initialized probe lost its original classification", err)
			}
		})
	}
	for _, body := range []string{"VADDSUBPD X0,X1", "VADDSUBPD.Z X0,X1,X2", "NOT_AN_X86_OPCODE"} {
		t.Run("grammar-error/"+body, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+body+"\nRET\n")
			if err != nil {
				t.Fatal("this control must reach the actual lowering grammar", err)
			}
			err = ProbeInstructionSequence(ArchAMD64, "amd64", file.Funcs[0].Instrs[1:2])
			if err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an original grammar error was hidden behind source context", err)
			}
		})
	}
}
