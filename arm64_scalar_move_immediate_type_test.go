package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestARM64ScalarGPMoveRejectsFloatingOperandThroughFullTranslate(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, literal := range []string{"0.0", "-0.0", "1.5", "-1.5"} {
			for _, shape := range []struct{ suffix, operands string }{
				{operands: "$%s,R0"},
				{operands: "$%s,8(R0)"},
				{operands: "$%s,storage(SB)"},
				{operands: "R0,$%s"},
				{suffix: ".P", operands: "$%s,8(R0)"},
				{suffix: ".W", operands: "$%s,8(R0)"},
			} {
				instruction := op + shape.suffix + " " + fmt.Sprintf(shape.operands, literal)
				t.Run(instruction, func(t *testing.T) {
					source := "GLOBL storage(SB),16,$8\nTEXT floating(SB),516,$0-0\n" + instruction + "\nRET\n"
					requireARM64GoAssemblerResult(t, source, false)
					file, err := Parse(ArchARM64, source)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, operand := range file.Funcs[0].Instrs[1].Args {
						found = found || operand.Kind == OpImm && operand.ImmIsFloat
					}
					if !found {
						t.Fatal("test did not reach the typed floating immediate")
					}

					_, err = Translate(file, Options{
						Goarch:       "arm64",
						TargetTriple: "aarch64-unknown-linux-gnu",
						Sigs: map[string]FuncSig{
							"floating": {Name: "floating", Ret: Void},
						},
					})
					if err == nil || !strings.Contains(err.Error(), "floating immediate") {
						t.Fatalf("full lowerer did not reject the invalid floating operand: %v", err)
					}
				})
			}
		}
	}
}

func TestARM64ScalarGPMoveImmediateClassMatchesGo(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	// TYPE_FCONST is a distinct C_FCON class. The seven scalar GP spellings
	// have no such row; the unsigned spellings inherit the signed family's
	// rows (also checked by the complete GP move family test).
	for _, op := range []string{"AMOVB", "AMOVBU", "AMOVH", "AMOVHU", "AMOVW", "AMOVWU", "AMOVD"} {
		if regexp.MustCompile(`(?m)^\s*\{` + op + `, C_FCON,`).Match(source) {
			t.Fatalf("Go acquired a floating GP MOV row: %s; audit its complete semantics", op)
		}
	}
	for _, op := range []string{"AFMOVS", "AFMOVD"} {
		if !regexp.MustCompile(`(?m)^\s*\{` + op + `, C_FCON, C_NONE, C_NONE, C_FREG,`).Match(source) {
			t.Fatalf("Go floating immediate row changed: %s", op)
		}
	}
}

func TestARM64ScalarGPMoveFloatGuardKeepsValidIntegerAndFPTransfers(t *testing.T) {
	lines := []string{"GLOBL storage(SB),16,$8", "TEXT valid(SB),516,$0-0"}
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		lines = append(lines, op+" $0,R0", op+" R1,R0", op+" $0,8(R0)", op+" $0,storage(SB)")
	}
	lines = append(lines,
		"MOVW $806,R0", "MOVD $-601,R0", "MOVD $0x123456789abcdef,R0",
		"FMOVS $0.0,F0", "FMOVD $-0.0,F0", "FMOVS $1.5,F0", "FMOVD $-1.5,F0",
		"FMOVS R1,F0", "FMOVS F0,R1", "FMOVD R1,F0", "FMOVD F0,R1", "RET",
	)
	source := strings.Join(lines, "\n") + "\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{
			Goarch:       "arm64",
			TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"valid": {Name: "valid", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "valid-moves.ll", "valid-moves.o", ir)
	}
}
