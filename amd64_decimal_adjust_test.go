package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86DecimalAdjustGo386Forms(t *testing.T) {
	rows := []struct{ op, bytes string }{
		{"AAA", "BYTE $0x37"},
		{"AAD", "BYTE $0xd5\nBYTE $10"},
		{"AAM", "BYTE $0xd4\nBYTE $10"},
		{"AAS", "BYTE $0x3f"},
		{"DAA", "BYTE $0x27"},
		{"DAS", "BYTE $0x2f"},
	}
	const prefix = "TEXT adjust(SB),4,$0-4\nMOVL $0xa5a5429a,AX\nADDL $0,AX\n"
	const suffix = "\nMOVL AX,ret+0(FP)\nRET\n"
	options := Options{
		Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"adjust": {Name: "adjust", Ret: I32, Frame: FrameLayout{
				Results: []FrameSlot{{Name: "ret", Type: I32, Field: -1}},
			}},
		},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	translate := func(t *testing.T, body string) string {
		t.Helper()
		file, err := Parse(ArchAMD64, prefix+body+suffix)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(err)
		}
		_, afterHeader, _ := strings.Cut(ir, "\ntarget triple")
		return afterHeader
	}
	for _, row := range rows {
		t.Run(row.op, func(t *testing.T) {
			goAssemblerOracleOutput(t, "386", prefix+row.op+suffix, "", true)
			goAssemblerOracleOutput(t, "amd64", prefix+row.op+suffix, "", false)
			named := translate(t, row.op)
			raw := translate(t, row.bytes)
			if named == "" || named != raw {
				t.Fatal("named and raw forms generated different module contents")
			}
			compileLLVMToObject(t, llc, options.TargetTriple, "decimal.ll", "decimal.o", "target triple"+named)
			if err := ProbeInstruction(ArchAMD64, "amd64", Instr{Op: Op(row.op), Raw: row.op}); err == nil {
				t.Fatal("accepted an illegal 64-bit mode instruction")
			}
		})
	}
	for _, op := range []string{"AAD", "AAM"} {
		bad := fmt.Sprintf("%s $10", op)
		goAssemblerOracleOutput(t, "386", prefix+bad+suffix, "", false)
		if err := ProbeInstruction(ArchAMD64, "386", Instr{Op: Op(op), Raw: bad, Args: []Operand{
			{Kind: OpImm, Imm: 10},
		}}); err == nil {
			t.Fatalf("accepted the raw radix operand in named %s", op)
		}
	}
}

func TestX86DecimalAdjustRequiresArchitecturalInputs(t *testing.T) {
	const source = "TEXT adjust(SB),4,$0-0\nMOVW $0x102, AX\nAAA\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"adjust": {Name: "adjust", Ret: Void}},
	})
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "undefined input") {
		t.Fatalf("AAA with uninitialized AF returned %v", err)
	}
}

func TestX86DecimalAdjustZeroRadixFault(t *testing.T) {
	const source = "TEXT adjust(SB),4,$0-0\nBYTE $0xd4\nBYTE $0\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"adjust": {Name: "adjust", Ret: Void}},
	}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, `asm sideeffect ".byte 0xd4, 0"`) || !strings.Contains(ir, "unreachable") {
		t.Fatal("encoded AAM 0 did not retain the terminal divide fault")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, options.TargetTriple, "decimal-fault.ll", "decimal-fault.o", ir)
	options.TargetTriple = "aarch64-unknown-linux-gnu"
	if got, err := Translate(file, options); got != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("foreign backend returned IR=%t, error=%v", got != "", err)
	}
}
