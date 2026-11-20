package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86FloatMulDivMode32HighNamesStayUnlowered(t *testing.T) {
	for _, opcode := range x86FloatMulDivOpcodes() {
		if !strings.HasPrefix(opcode, "V") {
			continue
		}
		widths := []string{"X", "Y", "Z"}
		if strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD") {
			widths = widths[:1]
		}
		for _, width := range widths {
			for _, index := range []int{8, 15, 16, 29, 31} {
				row := fmt.Sprintf("%s %s%d,%s1,%s2", opcode, width, index, width, width)
				t.Run(row, func(t *testing.T) {
					source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
					goAccepted := width != "Z"
					goAssemblerOracleOutput(t, "386", source, "", goAccepted)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					context, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					context.goarch = "386"
					before := output.Len()
					known, term, err := context.lowerFloatMulDiv(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
					if !known || term || err == nil || goAccepted && !errors.Is(err, ErrProbeNeedsContext) || output.Len() != before {
						t.Fatalf("mode32 high bank acquired a physical value: %t/%t/%v", known, term, err)
					}
				})
			}
		}
	}
}

func TestX86FloatMulDivMode32KeepsActualMXCSRInstructions(t *testing.T) {
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 llc/llvm-objdump required")
	}
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for _, opcode := range x86FloatMulDivOpcodes() {
		if strings.HasSuffix(opcode, "PS") || strings.HasSuffix(opcode, "PD") {
			continue
		}
		bits, typ := 32, I32
		load, resultOffset := "MOVSS", 8
		if strings.HasSuffix(opcode, "SD") {
			bits, typ, load, resultOffset = 64, I64, "MOVSD", 16
		}
		name := strings.ToLower(opcode)
		row, destination := opcode+" X1,X0", "X0"
		if strings.HasPrefix(opcode, "V") {
			row, destination = opcode+" X1,X0,X2", "X2"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s a+0(FP),X0\n%s b+%d(FP),X1\n%s\n%s %s,result+%d(FP)\nRET\n",
			name, resultOffset+bits/8, load, load, bits/8, row, load, destination, resultOffset)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{typ, typ}, Ret: typ,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}, {Offset: int64(bits / 8), Type: typ, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: int64(resultOffset), Type: typ, Field: -1}},
			}}
	}
	goAssemblerOracleOutput(t, "386", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		input, object := filepath.Join(dir, "mode32.ll"), filepath.Join(dir, "mode32.o")
		if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, llc, "-O2", "-mtriple="+triple, "-filetype=obj", input, "-o", object)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("actual mode32 object: %v\n%s", err, output)
		}
		ctx, cancel = runtimeOracleStageContext(t)
		command = exec.CommandContext(ctx, disassembler, "-d", object)
		output, err = runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("actual mode32 machine instructions: %v\n%s", err, output)
		}
		for _, opcode := range []string{"mulss", "mulsd", "divss", "divsd"} {
			if strings.Count(string(output), "\t"+opcode+"\t") != 2 {
				t.Fatalf("%s lost %s/MXCSR to another FP environment:\n%s", triple, opcode, output)
			}
		}
		if strings.Contains(string(output), "fmul") || strings.Contains(string(output), "fdiv") {
			t.Fatalf("mode32 MUL/DIV used x87 instead of source MXCSR:\n%s", output)
		}
	}
}
