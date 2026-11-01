package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86Reciprocal14InitializeOriginalShapes(t *testing.T, original, arch string) (string, string, int) {
	t.Helper()
	var source, declarations strings.Builder
	count := 0
	for _, line := range strings.Split(original, "\n") {
		instruction := strings.TrimSpace(line)
		if instruction == "" || instruction == "RET" || strings.HasPrefix(instruction, "TEXT ") {
			continue
		}
		if arch == "386" {
			// Keep the original high-bank source's Go assembler observation
			// above. Its physical mode32 counterpart uses actual low registers.
			instruction = strings.NewReplacer("X20", "X4", "Y20", "Y4", "X21", "X5").Replace(instruction)
		}
		ins := x86ScalarLaneInstruction(t, instruction)
		registers := [3]int{0, 0, 0}
		for index, operand := range ins.Args {
			register, vector := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
			if !vector {
				continue
			}
			if index == len(ins.Args)-1 {
				registers[2] = register
			} else if index == 0 {
				registers[0] = register
			} else {
				registers[1] = register
			}
		}
		body, declaration := x86PackedAbsSignInitializedInstruction(count, instruction, arch, registers)
		maskOffset := 32
		if arch == "386" {
			maskOffset = 16
		}
		var masks strings.Builder
		for k := 2; k <= 5; k++ {
			fmt.Fprintf(&masks, "KMOVQ mask+%d(FP),K%d\n", maskOffset, k)
		}
		body = strings.Replace(body, "STC\n", masks.String()+"STC\n", 1)
		declaration = strings.Replace(declaration, "input,control,old *[64]byte", "input *[128]byte,control,old *[64]byte", 1)
		source.WriteString(body)
		declarations.WriteString(declaration)
		count++
	}
	return source.String(), declarations.String(), count
}

func TestX86Reciprocal14Mode32HighSyntaxHasNoPhysicalBinding(t *testing.T) {
	for _, member := range x86Reciprocal14TestMembers {
		instruction := member.op + " X1,X20"
		if member.scalar {
			instruction = member.op + " X1,X20,X21"
		}
		source := "TEXT high(SB),$0-0\n" + instruction + "\nRET\n"
		requireX86GoAssemblerResult(t, "386", source, true)
		ins := x86ScalarLaneInstruction(t, instruction)
		if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("named high-bank syntax was mistaken for a physical mode32 register", instruction, known, err)
		}
	}
}

func TestTranslateX86Reciprocal14CompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's _yvexpandpd table accepts EVEX X/Y/Z register or memory
	// sources, optional scalar-memory broadcast, and optional K1-K7 merge/.Z
	// masking. _yvgetexpsd accepts scalar memory/X sources, an X passthrough,
	// and the same optional mask. The 386 frontend accepts packed three-operand
	// masks, refuses scalar four-operand masks, and limits Z registers to Z0-Z7.
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			lastZ := 31
			if target.goarch == "386" {
				lastZ = 7
			}
			var source strings.Builder
			source.WriteString("TEXT reciprocal14forms(SB),$0-0\n")
			for _, op := range []string{"VRCP14PS", "VRCP14PD", "VRSQRT14PS", "VRSQRT14PD"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s1, %s20\n", op, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20\n", op, width)
					fmt.Fprintf(&source, "\t%s.BCST 16(AX), %s20\n", op, width)
				}
				fmt.Fprintf(&source, "\t%s Z1, Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s 24(AX), Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s.BCST 32(AX), Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s X1, K1, X20\n", op)
				fmt.Fprintf(&source, "\t%s.Z 40(AX), K2, Y20\n", op)
				fmt.Fprintf(&source, "\t%s.BCST.Z 48(AX), K3, Z%d\n", op, lastZ)
			}
			for _, op := range []string{"VRCP14SS", "VRCP14SD", "VRSQRT14SS", "VRSQRT14SD"} {
				fmt.Fprintf(&source, "\t%s X1, X20, X21\n", op)
				fmt.Fprintf(&source, "\t%s 56(AX), X20, X21\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X20, K4, X21\n", op)
					fmt.Fprintf(&source, "\t%s.Z 64(AX), X20, K5, X21\n", op)
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			initialized, declaration, count := x86Reciprocal14InitializeOriginalShapes(t, source.String(), target.goarch)
			want := 64
			if target.goarch == "386" {
				want = 56
			}
			if count != want {
				t.Fatal("original reciprocal14 shape count changed", count, want)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, initialized, declaration, target.goarch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized original reciprocal14 shapes rejected", err)
					}
					compileLLVMToObject(t, llc, target.triple, "reciprocal14-"+target.name+".ll", "reciprocal14-"+target.name+".o", ir)
				})
			}
		})
	}
}

func TestTranslateX86Reciprocal14RejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VRCP14PS X0, Y1"},
		{goarch: "amd64", instruction: "VRSQRT14PD.Z Z0, Z1"},
		{goarch: "amd64", instruction: "VRCP14PS.BCST X0, X1"},
		{goarch: "amd64", instruction: "VRCP14PD.SAE Z0, Z1"},
		{goarch: "amd64", instruction: "VRSQRT14PS Z0, K0, Z1"},
		{goarch: "amd64", instruction: "VRCP14SS X0, X1"},
		{goarch: "amd64", instruction: "VRCP14SD Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRSQRT14SS.BCST 8(AX), X1, X2"},
		{goarch: "amd64", instruction: "VRSQRT14SD.SAE X0, X1, X2"},
		{goarch: "amd64", instruction: "VRCP14SS.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VRCP14SS X0, X1, K0, X2"},
		{goarch: "386", instruction: "VRCP14SS X0, X1, K1, X2"},
		{goarch: "386", instruction: "VRSQRT14PD Z0, Z8"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's reciprocal14 tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
