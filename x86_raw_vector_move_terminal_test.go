package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawVectorMoveFormatProbeRetainsTerminalFault(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const source = "TEXT moveprobe(SB),4,$0-0\nVMOVSS (AX),X0\nVMOVSD X1,(BX)\nVMOVUPS (AX),Y2\nVMOVDQU32 Y3,(BX)\nRET\n"
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			code := assembleX87ControlBytes(t, target.arch, source)
			original := append([]byte(nil), code...)
			// Preserve the original complete RET program and all public
			// Context observations before the private fault-ended transport.
			raw := "TEXT moveprobe(SB),4,$0-0\n" + x86DwordProductDirectives(code)
			x86UnboundVoidFormatSources(t, raw, target.arch, target.triple)
			probe := x86RawUnprovedReturnFormProbeFile(t, target.arch, "moveprobe", code)
			if !bytes.Equal(code, original) {
				t.Fatal("private transport changed the independent original Go bytes")
			}
			normalized, err := normalizeX86RawFile(probe, target.arch)
			if err != nil || len(normalized.Funcs) != 1 {
				t.Fatal("private transport lost its decoded function", err)
			}
			instructions := normalized.Funcs[0].Instrs
			if len(instructions) != 6 || (instructions[5].Op != "UD2" && instructions[5].Op != "UNDEF") ||
				len(instructions[5].Args) != 0 {
				t.Fatal("private transport lost its complete body and terminal #UD")
			}
			named, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			for index, instruction := range instructions[1:5] {
				want := named.Funcs[0].Instrs[index+1]
				if instruction.Op != want.Op || !reflect.DeepEqual(instruction.Args, want.Args) {
					t.Fatal("terminal transport changed an original move operand", index)
				}
			}
			ir := x86UnboundVoidRawVectorMoveProbeObject(t, probe, target.arch, target.triple)
			for index := 0; index < 4; index++ {
				body := x86StringMemoryFunction(t, ir, fmt.Sprintf("InstructionFormat%d", index))
				if strings.Count(body, `asm sideeffect "ud2"`) != 1 || !strings.Contains(body, "unreachable") ||
					strings.Contains(body, "ret void") {
					t.Fatal("private move format acquired a return or lost its terminal fault", index)
				}
			}
			for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				x86PackedStringCompileObject(t, llc, target.triple, input, "-O0")
			}
		})
	}
}

func TestX86VectorMoveFaultRowsKeepLaterFormatsVisible(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const rows = "VMOVSS (AX),X0\nVMOVSD X1,(BX)\nVMOVUPS (AX),Y2\nVMOVDQU32.Z X3,K1,(BX)\nVMOVAPD (AX),X4\nVMOVDQU32 X5,(BX)\n"
	for _, target := range x86RawReturnTargets {
		for _, fault := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fault=%t", target.triple, fault), func(t *testing.T) {
				terminal := "RET\n"
				if fault {
					terminal = "BYTE $0x0f\nBYTE $0x0b\n"
				}
				source := "TEXT moverows(SB),4,$0-0\n" + rows + terminal
				// The shared helper first authenticates the complete Go object
				// and all public Context observations, not a cut-down row.
				ir := x86UnboundVoidVectorMoveFormatObject(t, source, target.arch, target.triple)
				if strings.Count(ir, "define void @InstructionFormat") != 6 {
					t.Fatal("an architectural fault swallowed a later format row")
				}
				for index := 0; index < 6; index++ {
					body := x86StringMemoryFunction(t, ir, fmt.Sprintf("InstructionFormat%d", index))
					wantFault := fault || index == 3
					if wantFault {
						if strings.Count(body, `asm sideeffect "ud2"`) != 1 || !strings.Contains(body, "unreachable") ||
							strings.Contains(body, "ret void") {
							t.Fatal("format row lost its single terminal fault", index)
						}
					} else if !strings.Contains(body, "ret void") || strings.Contains(body, `asm sideeffect "ud2"`) {
						t.Fatal("ordinary original format row changed its return", index)
					}
				}
				for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					x86PackedStringCompileObject(t, llc, target.triple, input, "-O0")
				}
			})
		}
	}
}
