package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

const x86StaticSetShiftData = "DATA ·cell+0(SB)/8,$0x0102030405060708\nGLOBL ·cell(SB),16,$24\n"

func x86StaticSetShiftInstructions(arch string) []string {
	var instructions []string
	for _, operation := range x86NativeSetOracle {
		instructions = append(instructions, operation+" ·cell+4(SB)")
	}
	for _, row := range x86ScalarShiftMemoryRows(arch) {
		if !row.readOnly {
			instructions = append(instructions, strings.ReplaceAll(row.text, "1(DI)", "·cell+4(SB)"))
		}
	}
	return append(instructions, "SHLL $4,·cell+4(SB):AX", "SHRL CX,·cell+4(SB):AX")
}

func TestX86StaticSetShiftCompleteFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			assembly.WriteString(x86StaticSetShiftData)
			instructions := x86StaticSetShiftInstructions(target.arch)
			for i, instruction := range instructions {
				name := fmt.Sprintf("Static%d", i)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-0\nMOVL $1,AX\nMOVL $2,CX\nCMPL AX,CX\n%s\nRET\n", name, instruction)
				fmt.Fprintf(&declarations, "func %s()\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if target.arch == "386" {
						nm := findLLVM22Tool("llvm-nm")
						if nm == "" {
							t.Fatal("LLVM 22 llvm-nm required")
						}
						object := x86PackedStringCompileObject(t, llc, target.triple, ir, "-O0")
						output, err := exec.Command(nm, "--undefined-only", object).CombinedOutput()
						if err != nil || strings.TrimSpace(string(output)) != "" {
							t.Fatalf("386 shift object has unresolved symbols: %v\n%s", err, output)
						}
					}
					for _, variant := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if got := strings.Count(variant, "store volatile "); got != len(instructions) {
							t.Fatalf("got %d volatile stores, want %d", got, len(instructions))
						}
						if got := strings.Count(variant, "load volatile "); got != len(instructions)-len(x86NativeSetOracle) {
							t.Fatalf("shift read or SETcc write-only effect changed: %d volatile loads", got)
						}
						x86PackedStringCompileObject(t, llc, target.triple, variant, "-O2")
					}
				})
			}
		})
	}
}

func TestX86StaticSetShiftNeedsWritableBytesAndInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, test := range []struct {
			instruction, setup, missing string
			width                       int
		}{
			{"SETCC ·cell+4(SB)", "CLC\n", "CLC\n", 1},
			{"SHLL CL,AX,·cell+4(SB)", "MOVL $7,AX\nMOVL $2,CX\n", "MOVL $7,AX\n", 4},
			{"RCRW $1,·cell+4(SB)", "STC\n", "STC\n", 2},
		} {
			prepare := func(data, setup, instruction string) string {
				return data + "TEXT ·Value(SB),4,$0-0\n" + setup + instruction + "\nRET\n"
			}
			failures := map[string]string{
				"external":      prepare("", test.setup, test.instruction),
				"readonly":      prepare("GLOBL ·cell(SB),24,$24\n", test.setup, test.instruction),
				"short":         prepare(fmt.Sprintf("GLOBL ·cell(SB),16,$%d\n", 3+test.width), test.setup, test.instruction),
				"negative":      prepare(x86StaticSetShiftData, test.setup, strings.Replace(test.instruction, "+4(SB)", "-1(SB)", 1)),
				"code":          prepare(x86StaticSetShiftData, test.setup, strings.Replace(test.instruction, "·cell+4(SB)", "·Value(SB)", 1)),
				"pointer-data":  prepare(fmt.Sprintf("DATA ·cell+0(SB)/%d,$·other(SB)\nGLOBL ·cell(SB),16,$24\nGLOBL ·other(SB),16,$8\n", goWordSize(arch)), test.setup, test.instruction),
				"missing-input": prepare(x86StaticSetShiftData, strings.Replace(test.setup, test.missing, "", 1), test.instruction),
				"raw-return":    strings.Replace(prepare(x86StaticSetShiftData, test.setup, test.instruction), "RET\n", "BYTE $0xc3\nRET\n", 1),
			}
			for name, source := range failures {
				t.Run(arch+"/"+test.instruction+"/"+name, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", arch, x86AddressMemoryTargets(arch)[0], api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("%s granted source/storage permissions: %v", api, err)
						}
					}
				})
			}
		}
	}
}
