package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86COMIModeContextCannotHideMalformedSource(t *testing.T) {
	for _, name := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, body := range []string{
			name + " X8,Y1\n",
			name + " slot+0(FP)(AX*1),Y1\n",
			name + " X8,X1\nRET\n" + name + " X0,Y1\n",
			name + " X8,X1\nRET\nTEXT ·later(SB),4,$0-0\n" + name + " X0,Y1\n",
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(name+"/"+api+"/"+body, func(t *testing.T) {
					_, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-0\n"+body+"RET\n",
						"func view()\nfunc later()\n", "386", "i386-unknown-linux-gnu", api)
					if err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("mode32 context hid malformed original source: %v", err)
					}
				})
			}
		}
	}
}

func TestX86COMIDirectLowererRequiresNativeTarget(t *testing.T) {
	for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "i386-unknown-linux-gnu"} {
		var output strings.Builder
		ctx := amd64Ctx{b: &output, goarch: "amd64", targetTriple: triple}
		instruction := x86ScalarLaneInstruction(t, "COMISS X0,X1")
		known, terminated, err := ctx.lowerVectorScalarFlagCompare(instruction.Op, instruction)
		if !known || terminated || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
			t.Fatal("direct helper emitted without native target", triple, known, terminated, err, output.String())
		}
	}
}

func TestX86COMIRawVEXLengthIsNotPortableIgnoredBit(t *testing.T) {
	for _, name := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+name+" X0,X1\nRET\n")
		if len(code) != 5 || code[0] != 0xc5 || code[1]&4 != 0 {
			t.Fatalf("actual Go must retain its VEX.L0 encoding: %s %x", name, code)
		}
		code[1] |= 4
		for _, mode := range []int{32, 64} {
			if _, _, matched, err := decodedX86ScalarFlagCompareInstruction(code[:4], mode); !matched || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("raw VEX.L1 normalized to L0 without physical contract: %s mode%d %x %v", name, mode, code, err)
			}
			var source strings.Builder
			source.WriteString("TEXT ·view(SB),4,$0-0\n")
			for _, value := range code[:4] {
				fmt.Fprintf(&source, "BYTE $%#x\n", value)
			}
			source.WriteString("RET\n")
			arch, triple := "amd64", "x86_64-unknown-linux-gnu"
			if mode == 32 {
				arch, triple = "386", "i386-unknown-linux-gnu"
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source.String(), "func view()\n", arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("raw L1 lost context through public API", name, arch, api, err)
				}
			}
		}
	}
}

func TestX86COMIRawEVEXGenerationSurvivesLowRegisters(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT ·view(SB),4,$0-0\n")
	for _, opcode := range []int{0x2e, 0x2f} {
		for _, double := range []bool{false, true} {
			code := []byte{0x62, 0xf1, 0x7c, 0x08, byte(opcode), 0xc8}
			if double {
				code[2] |= 0x81
			}
			for _, value := range code {
				fmt.Fprintf(&source, "BYTE $%#x\n", value)
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range x86RawReturnTargets {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				if ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func view()\n", target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original low-bank EVEX format invented its X inputs", err)
				}
				ir := x86COMIOriginalFormatObject(t, source.String(), target.arch, target.triple)
				if strings.Count(ir, "{evex} v") != 4 || !strings.Contains(ir, "+avx512f") {
					t.Fatal("low-register raw EVEX private format lost generation/feature", ir)
				}
				x86COMICompileOriginalFormatObjects(t, llc, target.triple, "raw-evex-comi", ir)
			})
		}
	}
}
