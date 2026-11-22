package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

const mode32MMXFrameSignature = "func Copy(p, q *uint64)"

func mode32MMXFrameCopy(setup, body string) string {
	const entry = "TEXT ·Copy(SB),4,$16-8\nMOVL p+0(FP),AX\nMOVL q+4(FP),BX\n"
	return entry + setup + body + "\nEMMS\nRET\n"
}

func TestMode32NativeMMXFrameOriginalOperands(t *testing.T) {
	const loadAndSpill = "MOVQ (AX), M0\nMOVQ M0, 8(SP)\nMOVQ 8(SP), M0\n"
	const pair = loadAndSpill + "MOVQ M0, (BX)"
	const official = loadAndSpill + "MOVQ M0, (AX)\nMOVQ M0, (BX)"
	cases := []struct {
		name   string
		source string
	}{
		{"official 386enc.s", mode32MMXFrameCopy("", official)},
		{"logical AUTO", mode32MMXFrameCopy("", strings.ReplaceAll(pair, "8(SP)", "spill-8(SP)"))},
		{"typed derived SP", mode32MMXFrameCopy("LEAL 8(SP),DX\n", strings.Replace(pair, "MOVQ 8(SP), M0", "MOVQ (DX), M0", 1))},
		{"dword memory", mode32MMXFrameCopy("", "MOVL (AX), M0\nMOVL M0, 12(SP)\nMOVL 12(SP), M0\nMOVL M0, (BX)")},
		{"scalar prefix", mode32MMXFrameCopy("MOVL $5,8(SP)\nMOVL $7,12(SP)\n", "MOVQ 8(SP), M0\nMOVQ M0, (BX)")},
		{"shuffle reads frame", mode32MMXFrameCopy("", "MOVQ (AX), M0\nMOVQ M0, 8(SP)\nPSHUFW $27, 8(SP), M1\nMOVQ M1, (BX)")},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			requireX86GoAssemblerResult(t, "386", row.source, true)
			for _, target := range x86Legacy127Targets("386") {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, row.source, mode32MMXFrameSignature, "386", target, api)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target, "mmx-frame.ll", "mmx-frame.o", ir)
					})
				}
			}
		})
	}
}

func TestMode32NativeMMXFrameNoInventedBytes(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"uninitialized", "MOVQ 8(SP),M0\nMOVQ M0,(BX)"},
		{"partial store", "MOVQ (AX),M0\nMOVL M0,8(SP)\nMOVQ 8(SP),M0\nMOVQ M0,(BX)"},
		{"pointer is not data", "MOVL AX,8(SP)\nMOVL $1,12(SP)\nMOVQ 8(SP),M0\nMOVQ M0,(BX)"},
		{"straddles frame", "MOVQ (AX),M0\nMOVQ M0,12(SP)"},
		{"whole extent", "MOVQ (AX),M0\nMOVQ M0,16(SP)"},
		{"index without proof", "MOVQ (AX),M0\nMOVQ M0,8(SP)(AX*1)"},
		{"streaming alignment", "MOVQ (AX),M0\nMOVNTQ M0,8(SP)"},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			source := mode32MMXFrameCopy("", row.body)
			requireX86GoAssemblerResult(t, "386", source, true)
			if _, err := x86ScalarFPBitViewAPI(t, source, mode32MMXFrameSignature,
				"386", "i386-unknown-linux-gnu", "text"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved native frame obtained an MMX access:", err)
			}
		})
	}
}

func TestMode32NativeMMXFrameFeedsScalarContinuation(t *testing.T) {
	const prefix = "TEXT ·Value(SB),4,$16-8\nMOVL p+0(FP),AX\n"
	const body = "MOVQ (AX),M0\nMOVQ M0,8(SP)\nEMMS\nMOVL 12(SP),AX\nMOVL AX,ret+4(FP)\nRET\n"
	const declaration = "func Value(p *uint64) uint32"
	source := prefix + body
	requireX86GoAssemblerResult(t, "386", source, true)
	for _, target := range x86Legacy127Targets("386") {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", target, api)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, findLLVM22Tool("llc"), target, "mmx-scalar.ll", "mmx-scalar.o", ir)
			})
		}
	}
}
