package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GPSIMDTransferFPSpansRejectEveryMissingByteBeforeIR(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		width := 4
		if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
			width = 8
		}
		for missing := 0; missing < width; missing++ {
			t.Run(fmt.Sprintf("%s/missing%d", op, missing), func(t *testing.T) {
				var args []LLVMType
				var slots []FrameSlot
				for offset := 0; offset < width; offset++ {
					if offset != missing {
						slots = append(slots, FrameSlot{Offset: int64(offset), Type: I8, Index: len(args), Field: -1})
						args = append(args, I8)
					}
				}
				var output strings.Builder
				ctx := newAMD64Ctx(&output, Func{}, FuncSig{Args: args, Ret: Void, Frame: FrameLayout{Params: slots}}, nil, nil, false)
				ctx.goarch = "amd64"
				ins := x86YMMReadSource(t, op+" x+0(FP),X0")
				known, _, err := ctx.lowerVectorScalarIntegerMove(ins.Op, ins)
				if !known || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
					t.Fatalf("missing byte acquired transfer or partial IR: %v\n%s", err, output.String())
				}
			})
		}
	}
}

func TestX86GPSIMDTransferDeadMemoryRetainsNativeWidth(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		t.Run(op, func(t *testing.T) {
			bits := 32
			if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
				bits = 64
			}
			for _, arch := range []string{"amd64", "386"} {
				source := "TEXT f(SB),4,$0-0\n" + op + " (AX),X0\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if !strings.Contains(text, fmt.Sprintf("load volatile i%d", bits)) {
						t.Fatalf("dead %s memory read erased or widened on %s: want observable %d-bit load\n%s", op, arch, bits, text)
					}
					compileLLVMToObject(t, llc, triple, "transfer-dead-read.ll", "transfer-dead-read.o", text)
				}
			}
		})
	}
}
