package plan9asm

import (
	"errors"
	"testing"
)

func TestARM64OperandProbesDoNotInventRestoredSPOrLR(t *testing.T) {
	for _, instruction := range []string{
		"BIC $255,R0,RSP",
		"ORN $255,R0,RSP",
		"ADRP target,R30",
		"WORD $0x4e042c1e", // SMOV V0.S[0], LR really writes GP30.
		"VST1.P [V0.B16],16(RSP)",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT form(SB),4,$0-0\n" + instruction + "\ntarget:\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
			} {
				if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"form": {Name: "form", Ret: Void}},
				}); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: an unrestored caller continuation must need context, got %v", triple, err)
				}
			}
		})
	}
}

func TestARM64SymbolTailHasWholeFunctionContinuationProof(t *testing.T) {
	const source = "TEXT caller(SB),4,$0-0\nB sink(SB)\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"caller": {Name: "caller", Ret: Void}, "sink": {Name: "sink", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "proven-tail.ll", "proven-tail.o", ir)
		})
	}
}
