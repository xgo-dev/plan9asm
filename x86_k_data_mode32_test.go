package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Primary Intel XED: F2/W1 92/93 aliases to KMOVD32 in32-bit mode.
// The original Go W1 bytes remain literal even though the GP transfer is32-bit.
func TestX86KDataMode32GPQEffective32NamedAndRaw(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, row := range []struct {
		name, instruction, source, declaration string
		encoding                               []byte
	}{
		{"K-to-GP", "KMOVQ K0,BX",
			"TEXT ·Value(SB),4,$0-12\nKMOVQ a+0(FP),K0\nKMOVQ K0,BX\nMOVL BX,ret+8(FP)\nRET\n",
			"func Value(a uint64) uint32", []byte{0xc4, 0xe1, 0xfb, 0x93, 0xd8}},
		{"GP-to-K", "KMOVQ AX,K0",
			"TEXT ·Value(SB),4,$0-12\nMOVL a+0(FP),AX\nKMOVQ AX,K0\nKMOVQ K0,ret+4(FP)\nRET\n",
			"func Value(a uint32) uint64", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc0}},
	} {
		t.Run(row.name, func(t *testing.T) {
			listing, err := x86ScalarLiteralGoListing(t, "386", row.source)
			if err != nil {
				t.Fatal(err)
			}
			fixture := x86OfficialPackedCase{
				row: "independent/K-data/mode32/" + row.name, symbol: "Value", line: 3,
				witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: row.encoding},
			}
			if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{fixture}); err != nil {
				t.Fatal(err)
			}
			for _, raw := range []bool{false, true} {
				name, source := "named", row.source
				if raw {
					name = "raw"
					source = strings.Replace(source, row.instruction+"\n", x86RawDisplacementDirectives(row.encoding), 1)
				}
				t.Run(name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, "386", "i386-unknown-linux-gnu", api)
							if err != nil || ir == "" {
								t.Fatal("legal32-bit KMOV alias lacks its effective-width contract", err)
							}
							effect, known, err := x86TypedMaskMoveByteEffect("KMOVQ", x86ScalarLaneInstruction(t, row.instruction), "386")
							if !known || err != nil || len(effect.operands) != 2 ||
								effect.operands[0].width != 4 || effect.operands[1].width != 4 {
								t.Fatal("typed effect did not bind the effective32-bit GP transfer", known, err, effect)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, "i386-unknown-linux-gnu", ir, level)
							}
						})
					}
				})
			}
		})
	}
	// The independent portable integer owner checks values separately; these
	// objects do not establish native386/AVX512 execution.
}

func TestX86KDataMode32GPQRejectsMissingNumericalInputs(t *testing.T) {
	for _, row := range []struct {
		name, declaration, body, instruction string
		code                                 []byte
	}{
		{"unknown-GP", "func Value(a uint32) uint64", "", "KMOVQ AX,K0", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc0}},
		{"partial-GP", "func Value(a uint32) uint64", "MOVW a+0(FP),AX\n", "KMOVQ AX,K0", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc0}},
		{"pointer-GP", "func Value(a *byte) uint64", "MOVL a+0(FP),AX\n", "KMOVQ AX,K0", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc0}},
		{"unknown-K", "func Value(a uint64) uint32", "", "KMOVQ K0,BX", []byte{0xc4, 0xe1, 0xfb, 0x93, 0xd8}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := "KMOVQ K0,ret+4(FP)\n"
			if row.name == "unknown-K" {
				store = "MOVL BX,ret+8(FP)\n"
			}
			for _, raw := range []bool{false, true} {
				instruction := row.instruction + "\n"
				if raw {
					instruction = x86RawDisplacementDirectives(row.code)
				}
				source := "TEXT ·Value(SB),4,$0-12\n" + row.body + instruction + store + "RET\n"
				x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, "386", "i386-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("mode-effective width invented NUM/K input", raw, api, err)
					}
				}
			}
		})
	}
}

func TestX86KDataMode32KeepsQNonGP64(t *testing.T) {
	for _, text := range []string{"KMOVQ K0,K3", "KMOVQ (AX),K3", "KMOVQ K0,(AX)"} {
		t.Run(text, func(t *testing.T) {
			effect, known, err := x86TypedMaskMoveByteEffect("KMOVQ", x86ScalarLaneInstruction(t, text), "386")
			if !known || err != nil || len(effect.operands) != 2 ||
				effect.operands[0].width != 8 || effect.operands[1].width != 8 {
				t.Fatal("GP-width normalization truncated a real64-bit K/memory form", known, err, effect)
			}
		})
	}
}
