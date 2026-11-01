package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent Intel FP16 sections 5.10, 5.16, 5.18, 5.19, 5.21 and 5.24.
// These are physical map5/map6 forms, not Go named-opcode registrations.
// https://cdrdv2-public.intel.com/678970/intel-avx512-fp16.pdf
var x86FP16ConversionResultNames = []string{
	"VCVTPH2PSX", "VCVTPS2PHX", "VCVTSH2SS", "VCVTSS2SH", "VCVTSH2SD", "VCVTSD2SH",
}

func x86FP16ConversionResultEncoding(member, length int, memory, control, zero bool) []byte {
	var code []byte
	if member < 2 {
		code = rawFP16Conversion(member == 1, length, 1, 0, 1, memory, control, zero)
	} else {
		code = rawFP16ScalarConversion(member-2, length, 2, 1, 0, 1, memory, control, zero)
	}
	if memory {
		code[len(code)-1] = 0 // Actual incoming AX pointer, without a guessed extent.
	}
	return code
}

func x86FP16ConversionResultFixture(name, arch string, member, length int, memory, control, zero bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	code := x86FP16ConversionResultEncoding(member, length, memory, control, zero)
	source := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n%s p+0(FP),AX\n", name, word+4, move) +
		"MOVL $1,CX\nKMOVD CX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n" +
		x86RawDisplacementDirectives(code) +
		fmt.Sprintf("MOVL X0,DX\nMOVL DX,ret+%d(FP)\nRET\n", word)
	return source, fmt.Sprintf("func %s(p *byte) uint32\n", name)
}

func TestX86RawFP16ConversionInitializedNativeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for batch := 0; batch < 2; batch++ {
			t.Run(fmt.Sprintf("%s/batch%d", target.triple, batch), func(t *testing.T) {
				var source, declarations strings.Builder
				encodings := make(map[string]x86RawFP16ObjectEncoding)
				count := 0
				for member := range x86FP16ConversionResultNames {
					if member%2 != batch {
						continue
					}
					for length := 0; length < 4; length++ {
						for _, memory := range []bool{false, true} {
							for _, control := range []bool{false, true} {
								if member < 2 && length == 3 && (memory || !control) || member >= 2 && memory && control {
									continue
								}
								for _, zero := range []bool{false, true} {
									name := fmt.Sprintf("conversion%d", count)
									asm, declaration := x86FP16ConversionResultFixture(name, target.arch, member, length, memory, control, zero)
									encodings[name] = x86RawFP16ObjectEncoding{
										code:          x86FP16ConversionResultEncoding(member, length, memory, control, zero),
										lengthIgnored: member >= 2 && (!control || member%2 == 0) || member == 0 && !memory && control,
										maskMove:      "kmovw",
									}
									source.WriteString(asm)
									declarations.WriteString(declaration)
									count++
								}
							}
						}
					}
				}
				if count != 74 {
					t.Fatal("incomplete conversion controls, LLIG, masks or source axes", count)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized complete raw conversion family", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "asm sideeffect") != count {
							t.Fatal("conversion lost its original MXCSR/exception effect", api)
						}
						for member, op := range x86FP16ConversionResultNames {
							if member%2 != batch {
								continue
							}
							if !strings.Contains(text, strings.ToLower(op)+" ") {
								t.Fatal("missing original native conversion", api, op)
							}
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86RawFP16CheckObject(t, llc, target.triple, text, level, encodings)
						}
					}
				}
			})
		}
	}
}

func TestX86RawFP16ConversionCannotInventInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for member, op := range x86FP16ConversionResultNames {
			for _, memory := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/memory=%t", arch, op, memory), func(t *testing.T) {
					code := x86RawDisplacementDirectives(x86FP16ConversionResultEncoding(member, 0, memory, false, false))
					bare := "TEXT Value(SB),4,$0-0\n" + code + "RET\n"
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, bare, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void raw conversion borrowed unknown inputs or masks", api, err)
						}
					}
				})
			}
		}
	}
}
