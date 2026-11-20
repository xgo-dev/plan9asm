package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Intel FP16 sections 5.44-5.49: all 30 multiply-add names, three orders,
// packed/scalar forms, memory/broadcast, LLIG and all four rounding controls.
// https://cdrdv2-public.intel.com/678970/intel-avx512-fp16.pdf
func x86FP16FMAResultEncoding(opcode, length byte, memory, control, zero bool) []byte {
	code := encodeRawFP16FMA(opcode, length, 2, 1, 0, 1, memory, control, zero)
	if memory {
		code[len(code)-1] = 0
	}
	return code
}

func x86FP16FMAResultFixtures(t *testing.T, arch string, order, batch int) (string, string, map[string]x86RawFP16ObjectEncoding) {
	t.Helper()
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	encodings := make(map[string]x86RawFP16ObjectEncoding)
	variants := 0
	ops := rawFP16FMAOps()
	if len(ops) != 30 {
		t.Fatal("incomplete independent FP16 FMA family", len(ops))
	}
	for _, opcode := range x86FMA3Opcodes() {
		if int(opcode>>4)-9 != order {
			continue
		}
		scalar := strings.HasSuffix(string(ops[opcode]), "SH")
		for length := byte(0); length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if scalar && memory && control || !scalar && length == 3 && (memory || !control) {
						continue
					}
					for _, masked := range []bool{false, true} {
						for _, zero := range []bool{false, true} {
							if zero && !masked {
								continue
							}
							selected := variants%6 == batch
							variants++
							if !selected {
								continue
							}
							name := fmt.Sprintf("halfFMA%d", len(encodings))
							maskMove := "kmovw"
							if !scalar && (length == 2 || !memory && control) {
								maskMove = "kmovd"
							}
							code := x86FP16FMAResultEncoding(opcode, length, memory, control, zero)
							if !masked {
								code[3] &^= 7
								maskMove = ""
							}
							encodings[name] = x86RawFP16ObjectEncoding{
								code: code, lengthIgnored: scalar && !control, maskMove: maskMove,
							}
							fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s p+0(FP),AX\n", name, word+4, move)
							source.WriteString("MOVL $1,CX\nKMOVD CX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n")
							source.WriteString(x86RawDisplacementDirectives(code))
							fmt.Fprintf(&source, "MOVL X0,DX\nMOVL DX,ret+%d(FP)\nRET\n", word)
							fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
						}
					}
				}
			}
		}
	}
	if variants != 378 || len(encodings) != 63 {
		t.Fatal("incomplete independent FP16 FMA physical partition", variants, len(encodings))
	}
	return source.String(), declarations.String(), encodings
}

func TestX86RawFP16FMA132NativeObjects(t *testing.T) { x86FP16FMAInitializedObjects(t, 0) }
func TestX86RawFP16FMA213NativeObjects(t *testing.T) { x86FP16FMAInitializedObjects(t, 1) }
func TestX86RawFP16FMA231NativeObjects(t *testing.T) { x86FP16FMAInitializedObjects(t, 2) }

func x86FP16FMAInitializedObjects(t *testing.T, order int) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for batch := 0; batch < 6; batch++ {
			t.Run(fmt.Sprintf("%s/batch%d", target.triple, batch), func(t *testing.T) {
				source, declarations, encodings := x86FP16FMAResultFixtures(t, target.arch, order, batch)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized complete FP16 FMA inputs", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "asm sideeffect") != 63 {
							t.Fatal("FP16 FMA lost an original native arithmetic effect", api)
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

func TestX86RawFP16FMACannotInventInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for opcode, op := range rawFP16FMAOps() {
			for _, memory := range []bool{false, true} {
				for _, masked := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/memory%t/masked%t", arch, op, memory, masked), func(t *testing.T) {
						code := x86FP16FMAResultEncoding(opcode, 0, memory, false, masked)
						if !masked {
							code[3] &^= 7
						}
						bare := "TEXT Value(SB),4,$0-0\n" + x86RawDisplacementDirectives(code) + "RET\n"
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, bare, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void FP16 FMA invented source, old destination or mask inputs", api, err)
							}
						}
					})
				}
			}
		}
	}
}
