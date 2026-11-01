package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86FP16BinaryResultEncoding(opcode, length byte, scalar, memory, control bool, mask int) []byte {
	encode := encodeRawFP16Binary
	if scalar {
		encode = encodeRawFP16ScalarBinary
	}
	code := encode(opcode, length, 2, 1, 0, 1, memory, control, mask == 2)
	if memory {
		code[len(code)-1] = 0
	}
	if mask == 0 {
		code[3] &^= 7
	}
	return code
}

// Independent MAP5 opcode/control matrix: six operations, packed and scalar.
// MIN/MAX use SAE (LL ignored), whereas arithmetic has four rounding modes.
func x86FP16BinaryResultFixtures(t *testing.T, arch string, scalar bool, batch int) (string, string, map[string]x86RawFP16ObjectEncoding) {
	t.Helper()
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	encodings := make(map[string]x86RawFP16ObjectEncoding)
	variants := 0
	for _, opcode := range []byte{0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f} {
		for length := byte(0); length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if scalar && memory && control || !scalar && length == 3 && (memory || !control) {
						continue
					}
					for mask := 0; mask < 3; mask++ {
						selected := variants%3 == batch
						variants++
						if !selected {
							continue
						}
						name := fmt.Sprintf("halfBinary%d", len(encodings))
						maskMove := "kmovw"
						if !scalar && (length == 2 || !memory && control) {
							maskMove = "kmovd"
						}
						if mask == 0 {
							maskMove = ""
						}
						encodings[name] = x86RawFP16ObjectEncoding{
							code:          x86FP16BinaryResultEncoding(opcode, length, scalar, memory, control, mask),
							lengthIgnored: scalar && !control || (opcode == 0x5d || opcode == 0x5f) && control && !memory,
							maskMove:      maskMove,
						}
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s p+0(FP),AX\n", name, word+4, move)
						source.WriteString("MOVL $1,CX\nKMOVD CX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n")
						source.WriteString(x86RawDisplacementDirectives(encodings[name].code))
						fmt.Fprintf(&source, "MOVL X0,DX\nMOVL DX,ret+%d(FP)\nRET\n", word)
						fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
					}
				}
			}
		}
	}
	want := 234
	if scalar {
		want = 216
	}
	if variants != want || len(encodings) != want/3 {
		t.Fatal("incomplete independent FP16 binary physical partition", variants, len(encodings))
	}
	return source.String(), declarations.String(), encodings
}

func TestX86RawFP16PackedBinaryNativeObjects(t *testing.T) {
	x86FP16BinaryInitializedObjects(t, false)
}

func TestX86RawFP16ScalarBinaryNativeObjects(t *testing.T) {
	x86FP16BinaryInitializedObjects(t, true)
}

func x86FP16BinaryInitializedObjects(t *testing.T, scalar bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for batch := 0; batch < 3; batch++ {
			t.Run(fmt.Sprintf("%s/batch%d", target.triple, batch), func(t *testing.T) {
				source, declarations, encodings := x86FP16BinaryResultFixtures(t, target.arch, scalar, batch)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized complete FP16 binary inputs", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "asm sideeffect") != len(encodings) {
							t.Fatal("FP16 binary lost an original native arithmetic effect", api)
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

func TestX86RawFP16BinaryCannotInventInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, scalar := range []bool{false, true} {
			for opcode := range rawFP16BinaryOpcodes {
				for _, memory := range []bool{false, true} {
					for mask := 0; mask < 3; mask++ {
						t.Run(fmt.Sprintf("%s/%x/scalar%t/memory%t/mask%d", arch, opcode, scalar, memory, mask), func(t *testing.T) {
							code := x86FP16BinaryResultEncoding(opcode, 0, scalar, memory, false, mask)
							source := "TEXT Value(SB),4,$0-0\n" + x86RawDisplacementDirectives(code) + "RET\n"
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("Void FP16 binary invented source, merge or mask inputs", api, err)
								}
							}
						})
					}
				}
			}
		}
	}
}
