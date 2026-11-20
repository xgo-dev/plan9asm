package plan9asm

import (
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Intel SDM Vol. 2B SQRTPS/PD/SS/SD: VEX.WIG, scalar EVEX.LIG,
// packed EVEX.W0/W1, and physical low-bank masking in both modes.
// Go emits canonical W/L bits, so its named tables cannot witness WIG/LIG.
// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf
func TestX86SqrtRawPhysicalForms(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc required")
	}
	for pp, name := range []string{"VSQRTPS", "VSQRTPD", "VSQRTSS", "VSQRTSD"} {
		for _, mode := range []int{32, 64} {
			decode := decodedX86SameWidthConversionInstruction
			arch, triple := "amd64", "x86_64-unknown-linux-gnu"
			if mode == 32 {
				arch, triple = "386", "i386-unknown-linux-gnu"
			}
			if pp >= 2 {
				decode = decodedX86VEXBinaryFloatInstruction
			}
			check := func(t *testing.T, code []byte, evex bool) Instr {
				t.Helper()
				var input strings.Builder
				for _, value := range code {
					fmt.Fprintf(&input, "0x%02x ", value)
				}
				input.WriteByte('\n')
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				command := exec.CommandContext(ctx, mc, "-triple="+triple, "-disassemble", "-mattr=+avx,+avx512f,+avx512vl")
				command.Stdin = strings.NewReader(input.String())
				output, err := runtimeOracleCombinedOutput(ctx, command)
				if err != nil || strings.Contains(string(output), "warning") || strings.Count(string(output), strings.ToLower(name)) != 1 {
					t.Fatalf("independent LLVM decoding of %x: %v\n%s", code, err, output)
				}
				ins, length, known, err := decode(code, mode)
				if !known || err != nil || length != len(code) {
					t.Fatalf("physical SQRT %x rejected: %v", code, err)
				}
				form, known, err := x86SqrtProperties(ins, arch)
				if !known || err != nil {
					t.Fatal("decoder/typed grammar disagree", err)
				}
				if x86SqrtNativeEVEX(ins, form) != evex {
					t.Fatal("physical encoding generation lost", ins.Raw)
				}
				return ins
			}
			for _, wide := range []bool{false, true} {
				if pp >= 2 && wide {
					continue // Intel documents VEX.L=1 scalar behavior as unpredictable.
				}
				t.Run(fmt.Sprintf("%s/%d/VEX/wide%t", name, mode, wide), func(t *testing.T) {
					code := []byte{0xc4, 0xe1, 0x78 | byte(pp), 0x51, 0xd1}
					if pp >= 2 {
						code[2], code[4] = 0x68|byte(pp), 0xd9
					}
					if wide {
						code[2] |= 4
					}
					control := check(t, code, false)
					code[2] |= 0x80
					actual := check(t, code, false)
					if actual.Op != control.Op || !reflect.DeepEqual(actual.Args, control.Args) {
						t.Fatal("WIG changed operands")
					}
				})
			}
			for length := byte(0); length < 4; length++ {
				if pp < 2 && length == 3 {
					continue // Packed LL=3 remains reserved without embedded rounding.
				}
				for _, mask := range []byte{0, 1, 0x81} {
					for _, memory := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%d/EVEX/LL%d/mask%x/memory%t", name, mode, length, mask, memory), func(t *testing.T) {
							code := []byte{0x62, 0xf1, 0x7c | byte(pp), 0x08 | length<<5 | mask, 0x51, 0xd1}
							if pp >= 2 {
								code[2], code[5] = 0x6c|byte(pp), 0xd9
								if memory {
									code[5] = 0x18 // (AX), upper X2, destination X3.
								}
							} else if memory {
								code[5] = 0x10 // (AX), destination X/Y/Z2.
							}
							if pp&1 != 0 {
								code[2] |= 0x80
							}
							check(t, code, true)
						})
					}
				}
			}
		}
	}
}

func TestX86SqrtRawReservedFieldsStayRejected(t *testing.T) {
	for pp := byte(0); pp < 4; pp++ {
		for _, mode := range []int{32, 64} {
			decode := decodedX86SameWidthConversionInstruction
			code := []byte{0x62, 0xf1, 0x7c | pp, 0x08, 0x51, 0xd1}
			if pp >= 2 {
				decode = decodedX86VEXBinaryFloatInstruction
				code[2], code[5] = 0x6c|pp, 0xd9
			}
			if pp&1 != 0 {
				code[2] |= 0x80
			}
			mutations := map[string]func([]byte){
				"wrong-W":      func(b []byte) { b[2] ^= 0x80 },
				"fixed-bit":    func(b []byte) { b[2] &^= 4 },
				"zero-no-mask": func(b []byte) { b[3] |= 0x80 },
			}
			if pp < 2 {
				mutations["packed-LL3"] = func(b []byte) { b[3] |= 0x60 }
				mutations["packed-vvvv"] = func(b []byte) { b[2] &^= 8 }
			} else {
				mutations["scalar-broadcast"] = func(b []byte) { b[3] |= 0x10; b[5] = 0x18 }
			}
			if mode == 32 {
				mutations["high-bank"] = func(b []byte) { b[1] &^= 0x10 }
			}
			for name, edit := range mutations {
				t.Run(fmt.Sprintf("pp%d/mode%d/%s", pp, mode, name), func(t *testing.T) {
					changed := append([]byte(nil), code...)
					edit(changed)
					if _, _, known, err := decode(changed, mode); !known || err == nil {
						t.Fatal("reserved encoding acquired semantics", changed, known, err)
					}
				})
			}
			for length := 0; length < len(code); length++ {
				if _, _, known, err := decode(code[:length], mode); known && err == nil {
					t.Fatal("truncated encoding accepted", code[:length])
				}
			}
			if pp >= 2 {
				if _, _, known, err := decode([]byte{0xc4, 0xe1, 0x6c | pp, 0x51, 0xd9}, mode); !known || err == nil {
					t.Fatal("unpredictable scalar VEX.L1 acquired L0 semantics")
				}
			}
		}
	}
}
