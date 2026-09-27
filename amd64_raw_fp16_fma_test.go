package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Intel AVX512-FP16 specification, sections 5.44-5.49: MAP6.66.W0,
// packed X/Y/Z and scalar LLIG, with the same opcode/order axes as FMA3.
// Go 1.27 has no named PH/SH FMA forms, so these are raw encodings only.
func rawFP16FMAOps() map[byte]Op {
	ops := make(map[byte]Op)
	for orderIndex, order := range []int{132, 213, 231} {
		for familyIndex, family := range []string{"VFMADD", "VFMSUB", "VFNMADD", "VFNMSUB"} {
			for scalarIndex, suffix := range []string{"PH", "SH"} {
				opcode := byte(0x98 + orderIndex*16 + familyIndex*2 + scalarIndex)
				ops[opcode] = Op(fmt.Sprintf("%s%d%s", family, order, suffix))
			}
		}
		ops[byte(0x96+orderIndex*16)] = Op(fmt.Sprintf("VFMADDSUB%dPH", order))
		ops[byte(0x97+orderIndex*16)] = Op(fmt.Sprintf("VFMSUBADD%dPH", order))
	}
	return ops
}

func encodeRawFP16FMA(opcode, length byte, source1, source2, destination, mask int, memory, control, zero bool) []byte {
	code := encodeX86EVEXFMA3(opcode, false, length, control, zero, mask, destination, source1, source2)
	code[1] = code[1]&^byte(15) | 6
	if memory {
		// Keep register extension tests independent of memory base extensions.
		code[1] |= 0x60
		code[5] = byte(0x40 | (destination&7)<<3)
		code = append(code, 1)
	}
	return code
}

func TestDecodeRawFP16FMAGoATReproduction(t *testing.T) {
	for _, tc := range []struct {
		code []byte
		op   Op
	}{
		{[]byte{0x62, 0xb6, 0x7d, 0x48, 0xa8, 0x24, 0x4a}, "VFMADD213PH"},
		{[]byte{0x62, 0xf6, 0x7d, 0x48, 0x98, 0x0e}, "VFMADD132PH"},
		{[]byte{0x62, 0xb6, 0x7d, 0x08, 0x99, 0x0c, 0x76}, "VFMADD132SH"},
	} {
		got, err := decodeX86RawDirectiveGroup(tc.code, 64, 0, "GoAT FP16 FMA", map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Op != tc.op || !got[0].x86Encoded {
			t.Fatalf("%x decoded as %+v, want raw %s", tc.code, got, tc.op)
		}
	}
}

func TestDecodeRawFP16FMACompleteFormats(t *testing.T) {
	for opcode, base := range rawFP16FMAOps() {
		scalar := strings.HasSuffix(string(base), "SH")
		for length := byte(0); length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if scalar && memory && control || !scalar && length == 3 && (!control || memory) {
						continue
					}
					for _, mask := range []int{0, 1, 7} {
						for _, zero := range []bool{false, true} {
							if zero && mask == 0 {
								continue
							}
							code := encodeRawFP16FMA(opcode, length, 20, 21, 22, mask, memory, control, zero)
							got, size, ok, err := decodedX86VEXFMA3Instruction(code, 64)
							if err != nil || !ok || size != len(code) {
								t.Fatalf("%x: got %+v, size=%d, ok=%v, err=%v", code, got, size, ok, err)
							}
							want := base
							prefix, width := "X", 16
							if !scalar {
								vl := length
								if control && !memory {
									vl = 2
								}
								prefix, width = [...]string{"X", "Y", "Z"}[vl], 16<<vl
							}
							if control {
								if memory {
									want += ".BCST"
								} else {
									want += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[length]
								}
							}
							if zero {
								want += ".Z"
							}
							if got.Op != want || !got.x86Encoded || got.Args[1].String() != prefix+"20" ||
								got.Args[len(got.Args)-1].String() != prefix+"22" {
								t.Fatalf("%x: got %+v, want %s with %s20 and %s22", code, got, want, prefix, prefix)
							}
							if memory {
								if scalar || control {
									width = 2
								}
								if got.Args[0].String() != fmt.Sprintf("%d(AX)", width) {
									t.Fatalf("%x: wrong compressed displacement: %+v", code, got)
								}
							} else if got.Args[0].String() != prefix+"21" {
								t.Fatalf("%x: wrong register source: %+v", code, got)
							}
							if mask != 0 && got.Args[2].String() != fmt.Sprintf("K%d", mask) {
								t.Fatalf("%x: wrong mask: %+v", code, got)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodeRawFP16FMAInvalidFormats(t *testing.T) {
	valid := encodeRawFP16FMA(0x98, 0, 1, 2, 3, 1, false, false, false)
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong-w": func(code []byte) []byte {
			code[2] |= 0x80
			return code
		},
		"wrong-pp": func(code []byte) []byte {
			code[2] &^= 3
			return code
		},
		"fixed-bit": func(code []byte) []byte {
			code[2] &^= 4
			return code
		},
		"zero-k0": func(code []byte) []byte {
			code[3] = code[3]&^7 | 0x80
			return code
		},
		"packed-vl3": func(code []byte) []byte {
			code[3] |= 0x60
			return code
		},
		"scalar-broadcast": func(code []byte) []byte {
			code[3] |= 0x10
			code[4], code[5] = 0x99, 0x18
			return code
		},
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, _, ok, err := decodedX86VEXFMA3Instruction(code, 64); !ok || err == nil {
				t.Fatalf("accepted invalid %x: matched=%v, err=%v", code, ok, err)
			}
		})
	}
	for _, mode := range []int{32, 64} {
		for end := 1; end < len(valid); end++ {
			if _, err := decodeX86RawDirectiveGroup(valid[:end], mode, 0, "truncated FP16 FMA", map[string]bool{}); err == nil {
				t.Fatalf("accepted truncated %x in mode %d", valid[:end], mode)
			}
		}
	}
}

func TestDecodeRawFP16FMARIPLiteral(t *testing.T) {
	for _, opcode := range []byte{0x98, 0x99} {
		for _, broadcast := range []bool{false, true} {
			if opcode == 0x99 && broadcast {
				continue
			}
			code := encodeRawFP16FMA(opcode, 1, 1, 0, 2, 1, false, broadcast, true)
			code[5] = 0x15
			code = append(code, 1, 0, 0, 0, 0xc3)
			width := 32
			if opcode == 0x99 || broadcast {
				width = 2
			}
			for index := 0; index < width; index++ {
				code = append(code, byte(index+1))
			}
			got, err := decodeX86RawDirectiveGroup(code, 64, 0, "FP16 FMA RIP literal", map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].Args[0].Kind != OpSym || !got[0].x86RIPLiteral || got[1].Op != OpRET {
				t.Fatalf("decoded %x as %+v, want source-local literal and RET", code, got)
			}
		}
	}
}

func TestTranslateRawFP16FMALLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch   string
		triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawHalfFMA(SB),4,$0-0\n")
			for opcode, op := range rawFP16FMAOps() {
				scalar := strings.HasSuffix(string(op), "SH")
				for length := byte(0); length < 4; length++ {
					for _, memory := range []bool{false, true} {
						for _, control := range []bool{false, true} {
							if scalar && memory && control || !scalar && length == 3 && (!control || memory) {
								continue
							}
							code := encodeRawFP16FMA(opcode, length, 1, 2, 3, 1, memory, control, true)
							for _, value := range code {
								fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
							}
						}
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawHalfFMA": {Name: "rawHalfFMA", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.fma.f16", "@llvm.fma.v8f16", "@llvm.fma.v16f16", "@llvm.fma.v32f16",
				"@llvm.experimental.constrained.fma.f16", "@llvm.masked.load.v8i16", "phi i16", "+avx512fp16"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-half-fma.ll", "raw-half-fma.o", ir)
		})
	}
}

func TestRawFP16FMARejectsNamedGoForms(t *testing.T) {
	for _, op := range rawFP16FMAOps() {
		source := fmt.Sprintf("TEXT namedHalfFMA(SB),4,$0-0\n\t%s X0, X1, X2\n\tRET\n", op)
		requireX86GoAssemblerResult(t, "amd64", source, false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"namedHalfFMA": {Name: "namedHalfFMA", Ret: Void}},
		}); err == nil {
			t.Fatalf("accepted %s absent from Go's named assembler table", op)
		}
	}
}
