package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func rawFP16Conversion(narrow bool, length, mask, destination, source int, memory, control, zero bool) []byte {
	form := x86RawHalfConversionForm{mapNumber: 6, opcode: 0x13}
	if narrow {
		form.mapNumber, form.opcode = 5, 0x1d
	}
	code := encodeX86RawEVEXHalfConversion(form, length, mask, zero, control, destination, source, memory, 0)
	if memory {
		code[len(code)-1] = 1
	}
	return code
}

func TestRawFP16ConversionCompleteFormats(t *testing.T) {
	for _, narrow := range []bool{false, true} {
		for length := 0; length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if length == 3 && (memory || !control) {
						continue
					}
					for _, mask := range []int{0, 1, 7} {
						for _, zero := range []bool{false, true} {
							if zero && mask == 0 {
								continue
							}
							code := rawFP16Conversion(narrow, length, mask, 20, 21, memory, control, zero)
							got, size, ok, err := decodedX86PackedHalfConversionInstruction(code, 64)
							if err != nil || !ok || size != len(code) || !got.x86Encoded {
								t.Fatalf("%x: %+v, size=%d, ok=%v, err=%v", code, got, size, ok, err)
							}
							vl := length
							if control && !memory {
								vl = 2
							}
							wide, short := [...]string{"X", "Y", "Z"}[vl], [...]string{"X", "X", "Y"}[vl]
							src, dst, width := short+"21", wide+"20", 8<<vl
							want := Op("VCVTPH2PSX")
							if narrow {
								want, src, dst, width = "VCVTPS2PHX", wide+"21", short+"20", 16<<vl
							}
							if control {
								if memory {
									want += ".BCST"
									width = 2
									if narrow {
										width = 4
									}
								} else if narrow {
									want += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[length]
								} else {
									want += ".SAE"
								}
							}
							if memory {
								src = fmt.Sprintf("%d(AX)", width)
							}
							if zero {
								want += ".Z"
							}
							if got.Op != want || got.Args[0].String() != src || got.Args[len(got.Args)-1].String() != dst {
								t.Fatalf("%x: got %+v, want %s %s -> %s", code, got, want, src, dst)
							}
						}
					}
				}
			}
		}
	}
}

func TestRawFP16ConversionInvalidFormats(t *testing.T) {
	for _, narrow := range []bool{false, true} {
		for _, change := range []struct {
			index int
			bits  byte
		}{
			{2, 0x80}, {2, 0x04}, {2, 0x08}, {3, 0x08}, {3, 0x80}, {3, 0x60},
		} {
			code := rawFP16Conversion(narrow, 0, 0, 0, 1, false, false, false)
			code[change.index] ^= change.bits
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid FP16 conversion", map[string]bool{}); err == nil {
				t.Fatalf("accepted reserved encoding %x", code)
			}
		}
		for _, code := range [][]byte{
			rawFP16Conversion(narrow, 0, 0, 8, 1, false, false, false),
			rawFP16Conversion(narrow, 0, 0, 1, 8, false, false, false),
		} {
			if _, err := decodeX86RawDirectiveGroup(code, 32, 0, "386 high FP16 conversion", map[string]bool{}); err == nil {
				t.Fatalf("accepted extended register %x", code)
			}
		}
	}
}

func TestRawFP16ConversionLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawFP16Conversion(SB),4,$0-0\n")
	for _, narrow := range []bool{false, true} {
		for length := 0; length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if length == 3 && (memory || !control) {
						continue
					}
					for _, mask := range []int{0, 1} {
						for _, b := range rawFP16Conversion(narrow, length, mask, 1, 2, memory, control, mask != 0) {
							fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
						}
					}
				}
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawFP16Conversion": {Name: "rawFP16Conversion", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fpext <4 x half>", "fptrunc <4 x float>", "fcmp olt <16 x float>", "fcmp ogt <16 x float>",
				"@llvm.masked.load.v4i16", "@llvm.masked.load.v4i32", "phi i16", "phi i32", "+avx512fp16", "+avx512vl"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-fp16-conversion.ll", "raw-fp16-conversion.o", ir)
		})
	}
}

func TestRawFP16ConversionRIPAndNamedForms(t *testing.T) {
	for _, narrow := range []bool{false, true} {
		for length := 0; length < 3; length++ {
			for _, broadcast := range []bool{false, true} {
				code := rawFP16Conversion(narrow, length, 1, 0, 0, false, broadcast, true)
				code[5] = 5
				code = append(code, 1, 0, 0, 0, 0xc3)
				width := 8 << length
				if broadcast {
					width = 2
				}
				if narrow {
					width *= 2
				}
				code = append(code, make([]byte, width)...)
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, "FP16 conversion literal", map[string]bool{})
				if err != nil || len(got) != 2 || !got[0].x86RIPLiteral || got[0].Args[0].Kind != OpSym {
					t.Fatalf("%x: %+v, err=%v", code, got, err)
				}
				if _, err := decodeX86RawDirectiveGroup(code[:len(code)-1], 64, 0, "truncated FP16 pool", map[string]bool{}); err == nil {
					t.Fatal("accepted truncated constant pool")
				}
			}
		}
	}
	for _, op := range []string{"VCVTPH2PSX", "VCVTPS2PHX"} {
		source := "TEXT namedFP16Conversion(SB),4,$0-0\n" + op + " X0, X1\nRET\n"
		requireX86GoAssemblerResult(t, "amd64", source, false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"namedFP16Conversion": {Name: "namedFP16Conversion", Ret: Void}},
		}); err == nil {
			t.Fatalf("accepted named %s", op)
		}
	}
}
