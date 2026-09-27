package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent Intel AVX512-FP16 sections 5.18, 5.19, 5.21 and 5.24 rows.
var fp16ScalarConversionCases = []struct {
	op                  Op
	mapNumber, pp, code byte
	inputBits, outBits  int
	w                   bool
}{
	{"VCVTSH2SS", 6, 0, 0x13, 16, 32, false},
	{"VCVTSS2SH", 5, 0, 0x1d, 32, 16, false},
	{"VCVTSH2SD", 5, 2, 0x5a, 16, 64, false},
	{"VCVTSD2SH", 5, 3, 0x5a, 64, 16, true},
}

func rawFP16ScalarConversion(index, length, source1, source2, destination, mask int, memory, control, zero bool) []byte {
	tc := fp16ScalarConversionCases[index]
	code := encodeX86EVEXFMA3(tc.code, tc.w, byte(length), control, zero, mask, destination, source1, source2)
	code[1] = code[1]&0xf0 | tc.mapNumber
	code[2] = code[2]&^3 | tc.pp
	if memory {
		code[1] |= 0x60
		code[5] = 0x40 | byte(destination&7)<<3
		code = append(code, 1)
	}
	return code
}

func TestRawFP16ScalarConversionFormats(t *testing.T) {
	for index, tc := range fp16ScalarConversionCases {
		for length := 0; length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, control := range []bool{false, true} {
					if control && memory {
						continue
					}
					for _, mask := range []int{0, 1, 7} {
						for _, zero := range []bool{false, true} {
							if zero && mask == 0 {
								continue
							}
							code := rawFP16ScalarConversion(index, length, 20, 21, 22, mask, memory, control, zero)
							got, err := decodeX86RawDirectiveGroup(code, 64, 0, "FP16 scalar conversion", map[string]bool{})
							if err != nil || len(got) != 1 || !got[0].x86Encoded {
								t.Fatalf("%x: %+v, err=%v", code, got, err)
							}
							want := tc.op
							if control {
								if tc.inputBits == 16 {
									want += ".SAE"
								} else {
									want += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[length]
								}
							}
							if zero {
								want += ".Z"
							}
							source := "X21"
							if memory {
								source = fmt.Sprintf("%d(AX)", tc.inputBits/8)
							}
							ins := got[0]
							if ins.Op != want || ins.Args[0].String() != source || ins.Args[1].String() != "X20" || ins.Args[len(ins.Args)-1].String() != "X22" {
								t.Fatalf("%x: %+v, want %s %s, X20, [mask], X22", code, ins, want, source)
							}
						}
					}
				}
			}
		}
	}
}

func TestRawFP16ScalarConversionInvalidAndNamedForms(t *testing.T) {
	for index, tc := range fp16ScalarConversionCases {
		for _, change := range []struct {
			index int
			bits  byte
		}{{2, 4}, {2, 0x80}, {3, 0x80}} {
			code := rawFP16ScalarConversion(index, 0, 1, 2, 3, 0, false, false, false)
			code[change.index] ^= change.bits
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid scalar conversion", map[string]bool{}); err == nil {
				t.Fatalf("accepted reserved %x", code)
			}
		}
		code := rawFP16ScalarConversion(index, 0, 1, 2, 3, 0, true, true, false)
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid scalar broadcast", map[string]bool{}); err == nil {
			t.Fatalf("accepted scalar broadcast %x", code)
		}
		for operand := 0; operand < 3; operand++ {
			registers := [3]int{1, 2, 3}
			registers[operand] = 8
			code := rawFP16ScalarConversion(index, 0, registers[0], registers[1], registers[2], 1, false, false, false)
			if _, err := decodeX86RawDirectiveGroup(code, 32, 0, "386 high scalar conversion", map[string]bool{}); err == nil {
				t.Fatalf("accepted 386 extended register %x", code)
			}
		}
		source := "TEXT namedScalarHalf(SB),4,$0-0\n" + string(tc.op) + " X0, X1, X2\nRET\n"
		requireX86GoAssemblerResult(t, "amd64", source, false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"namedScalarHalf": {Name: "namedScalarHalf", Ret: Void}},
		}); err == nil {
			t.Fatalf("accepted named %s", tc.op)
		}
	}
}

func TestRawFP16ScalarConversionLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawScalarHalf(SB),4,$0-0\n")
	for index := range fp16ScalarConversionCases {
		for length := 0; length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, mask := range []int{0, 1} {
					for _, b := range rawFP16ScalarConversion(index, length, 1, 2, 3, mask, memory, !memory, mask != 0) {
						fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
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
				Sigs: map[string]FuncSig{"rawScalarHalf": {Name: "rawScalarHalf", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scalar-half.ll", "raw-scalar-half.o", ir)
		})
	}
}

func TestRawFP16ScalarConversionRIPLiteral(t *testing.T) {
	for index, tc := range fp16ScalarConversionCases {
		code := rawFP16ScalarConversion(index, 3, 1, 0, 0, 1, false, false, true)
		code[5] = 5
		code = append(code, 1, 0, 0, 0, 0xc3)
		code = append(code, make([]byte, tc.inputBits/8)...)
		got, err := decodeX86RawDirectiveGroup(code, 64, 0, "scalar FP16 literal", map[string]bool{})
		if err != nil || len(got) != 2 || !got[0].x86RIPLiteral || got[0].Args[0].Kind != OpSym {
			t.Fatalf("%x: %+v, err=%v", code, got, err)
		}
		if _, err := decodeX86RawDirectiveGroup(code[:len(code)-1], 64, 0, "truncated scalar FP16 literal", map[string]bool{}); err == nil {
			t.Fatal("accepted truncated constant pool")
		}
	}
}
