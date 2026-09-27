package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var rawFP16ScalarBinaryOpcodes = map[byte]Op{
	0x51: "VSQRTSH",
	0x58: "VADDSH",
	0x59: "VMULSH",
	0x5c: "VSUBSH",
	0x5d: "VMINSH",
	0x5e: "VDIVSH",
	0x5f: "VMAXSH",
}

func encodeRawFP16ScalarBinary(opcode, length byte, source1, source2, destination, mask int, memory, control, zero bool) []byte {
	code := encodeX86EVEXBinaryFloat(opcode, 2, length, control, zero, mask, destination, source1, source2)
	code[1] = code[1]&^byte(15) | 5
	if memory {
		code[5] = byte(0x40 | (destination&7)<<3)
		code = append(code, 1)
	}
	return code
}

func TestDecodeRawFP16ScalarBinaryGoATReproduction(t *testing.T) {
	// VADDSH (SI)(CX*2), X0, X0 from go-highway's GoAT output.
	code := []byte{0x62, 0xf5, 0x7e, 0x08, 0x58, 0x04, 0x4e}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "GoAT VADDSH", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VADDSH" || !decoded[0].x86Encoded {
		t.Fatalf("decoded %#v, want one raw VADDSH", decoded)
	}
}

func TestDecodeRawFP16ScalarBinaryCompleteForms(t *testing.T) {
	for opcode, baseOp := range rawFP16ScalarBinaryOpcodes {
		for length := byte(0); length < 4; length++ {
			for _, memory := range []bool{false, true} {
				for _, mask := range []int{0, 1, 7} {
					for _, zero := range []bool{false, true} {
						if zero && mask == 0 {
							continue
						}
						for _, control := range []bool{false, true} {
							if control && memory {
								continue
							}
							code := encodeRawFP16ScalarBinary(opcode, length, 20, 21, 22, mask, memory, control, zero)
							got, size, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
							if err != nil || !ok || size != len(code) {
								t.Fatalf("%x: got %+v, size=%d, ok=%v, err=%v", code, got, size, ok, err)
							}
							wantOp := baseOp
							if control {
								if opcode == 0x5d || opcode == 0x5f {
									wantOp += ".SAE"
								} else {
									wantOp += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[length]
								}
							}
							if zero {
								wantOp += ".Z"
							}
							if got.Op != wantOp || !got.x86Encoded || got.Args[1].String() != "X20" ||
								got.Args[len(got.Args)-1].String() != "X22" {
								t.Fatalf("%x: got %+v, want %s with X20 and X22", code, got, wantOp)
							}
							if memory && got.Args[0].Kind != OpMem || !memory && got.Args[0].String() != "X21" {
								t.Fatalf("%x: wrong source %+v", code, got)
							}
							if mask != 0 && (len(got.Args) != 4 || got.Args[2].String() != fmt.Sprintf("K%d", mask)) {
								t.Fatalf("%x: wrong mask %+v", code, got)
							}
						}
					}
				}
			}
		}
	}
}

func TestDecodeRawFP16ScalarBinaryInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"wrong-width", []byte{0x62, 0xf5, 0xfe, 0x08, 0x58, 0xc0}, 64},
		{"missing-fixed", []byte{0x62, 0xf5, 0x7a, 0x08, 0x58, 0xc0}, 64},
		{"zero-k0", []byte{0x62, 0xf5, 0x7e, 0x88, 0x58, 0xc0}, 64},
		{"memory-rounding", []byte{0x62, 0xf5, 0x7e, 0x18, 0x58, 0x00}, 64},
		{"386-high-register", []byte{0x62, 0x75, 0x7e, 0x08, 0x58, 0xc0}, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok, err := decodedX86VEXBinaryFloatInstruction(tc.code, tc.mode); !ok || err == nil {
				t.Fatalf("invalid %x: matched=%v, err=%v", tc.code, ok, err)
			}
		})
	}
}

func TestDecodeRawFP16BinaryRIPLiteral(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      []byte
		dataWidth int
		want      Op
	}{
		{"scalar", encodeRawFP16ScalarBinary(0x58, 0, 1, 0, 2, 0, false, false, false), 2, "VADDSH"},
		{"packed", encodeRawFP16Binary(0x58, 0, 1, 0, 2, 0, false, false, false), 16, "VADDPH"},
		{"broadcast", encodeRawFP16Binary(0x58, 1, 1, 0, 2, 0, false, true, false), 2, "VADDPH.BCST"},
		{"sqrt-scalar", encodeRawFP16ScalarBinary(0x51, 0, 1, 0, 2, 0, false, false, false), 2, "VSQRTSH"},
		{"sqrt-packed", rawFP16PackedSqrt(0, 0, 2, 0, false, false, false), 16, "VSQRTPH"},
		{"sqrt-broadcast", rawFP16PackedSqrt(1, 0, 2, 0, false, true, false), 2, "VSQRTPH.BCST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := append([]byte(nil), tc.code...)
			code[5] = 0x15
			code = append(code, 1, 0, 0, 0, 0xc3)
			for index := 0; index < tc.dataWidth; index++ {
				code = append(code, byte(index+1))
			}
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, tc.name, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != 2 || decoded[0].Op != tc.want ||
				decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
				decoded[1].Op != OpRET {
				t.Fatalf("decoded %x as %#v, want %s source-local FP16 literal", code, decoded, tc.want)
			}
		})
	}
}

func TestTranslateRawFP16ScalarBinaryLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
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
			source.WriteString("TEXT rawFP16ScalarBinary(SB),4,$0-0\n")
			for opcode := range rawFP16ScalarBinaryOpcodes {
				for _, memory := range []bool{false, true} {
					code := encodeRawFP16ScalarBinary(opcode, 2, 1, 2, 3, 1, memory, !memory, true)
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawFP16ScalarBinary": {Name: "rawFP16ScalarBinary", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fadd half", "fsub half", "fmul half", "fdiv half", "load i16", "_scalar_load", "phi i16"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-fp16-scalar-binary.ll", "raw-fp16-scalar-binary.o", ir)
		})
	}
}

func TestRawFP16ScalarRejectsNamedGoForms(t *testing.T) {
	for _, op := range []Op{"VMOVSH", "VADDSH", "VSUBSH", "VMULSH", "VDIVSH", "VMINSH", "VMAXSH", "VSQRTSH"} {
		t.Run(string(op), func(t *testing.T) {
			source := fmt.Sprintf("TEXT namedHalf(SB),4,$0-0\n\t%s X0, X1, X2\n\tRET\n", op)
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"namedHalf": {Name: "namedHalf", Ret: Void}},
			}); err == nil {
				t.Fatal("accepted FP16 mnemonic absent from Go's named assembler table")
			}
		})
	}
}
