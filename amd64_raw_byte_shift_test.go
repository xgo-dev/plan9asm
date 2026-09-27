package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVectorByteShift(left, evex bool, width, source, destination int, imm byte) []byte {
	extension := 3
	if left {
		extension = 7
	}
	vectorBits := map[int]int{16: 0, 32: 1, 64: 2}[width]
	var code []byte
	if evex {
		code = encodeX86EVEXPackedWordMultiply(1, 0x73, vectorBits, 0, false, false, extension, destination, source)
	} else {
		code = encodeX86VEXPackedWordMultiply(1, 0x73, width == 32, false, extension, destination, source)
	}
	code[len(code)-1] = byte(0xc0 | extension<<3 | source&7)
	return append(code, imm)
}

func TestDecodedX86RawVectorByteShiftCompleteFamily(t *testing.T) {
	for _, left := range []bool{false, true} {
		for _, evex := range []bool{false, true} {
			widths := []int{16, 32}
			if evex {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				registers := []int{0, 7, 8, 15}
				if evex {
					registers = append(registers, 16, 31)
				}
				for _, register := range registers {
					name := fmt.Sprintf("left%t/evex%t/%d/reg%d", left, evex, width, register)
					t.Run(name, func(t *testing.T) {
						code := encodeX86RawVectorByteShift(left, evex, width, register, register, 15)
						got, length, matched, err := decodedX86RawVectorByteShiftInstruction(code, 64)
						want := Op("VPSRLDQ")
						if left {
							want = "VPSLLDQ"
						}
						widthName := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
						if err != nil || !matched || length != len(code) || got.Op != want ||
							len(got.Args) != 3 || got.Args[0].Imm != 15 ||
							got.Args[1].String() != fmt.Sprintf("%s%d", widthName, register) ||
							got.Args[2].String() != fmt.Sprintf("%s%d", widthName, register) {
							t.Fatalf("decode %x = %+v length=%d matched=%t err=%v", code, got, length, matched, err)
						}
					})
				}
			}
		}
	}
	// Real bytes from simd@v1.21.1 reduce_avx2_amd64.s.
	real := []byte{0xc5, 0xf9, 0x73, 0xf8, 0x0f}
	got, length, matched, err := decodedX86RawVectorByteShiftInstruction(real, 64)
	if err != nil || !matched || length != len(real) || got.Op != "VPSLLDQ" ||
		got.Args[1].String() != "X0" || got.Args[2].String() != "X0" {
		t.Fatalf("decode real VPSLLDQ %x = %+v length=%d matched=%t err=%v", real, got, length, matched, err)
	}
}

func TestDecodedX86RawVectorByteShiftRejectsInvalidForms(t *testing.T) {
	valid := encodeX86RawVectorByteShift(true, false, 16, 0, 0, 15)
	for name, edit := range map[string]func([]byte) []byte{
		"W1":               func(b []byte) []byte { b[2] |= 0x80; return b },
		"truncated imm8":   func(b []byte) []byte { return b[:len(b)-1] },
		"address override": func(b []byte) []byte { return append([]byte{0x67}, b...) },
		"wrong group":      func(b []byte) []byte { b[len(b)-2] &^= 0x38; return b },
	} {
		t.Run(name, func(t *testing.T) {
			bad := edit(append([]byte(nil), valid...))
			if _, _, matched, err := decodedX86RawVectorByteShiftInstruction(bad, 64); matched && err == nil {
				t.Fatalf("accepted invalid byte shift %x", bad)
			}
		})
	}
}

func TestTranslateX86RawVectorByteShiftObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, code := range [][]byte{
		encodeX86RawVectorByteShift(true, false, 16, 0, 0, 15),
		encodeX86RawVectorByteShift(false, false, 32, 7, 7, 3),
		encodeX86RawVectorByteShift(true, true, 64, 17, 19, 255),
	} {
		name := fmt.Sprintf("rawByteShift%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range append(code, 0xc3) {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-byte-shift.ll", "raw-byte-shift.o", ir)
		})
	}
}

func x86RawVectorByteShiftConstant(left bool, width int) []byte {
	code := encodeX86RawVectorByteShift(left, true, width, 0, 0, 15)
	code[len(code)-2] = code[len(code)-2]&0x38 | 0x05
	imm := code[len(code)-1]
	code = append(code[:len(code)-1], 1, 0, 0, 0, imm, 0xc3)
	for i := 0; i < width; i++ {
		code = append(code, byte(i*19+9))
	}
	return code
}

func TestDecodeX86RawVectorByteShiftConstantCompleteFamily(t *testing.T) {
	for _, left := range []bool{false, true} {
		for _, width := range []int{16, 32, 64} {
			name := fmt.Sprintf("left%t/%d", left, width)
			t.Run(name, func(t *testing.T) {
				code := x86RawVectorByteShiftConstant(left, width)
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got[0].Args[1].Kind != OpSym || !got[0].x86RIPLiteral || got[1].Op != OpRET {
					t.Fatalf("decoded %x as %#v, want source-local byte-shift data", code, got)
				}
			})
		}
	}
}

func TestDecodeX86RawVectorByteShiftConstantRejectsUnsafeSources(t *testing.T) {
	valid := x86RawVectorByteShiftConstant(true, 64)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(code []byte) []byte { return code[:len(code)-1] },
		"overlap": func(code []byte) []byte {
			code[6] = 0
			return code
		},
		"outside": func(code []byte) []byte {
			code[6] = 127
			return code
		},
		"segment": func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address": func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe byte-shift RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawVectorByteShiftConstantObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, width := range []int{16, 32, 64} {
		code := x86RawVectorByteShiftConstant(index%2 == 0, width)
		name := fmt.Sprintf("rawByteShiftConstant%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-byte-shift-constant.ll", "raw-byte-shift-constant.o", ir)
		})
	}
}
