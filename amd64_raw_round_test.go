package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVEXRound(opcode byte, width256 bool, destination, upper, source int, imm byte) []byte {
	code := encodeX86VEXPackedWordMultiply(3, opcode, width256, false, destination, upper, source)
	return append(code, imm)
}

func TestDecodedX86RawVEXRoundCompleteFamily(t *testing.T) {
	for _, form := range []struct {
		opcode byte
		op     Op
		scalar bool
	}{
		{0x08, "VROUNDPS", false},
		{0x09, "VROUNDPD", false},
		{0x0a, "VROUNDSS", true},
		{0x0b, "VROUNDSD", true},
	} {
		for _, width256 := range []bool{false, true} {
			if form.scalar && width256 {
				continue
			}
			for _, source := range []int{0, 7, 8, 15} {
				for _, imm := range []byte{0, 9, 255} {
					name := fmt.Sprintf("%s/y%t/src%d/imm%d", form.op, width256, source, imm)
					t.Run(name, func(t *testing.T) {
						code := encodeX86RawVEXRound(form.opcode, width256, 11, 3, source, imm)
						if !form.scalar {
							code = encodeX86RawVEXRound(form.opcode, width256, 11, 0, source, imm)
						}
						got, length, matched, err := decodedX86RawVEXRoundInstruction(code, 64)
						if err != nil || !matched || length != len(code) || got.Op != form.op ||
							got.Args[0].Kind != OpImm || got.Args[0].Imm != int64(imm) ||
							got.Args[1].String() != fmt.Sprintf("%s%d", map[bool]string{false: "X", true: "Y"}[width256], source) {
							t.Fatalf("decode %x = %+v length=%d matched=%t err=%v", code, got, length, matched, err)
						}
						if form.scalar && (len(got.Args) != 4 || got.Args[2].String() != "X3") {
							t.Fatalf("scalar upper-lane operand missing: %+v", got)
						}
					})
				}
			}
		}
	}
	// Actual bytes in simd@v1.21.1 arith_avx2_amd64.s.
	real := []byte{0xc4, 0xa3, 0x7d, 0x08, 0x04, 0x86, 0x09}
	got, length, matched, err := decodedX86RawVEXRoundInstruction(real, 64)
	if err != nil || !matched || length != len(real) || got.Op != "VROUNDPS" ||
		got.Args[1].String() != "0(SI)(R8*4)" || got.Args[2].String() != "Y0" {
		t.Fatalf("decode real VROUNDPS %x = %+v length=%d matched=%t err=%v", real, got, length, matched, err)
	}
}

func TestDecodedX86RawVEXRoundRejectsInvalidForms(t *testing.T) {
	packed := encodeX86RawVEXRound(0x08, true, 0, 0, 0, 9)
	scalar := encodeX86RawVEXRound(0x0a, false, 0, 1, 0, 9)
	for name, bad := range map[string][]byte{
		"packed reserved vvvv": func() []byte {
			b := append([]byte(nil), packed...)
			b[2] &^= 0x08
			return b
		}(),
		"scalar L1": func() []byte {
			b := append([]byte(nil), scalar...)
			b[2] |= 0x04
			return b
		}(),
		"W1": func() []byte {
			b := append([]byte(nil), packed...)
			b[2] |= 0x80
			return b
		}(),
		"truncated imm8":   packed[:len(packed)-1],
		"address override": append([]byte{0x67}, packed...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, matched, err := decodedX86RawVEXRoundInstruction(bad, 64); !matched || err == nil {
				t.Fatalf("accepted invalid VROUND %x: matched=%t err=%v", bad, matched, err)
			}
		})
	}
}

func x86RawVEXRoundConstant(opcode byte, width256 bool) []byte {
	code := encodeX86RawVEXRound(opcode, width256, 0, 0, 0, 9)
	code[len(code)-2] = 0x05
	imm := code[len(code)-1]
	code = append(code[:len(code)-1], 1, 0, 0, 0, imm, 0xc3)
	width := 16
	if width256 {
		width = 32
	}
	if opcode == 0x0a {
		width = 4
	} else if opcode == 0x0b {
		width = 8
	}
	for i := 0; i < width; i++ {
		code = append(code, byte(i*17+11))
	}
	return code
}

func TestDecodeX86RawVEXRoundConstantCompleteFamily(t *testing.T) {
	for _, opcode := range []byte{0x08, 0x09, 0x0a, 0x0b} {
		for _, wide := range []bool{false, true} {
			if opcode >= 0x0a && wide {
				continue
			}
			name := fmt.Sprintf("%02x/y%t", opcode, wide)
			t.Run(name, func(t *testing.T) {
				code := x86RawVEXRoundConstant(opcode, wide)
				got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 2 || got[0].Args[1].Kind != OpSym || !got[0].x86RIPLiteral || got[1].Op != OpRET {
					t.Fatalf("decoded %x as %#v, want source-local round constant", code, got)
				}
			})
		}
	}
}

func TestDecodeX86RawVEXRoundConstantRejectsUnsafeSources(t *testing.T) {
	valid := x86RawVEXRoundConstant(0x08, true)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(code []byte) []byte { return code[:len(code)-1] },
		"overlap": func(code []byte) []byte {
			code[5] = 0
			return code
		},
		"outside": func(code []byte) []byte {
			code[5] = 127
			return code
		},
		"segment": func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address": func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe VROUND RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawVEXRoundObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, opcode := range []byte{0x08, 0x09, 0x0a, 0x0b} {
		code := x86RawVEXRoundConstant(opcode, opcode < 0x0a)
		name := fmt.Sprintf("rawVEXRound%d", index)
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
			compileLLVMToObject(t, llc, triple, "raw-vex-round.ll", "raw-vex-round.o", ir)
		})
	}
}
