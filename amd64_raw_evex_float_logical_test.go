package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawEVEXFloatLogicalEncoding(opcode, pp byte, width, mask int, zeroing, broadcast, rip bool) []byte {
	p1 := byte(0x7c | pp) // EVEX.vvvv names Z0, fixed bit set.
	if pp == 1 {
		p1 |= 0x80 // PD requires EVEX.W1.
	}
	p2 := byte(map[int]int{16: 0, 32: 1, 64: 2}[width]<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // Z3 first source, Z2 destination.
	if broadcast {
		modRM = 0x13 // 0(BX) first source.
	}
	if rip {
		modRM = 0x15 // RIP+disp32 first source.
	}
	code := []byte{0x62, 0xf1, p1, p2, opcode, modRM}
	if rip {
		code = append(code, 1, 0, 0, 0)
	}
	return code
}

func x86RawEVEXFloatLogicalLiteral(opcode, pp byte, width, mask int, zeroing, broadcast bool) []byte {
	code := x86RawEVEXFloatLogicalEncoding(opcode, pp, width, mask, zeroing, broadcast, true)
	code = append(code, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = 4
		if pp == 1 {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*13+3))
	}
	return code
}

func TestDecodeX86RawEVEXFloatLogicalArithAVX512Regression(t *testing.T) {
	// Go's assembler decodes these bytes as VANDPS 0(SI)(R8*4), Z0, Z1.
	code := []byte{0x62, 0xb1, 0x7c, 0x48, 0x54, 0x0c, 0x86, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "arith AVX512 VANDPS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VANDPS" ||
		decoded[0].Args[0].Kind != OpMem ||
		decoded[0].Args[0].Mem.Base != SI ||
		decoded[0].Args[0].Mem.Index != "R8" ||
		decoded[0].Args[0].Mem.Scale != 4 ||
		decoded[0].Args[1].Reg != "Z0" ||
		decoded[0].Args[2].Reg != "Z1" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawEVEXFloatLogicalCompleteGo127Family(t *testing.T) {
	for opcode, stem := range x86VEXPackedFloatLogicalTestOpcodes {
		for pp, suffix := range map[byte]string{0: "PS", 1: "PD"} {
			for _, width := range []int{16, 32, 64} {
				for _, masking := range []struct {
					mask int
					zero bool
				}{
					{}, {mask: 3}, {mask: 7, zero: true},
				} {
					for _, broadcast := range []bool{false, true} {
						code := x86RawEVEXFloatLogicalEncoding(opcode, pp, width, masking.mask, masking.zero, broadcast, false)
						got, length, ok, err := decodedX86RawEVEXFloatLogicalInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						want := Op(stem + suffix)
						if broadcast {
							want += ".BCST"
						}
						if masking.zero {
							want += ".Z"
						}
						if got.Op != want || len(got.Args) != 3+map[bool]int{false: 0, true: 1}[masking.mask != 0] {
							t.Fatalf("decode %x = %+v, want %s", code, got, want)
						}
						if broadcast && got.Args[0].Kind != OpMem || !broadcast && got.Args[0].Reg == "" {
							t.Fatalf("decode %x has wrong first source: %+v", code, got)
						}
					}
				}
			}
		}
	}
	high := []byte{0x62, 0x01, 0x04, 0x40, 0x54, 0xff}
	got, length, ok, err := decodedX86RawEVEXFloatLogicalInstruction(high, 64)
	if err != nil || !ok || length != len(high) || got.Raw != "VANDPS Z31, Z31, Z31" {
		t.Fatalf("high EVEX registers %x decoded as %+v, length=%d, ok=%v, err=%v", high, got, length, ok, err)
	}
}

func TestDecodeX86RawEVEXFloatLogicalRIPDataCompleteFamily(t *testing.T) {
	for opcode, stem := range x86VEXPackedFloatLogicalTestOpcodes {
		for pp, suffix := range map[byte]string{0: "PS", 1: "PD"} {
			for _, width := range []int{16, 32, 64} {
				for _, broadcast := range []bool{false, true} {
					name := fmt.Sprintf("%s%s/%d/bcst%t", stem, suffix, width, broadcast)
					t.Run(name, func(t *testing.T) {
						code := x86RawEVEXFloatLogicalLiteral(opcode, pp, width, 7, true, broadcast)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						dataWidth := width
						if broadcast {
							dataWidth = 4
							if pp == 1 {
								dataWidth = 8
							}
						}
						if len(decoded) != 2 || decoded[0].Args[0].Kind != OpSym ||
							!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET ||
							!bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-dataWidth:]) {
							t.Fatalf("decoded floating logical literal %x as %#v", code, decoded)
						}
					})
				}
			}
		}
	}
}

func TestDecodeX86RawEVEXFloatLogicalRejectsUnsafeForms(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated literal":       func(code []byte) []byte { return code[:len(code)-1] },
		"outside directive group": func(code []byte) []byte { code[6] = 127; return code },
		"overlapping instruction": func(code []byte) []byte { code[6] = 0; return code },
		"segment override":        func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address override":        func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(x86RawEVEXFloatLogicalLiteral(0x54, 0, 64, 7, true, true))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe floating logical literal %x", code)
			}
		})
	}
	for _, code := range [][]byte{
		x86RawEVEXFloatLogicalEncoding(0x54, 0, 16, 0, true, false, false),
		{0x62, 0xf1, 0x7c, 0x19, 0x54, 0xd3}, // EVEX.b with a register source.
	} {
		if _, _, ok, err := decodedX86RawEVEXFloatLogicalInstruction(code, 64); !ok || err == nil {
			t.Fatalf("accepted reserved floating logical form %x: ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateX86RawEVEXFloatLogicalRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for opcode, stem := range x86VEXPackedFloatLogicalTestOpcodes {
		for pp, suffix := range map[byte]string{0: "PS", 1: "PD"} {
			name := "literal" + stem + suffix
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range x86RawEVEXFloatLogicalLiteral(opcode, pp, 64, 7, true, true) {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
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
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-evex-float-logical-literal.ll", "raw-evex-float-logical-literal.o", ir)
		})
	}
}
