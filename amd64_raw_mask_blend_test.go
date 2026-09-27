package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawMaskBlendEncoding(op Op, width, mask int, zeroing, broadcast, rip bool) []byte {
	properties := map[Op]struct {
		opcode byte
		w      bool
	}{
		"VBLENDMPS": {0x65, false}, "VBLENDMPD": {0x65, true},
		"VPBLENDMD": {0x64, false}, "VPBLENDMQ": {0x64, true},
		"VPBLENDMB": {0x66, false}, "VPBLENDMW": {0x66, true},
	}[op]
	p1 := byte(0x75) // source 2 is register 1, fixed bit and pp=66.
	if properties.w {
		p1 |= 0x80
	}
	p2 := byte(map[int]int{16: 0, 32: 1, 64: 2}[width]<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xd3) // register 3, destination register 2.
	if broadcast {
		modRM = 0x13 // 0(BX), destination register 2.
	}
	if rip {
		modRM = 0x15 // RIP+disp32, destination register 2.
	}
	code := []byte{0x62, 0xf2, p1, p2, properties.opcode, modRM}
	if rip {
		code = append(code, 1, 0, 0, 0)
	}
	return code
}

func TestDecodeX86RawMaskBlend386FrontendBoundary(t *testing.T) {
	plain := x86RawMaskBlendEncoding("VBLENDMPS", 16, 0, false, false, false)
	if _, _, ok, err := decodedX86RawMaskBlendInstruction(plain, 32); !ok || err != nil {
		t.Fatalf("386 unmasked EVEX form: ok=%v err=%v", ok, err)
	}
	masked := x86RawMaskBlendEncoding("VBLENDMPS", 16, 1, false, false, false)
	if _, _, ok, err := decodedX86RawMaskBlendInstruction(masked, 32); !ok || err == nil {
		t.Fatalf("386 masked EVEX form accepted: ok=%v err=%v", ok, err)
	}
}

func x86RawMaskBlendLiteral(op Op, width, mask int, zeroing, broadcast bool) []byte {
	code := x86RawMaskBlendEncoding(op, width, mask, zeroing, broadcast, true)
	code = append(code, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = amd64MaskBlendSpecs[op].laneBits / 8
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*7+5))
	}
	return code
}

func TestDecodeX86RawMaskBlendCompleteGo127Family(t *testing.T) {
	if len(amd64MaskBlendSpecs) != 6 {
		t.Fatalf("modeled %d mask-blend operations, want six", len(amd64MaskBlendSpecs))
	}
	for op, spec := range amd64MaskBlendSpecs {
		for _, width := range []int{16, 32, 64} {
			for _, masking := range []struct {
				mask int
				zero bool
			}{
				{}, {mask: 5}, {mask: 7, zero: true},
			} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && !spec.broadcast {
						continue
					}
					code := x86RawMaskBlendEncoding(op, width, masking.mask, masking.zero, broadcast, false)
					got, length, ok, err := decodedX86RawMaskBlendInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %s %x = %+v, length=%d, ok=%v, err=%v", op, code, got, length, ok, err)
					}
					want := op
					if broadcast {
						want += ".BCST"
					}
					if masking.zero {
						want += ".Z"
					}
					if got.Op != want || len(got.Args) != 3+map[bool]int{false: 0, true: 1}[masking.mask != 0] ||
						got.Args[1].Reg != "Z1" && width == 64 {
						t.Fatalf("decode %s %x = %+v, want %s", op, code, got, want)
					}
				}
			}
		}
	}
}

func TestDecodeX86RawMaskBlendArgReduceAVX512Regression(t *testing.T) {
	code := []byte{0x62, 0xf2, 0x75, 0x4d, 0x65, 0xdb, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "argreduce AVX512 mask blend", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VBLENDMPS" ||
		decoded[0].Raw != "VBLENDMPS Z3, Z1, K5, Z3 /* decoded from argreduce AVX512 mask blend */" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawMaskBlendRIPDataCompleteFamily(t *testing.T) {
	for op, spec := range amd64MaskBlendSpecs {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && !spec.broadcast {
					continue
				}
				name := fmt.Sprintf("%s/%d/bcst%t", op, width, broadcast)
				t.Run(name, func(t *testing.T) {
					code := x86RawMaskBlendLiteral(op, width, 7, true, broadcast)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					dataWidth := width
					if broadcast {
						dataWidth = spec.laneBits / 8
					}
					if len(decoded) != 2 || decoded[0].Args[0].Kind != OpSym ||
						!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET ||
						!bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-dataWidth:]) {
						t.Fatalf("decoded mask-blend literal %x as %#v", code, decoded)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawMaskBlendRejectsUnsafeForms(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated literal":       func(code []byte) []byte { return code[:len(code)-1] },
		"outside directive group": func(code []byte) []byte { code[6] = 127; return code },
		"overlapping instruction": func(code []byte) []byte { code[6] = 0; return code },
		"segment override":        func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address override":        func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(x86RawMaskBlendLiteral("VBLENDMPS", 64, 7, true, true))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe mask-blend literal %x", code)
			}
		})
	}
	for _, code := range [][]byte{
		x86RawMaskBlendEncoding("VPBLENDMB", 16, 3, false, true, false),
		x86RawMaskBlendEncoding("VBLENDMPS", 16, 0, true, false, false),
	} {
		if _, _, ok, err := decodedX86RawMaskBlendInstruction(code, 64); !ok || err == nil {
			t.Fatalf("accepted reserved mask blend %x: ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateX86RawMaskBlendRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for op, spec := range amd64MaskBlendSpecs {
		for _, broadcast := range []bool{false, true} {
			if broadcast && !spec.broadcast {
				continue
			}
			name := fmt.Sprintf("maskBlendLiteral%d", index)
			index++
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range x86RawMaskBlendLiteral(op, 64, 7, true, broadcast) {
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
			compileLLVMToObject(t, llc, triple, "raw-mask-blend-literal.ll", "raw-mask-blend-literal.o", ir)
		})
	}
}
