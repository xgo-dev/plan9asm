package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86RawPackedAbsForms = []struct {
	opcode byte
	op     Op
	lane   int
	evex   bool
}{
	{0x1c, "VPABSB", 1, false},
	{0x1d, "VPABSW", 2, false},
	{0x1e, "VPABSD", 4, false},
	{0x1f, "VPABSQ", 8, true},
}

func encodeX86RawPackedAbs(formIndex, width, mask, destination, source int, zeroing, broadcast bool) []byte {
	form := x86RawPackedAbsForms[formIndex]
	vectorBits := map[int]int{16: 0, 32: 1, 64: 2}[width]
	var code []byte
	if width == 64 || mask != 0 || zeroing || broadcast || form.evex {
		code = encodeX86EVEXPackedWordMultiply(2, form.opcode, vectorBits, mask, form.evex, zeroing, destination, 0, source)
		if broadcast {
			code[3] |= 0x10
		}
	} else {
		code = encodeX86VEXPackedWordMultiply(2, form.opcode, width == 32, false, destination, 0, source)
	}
	return code
}

func TestDecodedX86RawPackedAbsCompleteFamily(t *testing.T) {
	for formIndex, form := range x86RawPackedAbsForms {
		for _, width := range []int{16, 32, 64} {
			for _, masked := range []bool{false, true} {
				for _, zeroing := range []bool{false, true} {
					if !masked && zeroing {
						continue
					}
					for _, source := range []int{0, 7, 16, 31} {
						if !masked && width != 64 && !form.evex && source >= 16 {
							continue
						}
						mask := 0
						if masked {
							mask = 3
						}
						name := fmt.Sprintf("%s/%d/k%d/z%t/src%d", form.op, width, mask, zeroing, source)
						t.Run(name, func(t *testing.T) {
							code := encodeX86RawPackedAbs(formIndex, width, mask, 19, source, zeroing, false)
							if width != 64 && !masked && !form.evex {
								code = encodeX86RawPackedAbs(formIndex, width, mask, 11, source, zeroing, false)
							}
							got, length, ok, err := decodedX86RawPackedAbsInstruction(code, 64)
							if err != nil || !ok || length != len(code) || !strings.HasPrefix(string(got.Op), string(form.op)) ||
								got.Args[0].String() != fmt.Sprintf("%s%d", map[int]string{16: "X", 32: "Y", 64: "Z"}[width], source) {
								t.Fatalf("decode %x = %+v length=%d ok=%t err=%v", code, got, length, ok, err)
							}
						})
					}
				}
			}
		}
	}
	// Actual bytes from simd@v1.21.1 arith_avx2_amd64.s.
	real := []byte{0xc4, 0xa2, 0x7d, 0x1e, 0x04, 0x86}
	got, length, ok, err := decodedX86RawPackedAbsInstruction(real, 64)
	if err != nil || !ok || length != len(real) || got.Op != "VPABSD" ||
		got.Args[0].String() != "0(SI)(R8*4)" || got.Args[1].String() != "Y0" {
		t.Fatalf("decode real VPABSD %x = %+v length=%d ok=%t err=%v", real, got, length, ok, err)
	}
}

func TestDecodedX86RawPackedAbsRejectsInvalidForms(t *testing.T) {
	valid := encodeX86RawPackedAbs(2, 32, 0, 1, 2, false, false)
	for name, edit := range map[string]func([]byte) []byte{
		"reserved vvvv":    func(b []byte) []byte { b[2] &^= 0x08; return b },
		"W1":               func(b []byte) []byte { b[2] |= 0x80; return b },
		"truncated":        func(b []byte) []byte { return b[:4] },
		"address override": func(b []byte) []byte { return append([]byte{0x67}, b...) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := edit(append([]byte(nil), valid...))
			if _, _, matched, err := decodedX86RawPackedAbsInstruction(bad, 64); !matched || err == nil {
				t.Fatalf("accepted invalid packed absolute %x: matched=%t err=%v", bad, matched, err)
			}
		})
	}
}

func TestTranslateX86RawPackedAbsObjects(t *testing.T) {
	const source = `TEXT rawPackedAbs(SB),$0-0
	BYTE $0xc4
	BYTE $0xa2
	BYTE $0x7d
	BYTE $0x1e
	BYTE $0x04
	BYTE $0x86
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
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
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawPackedAbs": {Name: "rawPackedAbs", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-packed-abs.ll", "raw-packed-abs.o", ir)
		})
	}
}

func x86RawPackedAbsConstant(formIndex, width int, broadcast bool) []byte {
	form := x86RawPackedAbsForms[formIndex]
	code := encodeX86RawPackedAbs(formIndex, width, 0, 0, 0, false, broadcast)
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = form.lane
	}
	for i := 0; i < dataWidth; i++ {
		code = append(code, byte(i*23+5))
	}
	return code
}

func TestDecodeX86RawPackedAbsConstantCompleteFamily(t *testing.T) {
	for formIndex, form := range x86RawPackedAbsForms {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && form.lane < 4 {
					continue
				}
				name := fmt.Sprintf("%s/%d/bcst%t", form.op, width, broadcast)
				t.Run(name, func(t *testing.T) {
					code := x86RawPackedAbsConstant(formIndex, width, broadcast)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := form.op
					if broadcast {
						want += ".BCST"
					}
					if len(decoded) != 2 || decoded[0].Op != want ||
						decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
						decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, want)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawPackedAbsConstantRejectsUnsafeSources(t *testing.T) {
	valid := x86RawPackedAbsConstant(2, 64, true)
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
				t.Fatalf("accepted unsafe RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawPackedAbsConstantObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, form := range []struct {
		formIndex, width int
		broadcast        bool
	}{
		{0, 32, false}, {1, 64, false}, {2, 64, true}, {3, 64, true},
	} {
		code := x86RawPackedAbsConstant(form.formIndex, form.width, form.broadcast)
		name := fmt.Sprintf("rawPackedAbsConstant%d", index)
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
			compileLLVMToObject(t, llc, triple, "raw-packed-abs-constant.ll", "raw-packed-abs-constant.o", ir)
		})
	}
}
