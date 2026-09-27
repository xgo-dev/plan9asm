package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawHorizontalFloatLiteral(opcode, pp byte, vex3 bool, width int) []byte {
	code := encodeX86VEXHorizontalFloat(opcode, pp, vex3, width == 32, false, 1, 2, 0)
	code[len(code)-1] = 0x0d // RIP+disp32, destination X/Y1.
	code = append(code, 1, 0, 0, 0, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*11+7))
	}
	return code
}

func TestDecodeX86RawHorizontalFloatRIPDataCompleteFamily(t *testing.T) {
	for opcode, stem := range map[byte]string{0x7c: "VHADD", 0x7d: "VHSUB", 0xd0: "VADDSUB"} {
		for pp, suffix := range map[byte]string{1: "PD", 3: "PS"} {
			for _, vex3 := range []bool{false, true} {
				for _, width := range []int{16, 32} {
					name := fmt.Sprintf("%s%s/vex3%t/%d", stem, suffix, vex3, width)
					t.Run(name, func(t *testing.T) {
						code := x86RawHorizontalFloatLiteral(opcode, pp, vex3, width)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						if len(decoded) != 2 || decoded[0].Op != Op(stem+suffix) ||
							decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
							decoded[1].Op != OpRET ||
							!bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-width:]) {
							t.Fatalf("decoded %x as %#v", code, decoded)
						}
					})
				}
			}
		}
	}
}

func TestDecodeX86RawHorizontalFloatRIPDataRejectsUnsafeSources(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source":        func(code []byte) []byte { return code[:len(code)-1] },
		"outside directive group": func(code []byte) []byte { code[5] = 127; return code },
		"overlapping instruction": func(code []byte) []byte { code[5] = 0; return code },
		"segment override":        func(code []byte) []byte { return append([]byte{0x64}, code...) },
		"address override":        func(code []byte) []byte { return append([]byte{0x67}, code...) },
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(x86RawHorizontalFloatLiteral(0xd0, 1, true, 32))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe horizontal/alternating RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawHorizontalFloatRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for opcode, stem := range map[byte]string{0x7c: "VHADD", 0x7d: "VHSUB", 0xd0: "VADDSUB"} {
		for pp, suffix := range map[byte]string{1: "PD", 3: "PS"} {
			name := "literal" + stem + suffix
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range x86RawHorizontalFloatLiteral(opcode, pp, true, 32) {
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
			compileLLVMToObject(t, llc, triple, "raw-horizontal-float-literal.ll", "raw-horizontal-float-literal.o", ir)
		})
	}
}
