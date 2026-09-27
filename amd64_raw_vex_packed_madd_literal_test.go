package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawVEXPackedMADDConstant(opcode byte, opcodeMap int, vex3, width256, w bool) []byte {
	code := encodeX86VEXPackedMADD(opcode, opcodeMap, vex3, width256, w, 0, 0, 0)
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	width := 16
	if width256 {
		width = 32
	}
	for i := 0; i < width; i++ {
		code = append(code, byte(i*29+13))
	}
	return code
}

func TestDecodeX86RawVEXPackedMADDLiteralCompleteFamily(t *testing.T) {
	for _, form := range []struct {
		opcode byte
		mapID  int
		op     Op
		vex2   bool
	}{
		{0xf5, 1, "VPMADDWD", true},
		{0x04, 2, "VPMADDUBSW", false},
	} {
		for _, vex3 := range []bool{false, true} {
			if !vex3 && !form.vex2 {
				continue
			}
			for _, width256 := range []bool{false, true} {
				for _, w := range []bool{false, true} {
					if !vex3 && w {
						continue
					}
					name := fmt.Sprintf("%s/vex3=%t/y=%t/w=%t", form.op, vex3, width256, w)
					t.Run(name, func(t *testing.T) {
						code := x86RawVEXPackedMADDConstant(form.opcode, form.mapID, vex3, width256, w)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						if len(decoded) != 2 || decoded[0].Op != form.op ||
							decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
							decoded[1].Op != OpRET {
							t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, form.op)
						}
					})
				}
			}
		}
	}
}

func TestDecodeX86RawVEXPackedMADDLiteralRejectsUnsafeSources(t *testing.T) {
	valid := x86RawVEXPackedMADDConstant(0xf5, 1, false, false, false)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(code []byte) []byte { return code[:len(code)-1] },
		"overlap": func(code []byte) []byte {
			code[4] = 0
			return code
		},
		"outside": func(code []byte) []byte {
			code[4] = 127
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

func TestTranslateX86RawVEXPackedMADDLiteralObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, form := range []struct {
		opcode byte
		mapID  int
	}{
		{0xf5, 1}, {0x04, 2},
	} {
		code := x86RawVEXPackedMADDConstant(form.opcode, form.mapID, true, true, false)
		name := fmt.Sprintf("packedMADDConstant%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		pools = append(pools, code[len(code)-32:])
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != len(pools) {
		t.Fatalf("materialized %d constants, want %d", len(normalized.Data), len(pools))
	}
	for index, datum := range normalized.Data {
		if !bytes.Equal(datum.Payload, pools[index]) {
			t.Fatalf("constant %d = %x, want %x", index, datum.Payload, pools[index])
		}
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
			compileLLVMToObject(t, llc, triple, "packed-madd-literal.ll", "packed-madd-literal.o", ir)
		})
	}
}
