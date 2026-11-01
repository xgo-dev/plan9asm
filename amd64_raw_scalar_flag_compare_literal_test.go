package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawScalarFlagCompareLiteral(op string, encoding string) []byte {
	pp, opcode := 0, 0x2f
	if strings.HasPrefix(op, "VU") {
		opcode = 0x2e
	}
	width := 4
	if strings.HasSuffix(op, "SD") {
		pp, width = 1, 8
	}
	var code []byte
	if encoding == "vex2" {
		code = []byte{0xc5, byte(0xf8 | pp), byte(opcode), 0x05}
	} else {
		evex := encoding == "evex"
		code = encodeRawScalarMove(evex, pp, opcode, 0, 0, 0, 0, false)
		if evex && width == 8 {
			code[2] |= 0x80
		}
		code[len(code)-1] = 0x05
	}
	code = append(code, 1, 0, 0, 0, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*37+21))
	}
	return code
}

func TestDecodeX86RawScalarFlagCompareRIPDataCompleteFamily(t *testing.T) {
	for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, encoding := range []string{"vex2", "vex3", "evex"} {
			name := op + "/" + encoding
			t.Run(name, func(t *testing.T) {
				code := x86RawScalarFlagCompareLiteral(op, encoding)
				decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded) != 2 || decoded[0].Op != Op(op) ||
					decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
					decoded[1].Op != OpRET {
					t.Fatalf("decoded %x as %#v, want %s source-local scalar", code, decoded, op)
				}
			})
		}
	}
}

func TestDecodeX86RawScalarFlagCompareRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawScalarFlagCompareLiteral("VUCOMISD", "evex")
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source": func(code []byte) []byte { return code[:len(code)-1] },
		"overlapping instruction": func(code []byte) []byte {
			code[6] = 0
			return code
		},
		"outside directive group": func(code []byte) []byte {
			code[6] = 127
			return code
		},
		"segment override": func(code []byte) []byte {
			return append([]byte{0x65}, code...)
		},
		"address override": func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		},
		"EVEX SAE memory": func(code []byte) []byte {
			code[3] |= 0x10
			return code
		},
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawScalarFlagCompareRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	index := 0
	for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, encoding := range []string{"vex2", "vex3", "evex"} {
			code := x86RawScalarFlagCompareLiteral(op, encoding)
			name := fmt.Sprintf("flagCompareLiteral%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range code {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			sigs[name] = FuncSig{Name: name, Ret: Void}
			width := 4
			if strings.HasSuffix(op, "SD") {
				width = 8
			}
			pools = append(pools, code[len(code)-width:])
			index++
		}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != len(file.Funcs) || len(sigs) != 12 {
		t.Fatal("complete original COMI RIP TEXT/declaration inventory changed")
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
	// Supply only the missing X0 input in a separately named companion.
	// Inserting before the complete original BYTE block preserves every raw
	// byte, its RIP displacement, its terminal RET and all source-local data.
	const header = "(SB),$0-0\n"
	const initializedHeader = "(SB),$0-0\nPXOR X0,X0\n"
	initialized := strings.ReplaceAll(source.String(), header, initializedHeader)
	if strings.Count(source.String(), header) != 12 || strings.Count(initialized, "PXOR X0,X0\n") != 12 ||
		strings.ReplaceAll(initialized, initializedHeader, header) != source.String() {
		t.Fatal("initialized RIP companion changed more than each missing X0 producer")
	}
	var declarations strings.Builder
	for _, function := range file.Funcs {
		fmt.Fprintf(&declarations, "func %s()\n", function.Sym)
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir := x86COMIOriginalFormatObject(t, source.String(), "amd64", triple)
			x86COMICompileOriginalFormatObjects(t, llc, triple, "flag-compare-literal", ir)
			x86COMIOriginalProducerObjects(t, initialized, declarations.String(), "amd64", triple)
		})
	}
}
