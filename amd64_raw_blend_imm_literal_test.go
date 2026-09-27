package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawImmediatePackedBlendLiteral(spec rawImmediatePackedBlendSpec, vex bool, width int) []byte {
	var code []byte
	if vex {
		code = encodeX86RawVEXImmediatePackedBlend(spec, byte((width-16)/16), 0, 1, 2, 0xa5)
	} else {
		code = encodeX86RawLegacyImmediatePackedBlend(spec, 0, 2, 0xa5)
	}
	modRMIndex := len(code) - 2
	code[modRMIndex] = 0x15 // RIP+disp32; destination remains X/Y2.
	code = append(code[:modRMIndex+1], append([]byte{1, 0, 0, 0}, code[modRMIndex+1:]...)...)
	code = append(code, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*7+3))
	}
	return code
}

func TestDecodeX86RawImmediatePackedBlendRIPDataCompleteFamily(t *testing.T) {
	for _, spec := range rawImmediatePackedBlendSpecs {
		for _, vex := range []bool{false, true} {
			if !vex && spec.legacy == "" {
				continue
			}
			widths := []int{16}
			if vex {
				widths = append(widths, 32)
			}
			for _, width := range widths {
				name := fmt.Sprintf("%s/vex%t/%d", spec.vector, vex, width)
				t.Run(name, func(t *testing.T) {
					code := x86RawImmediatePackedBlendLiteral(spec, vex, width)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := spec.legacy
					if vex {
						want = spec.vector
					}
					if len(decoded) != 2 || decoded[0].Op != want ||
						decoded[0].Args[0].Kind != OpImm || decoded[0].Args[0].Imm != 0xa5 ||
						decoded[0].Args[1].Kind != OpSym || !decoded[0].x86RIPLiteral ||
						decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, want)
					}
					if !bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-width:]) {
						t.Fatalf("source-local data = %x, want %x", decoded[0].x86RIPLiteralData, code[len(code)-width:])
					}
				})
			}
		}
	}
}

func TestDecodeX86RawImmediatePackedBlendRIPDataRejectsUnsafeSources(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source": func(code []byte) []byte { return code[:len(code)-1] },
		"outside directive group": func(code []byte) []byte {
			code[5] = 127
			return code
		},
		"overlapping instruction": func(code []byte) []byte {
			code[5] = 0
			return code
		},
		"segment override": func(code []byte) []byte {
			return append([]byte{0x64}, code...)
		},
		"address override": func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(x86RawImmediatePackedBlendLiteral(rawImmediatePackedBlendSpecs[2], true, 32))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe packed-blend RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawImmediatePackedBlendRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, spec := range rawImmediatePackedBlendSpecs {
		for _, vex := range []bool{false, true} {
			if !vex && spec.legacy == "" {
				continue
			}
			name := string(spec.legacy)
			width := 16
			if vex {
				name = string(spec.vector)
				width = 32
			}
			fmt.Fprintf(&source, "TEXT literal%s(SB),$0-0\n", name)
			for _, value := range x86RawImmediatePackedBlendLiteral(spec, vex, width) {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			sigs["literal"+name] = FuncSig{Name: "literal" + name, Ret: Void}
		}
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
	if len(normalized.Data) != len(sigs) {
		t.Fatalf("materialized %d constants, want %d", len(normalized.Data), len(sigs))
	}
	for _, fn := range normalized.Funcs {
		found := false
		for _, instruction := range fn.Instrs {
			if !instruction.x86RIPLiteral {
				continue
			}
			if len(instruction.Args) < 2 || !strings.Contains(instruction.Raw, instruction.Args[1].Sym) {
				t.Fatalf("%s raw text does not name its materialized source: %+v", fn.Sym, instruction)
			}
			found = true
		}
		if !found {
			t.Fatalf("%s has no decoded packed-blend literal", fn.Sym)
		}
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
			compileLLVMToObject(t, llc, triple, "raw-blend-imm-literal.ll", "raw-blend-imm-literal.o", ir)
		})
	}
}
