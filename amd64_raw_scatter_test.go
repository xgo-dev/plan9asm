package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeX86RawScatterSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VSCATTERQPS Y2, K1, 0(DI)(Z1*4).
	code := []byte{0x62, 0xf2, 0x7d, 0x49, 0xa3, 0x14, 0x8f, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "convolveFloat32 AVX512 VSCATTERQPS", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VSCATTERQPS" ||
		decoded[0].Args[0].Reg != "Y2" || decoded[0].Args[1].Reg != "K1" ||
		decoded[0].Args[2].Mem.Index != "Z1" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func x86RawScatterGoForms(goarch string) string {
	var source strings.Builder
	source.WriteString("TEXT rawScatterForms(SB),4,$0-0\n")
	widths := [...]string{"X", "Y", "Z"}
	for _, family := range x86ScatterOps {
		for _, op := range family {
			spec := amd64ScatterSpecs[string(op)]
			for width := 0; width < 3; width++ {
				dataWidth := widths[width]
				indexWidth := dataWidth
				switch spec.table {
				case amd64GatherDPD:
					if width > 0 {
						indexWidth = widths[width-1]
					}
				case amd64GatherQPS:
					if width > 0 {
						dataWidth = widths[width-1]
					}
				}
				fmt.Fprintf(&source, "\t%s %s1, K1, 8(BX)(%s2*4)\n", op, dataWidth, indexWidth)
				if goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s %s21, K7, -32(R8)(%s18*2)\n", op, dataWidth, indexWidth)
				}
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestDecodeX86RawScatterCompleteGoForms(t *testing.T) {
	expected := map[Op]bool{
		"VPSCATTERDD": true, "VPSCATTERDQ": true,
		"VPSCATTERQD": true, "VPSCATTERQQ": true,
		"VSCATTERDPS": true, "VSCATTERDPD": true,
		"VSCATTERQPS": true, "VSCATTERQPD": true,
	}
	for _, family := range x86ScatterOps {
		for _, op := range family {
			if !expected[op] {
				t.Fatalf("unexpected or repeated scatter opcode %s", op)
			}
			delete(expected, op)
		}
	}
	if len(expected) != 0 {
		t.Fatalf("missing Go scatter opcodes: %v", expected)
	}
	for _, goarch := range []string{"amd64", "386"} {
		t.Run(goarch, func(t *testing.T) {
			source := x86RawScatterGoForms(goarch)
			code := assembleX87ControlBytes(t, goarch, source)
			decoded, err := decodeX86RawDirectives(rawX86Function(code), goarch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
		})
	}
}

func TestDecodeX86RawScatterRejectsMalformedForms(t *testing.T) {
	valid := []byte{0x62, 0xf2, 0x7d, 0x49, 0xa3, 0x14, 0x8f}
	for _, variant := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing mask", func(code []byte) []byte { code[3] &^= 7; return code }},
		{"zeroing", func(code []byte) []byte { code[3] |= 0x80; return code }},
		{"broadcast", func(code []byte) []byte { code[3] |= 0x10; return code }},
		{"reserved length", func(code []byte) []byte { code[3] |= 0x60; return code }},
		{"register destination", func(code []byte) []byte { code[5] |= 0xc0; return code }},
		{"missing SIB", func(code []byte) []byte { return code[:6] }},
		{"reserved vvvv", func(code []byte) []byte { code[2] &^= 0x08; return code }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			code := variant.mutate(append([]byte(nil), valid...))
			if _, _, matched, err := decodedX86RawScatterInstruction(code, 64); !matched || err == nil {
				t.Fatalf("invalid %x: matched=%v err=%v", code, matched, err)
			}
		})
	}
}

func TestTranslateX86RawScatterLLVM22AllTargets(t *testing.T) {
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
			source := x86RawScatterGoForms(target.goarch)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			code := assembleX87ControlBytes(t, target.goarch, source)
			decoded := rawX86Function(code)
			file.Funcs[0].Instrs = append(file.Funcs[0].Instrs[:1], decoded.Instrs...)
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawScatterForms": {Name: "rawScatterForms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scatter.ll", "raw-scatter.o", ir)
		})
	}
}
