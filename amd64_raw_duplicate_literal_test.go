package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86RawDuplicateMoveConstant(spec rawDuplicateMoveSpec, encoding string, width int, mask int, zeroing bool) []byte {
	var code []byte
	switch encoding {
	case "legacy":
		code = encodeX86RawLegacyDuplicateMove(spec, 0, 0)
	case "vex":
		code = encodeX86RawVEXDuplicateMove(spec, byte(map[int]int{16: 0, 32: 1}[width]), 0, 0)
	case "evex":
		code = encodeX86RawEVEXDuplicateMove(spec, byte(map[int]int{16: 0, 32: 1, 64: 2}[width]), mask, zeroing, 0, 0)
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if spec.double && width == 16 {
		dataWidth = 8
	}
	for i := 0; i < dataWidth; i++ {
		code = append(code, byte(i*37+3))
	}
	return code
}

func TestDecodeX86RawDuplicateMoveConstantCompleteFamily(t *testing.T) {
	for _, spec := range rawDuplicateMoveSpecs {
		for _, encoding := range []string{"legacy", "vex", "evex"} {
			widths := []int{16}
			if encoding != "legacy" {
				widths = append(widths, 32)
			}
			if encoding == "evex" {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				mask := 0
				zeroing := false
				if encoding == "evex" && width == 64 {
					mask, zeroing = 3, true
				}
				name := fmt.Sprintf("%s/%s/%d", spec.vector, encoding, width)
				t.Run(name, func(t *testing.T) {
					code := x86RawDuplicateMoveConstant(spec, encoding, width, mask, zeroing)
					got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := spec.vector
					if encoding == "legacy" {
						want = spec.legacy
					}
					if zeroing {
						want += ".Z"
					}
					if len(got) != 2 || got[0].Op != want ||
						got[0].Args[0].Kind != OpSym || !got[0].x86RIPLiteral ||
						got[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data", code, got, want)
					}
				})
			}
		}
	}
}

func TestDecodeX86RawDuplicateMoveConstantRejectsUnsafeSources(t *testing.T) {
	valid := x86RawDuplicateMoveConstant(rawDuplicateMoveSpecs[0], "vex", 32, 0, false)
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
				t.Fatalf("accepted unsafe duplicate-move RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawDuplicateMoveConstantObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, spec := range rawDuplicateMoveSpecs {
		code := x86RawDuplicateMoveConstant(spec, "evex", 64, 3, true)
		name := fmt.Sprintf("rawDuplicateConstant%d", index)
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
			compileLLVMToObject(t, llc, triple, "raw-duplicate-literal.ll", "raw-duplicate-literal.o", ir)
		})
	}
}
