package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawImplicitMulDivWidths(t *testing.T) {
	for _, form := range []struct {
		name   string
		regBit byte
	}{
		{"MUL", 4}, {"IMUL", 5}, {"DIV", 6}, {"IDIV", 7},
	} {
		for _, width := range []struct {
			name   string
			prefix byte
			opcode byte
		}{
			{"B", 0, 0xf6},
			{"W", 0x66, 0xf7},
			{"L", 0, 0xf7},
			{"Q", 0x48, 0xf7},
		} {
			for _, memory := range []bool{false, true} {
				name := fmt.Sprintf("%s%s/mem%t", form.name, width.name, memory)
				t.Run(name, func(t *testing.T) {
					var code []byte
					if width.prefix != 0 {
						code = append(code, width.prefix)
					}
					modRM := byte(0xc2 | form.regBit<<3)
					if memory {
						modRM = 0x02 | form.regBit<<3
					}
					code = append(code, width.opcode, modRM, 0xc3)
					got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					if len(got) != 2 || string(got[0].Op) != form.name+width.name || got[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s", code, got, name)
					}
				})
			}
		}
	}
}

func TestTranslateX86RawImplicitMulDivWidthsObjects(t *testing.T) {
	var source strings.Builder
	for index, code := range [][]byte{
		{0xf6, 0xe2, 0xc3},
		{0x66, 0xf7, 0xea, 0xc3},
		{0xf7, 0xf2, 0xc3},
		{0x48, 0xf7, 0xfa, 0xc3},
	} {
		name := fmt.Sprintf("rawMulDivWidth%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			original, signatures := x86UnboundVoidFormatSources(t, source.String(), "amd64", triple)
			normalized, err := normalizeX86RawFile(original, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			// Original raw bytes and all public Context results stay bound
			// above. These private units measure native encoding syntax only;
			// they supply no implicit inputs or raw/native entry contract.
			ir := x86InstructionFormatObjectUnit(t, normalized, signatures, "amd64", triple, 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					if form, known, err := x86ImplicitDivideProperties(ins.Op, ins, "amd64"); known {
						if err != nil {
							return true, false, err
						}
						return true, false, c.emitNativeImplicitDivide(form)
					}
					terminated, err := c.lowerInstr(0, 0, ins, nil, nil)
					return true, terminated, err
				})
			compileLLVMToObject(t, llc, triple, "raw-muldiv-width.ll", "raw-muldiv-width.o", ir)
		})
	}
}
