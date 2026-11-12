package plan9asm

import (
	"fmt"
	"testing"
)

func x86RawMOVBE(width int, store bool, register int) []byte {
	var code []byte
	if width == 16 {
		code = append(code, 0x66)
	}
	rex := byte(0x40 | (register>>3&1)<<2)
	if width == 64 {
		rex |= 0x08
	}
	if rex != 0x40 {
		code = append(code, rex)
	}
	opcode := byte(0xf0)
	if store {
		opcode = 0xf1
	}
	code = append(code, 0x0f, 0x38, opcode, byte((register&7)<<3|0x02), 0xc3)
	return code
}

func TestDecodeX86RawMOVBECompleteWidthsAndDirections(t *testing.T) {
	for _, width := range []int{16, 32, 64} {
		for _, store := range []bool{false, true} {
			for _, register := range []int{0, 7, 8, 15} {
				name := fmt.Sprintf("%d/store%t/reg%d", width, store, register)
				t.Run(name, func(t *testing.T) {
					code := x86RawMOVBE(width, store, register)
					got, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := map[int]Op{16: "MOVBEW", 32: "MOVBEL", 64: "MOVBEQ"}[width]
					if len(got) != 2 || got[0].Op != want || got[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s", code, got, want)
					}
				})
			}
		}
	}
}

func TestTranslateX86RawMOVBEObjects(t *testing.T) {
	file := &File{Arch: ArchAMD64}
	index := 0
	for _, width := range []int{16, 32, 64} {
		for _, store := range []bool{false, true} {
			name := fmt.Sprintf("rawMOVBE%d", index)
			probe := x86RawUnprovedReturnFormProbeFile(t, "amd64", name, x86RawMOVBE(width, store, 8))
			file.Funcs = append(file.Funcs, probe.Funcs...)
			index++
		}
	}
	if index != 6 {
		t.Fatal("complete raw MOVBE width/direction directory changed", index)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir := x86UnboundVoidRawProbeObject(t, file, "amd64", triple)
			compileLLVMToObject(t, llc, triple, "raw-movbe.ll", "raw-movbe.o", ir)
		})
	}
}
