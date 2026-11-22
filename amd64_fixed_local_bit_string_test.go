package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalBitStringOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	count := 0
	for _, family := range []string{"BT", "BTC", "BTR", "BTS"} {
		for _, size := range []struct {
			suffix string
			bits   int
		}{{"W", 16}, {"L", 32}, {"Q", 64}} {
			for _, bit := range []int{3, size.bits + 1, -size.bits - 1} {
				name := fmt.Sprintf("Value%d", count)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
				assembly.WriteString("MOVQ AX,56(SP)\nMOVQ AX,64(SP)\nMOVQ AX,72(SP)\nMOVQ AX,80(SP)\nLEAQ 72(SP),BX\nXORQ CX,CX\n")
				fmt.Fprintf(&assembly, "MOVQ $%d,DX\n%s%s DX,(BX)\nSETCS CL\n", bit, family, size.suffix)
				assembly.WriteString("XORQ 56(SP),CX\nXORQ 64(SP),CX\nXORQ 72(SP),CX\nXORQ 80(SP),CX\nMOVQ CX,ret+8(FP)\nRET\n")
				fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
				count++
			}
		}
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalBitStringSignedIndexAndReach(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body    string
		offset, width int64
	}{
		{"word negative", "MOVW AX,70(SP)\nMOVQ $-1,DX\nBTSW DX,(BX)", 70, 2},
		{"dword signed at operand width", "MOVL AX,68(SP)\nMOVQ $0xffffffff,DX\nBTRL DX,(BX)", 68, 4},
		{"qword next word", "MOVQ AX,80(SP)\nMOVQ $64,DX\nBTCQ DX,(BX)", 80, 8},
		{"bounded two words", "MOVQ AX,72(SP)\nMOVQ AX,80(SP)\nMOVQ AX,DX\nANDQ $127,DX\nBTSQ DX,(BX)", 72, 16},
		{"immediate uses its own width", "MOVW AX,72(SP)\nBTW $15,(BX)", 72, 2},
		{"missing next word", "MOVQ AX,72(SP)\nMOVQ $64,DX\nBTQ DX,(BX)", 0, 0},
		{"negative off frame", "MOVQ AX,72(SP)\nMOVQ $-1024,DX\nBTSQ DX,(BX)", 0, 0},
		{"bounded missing word", "MOVQ AX,72(SP)\nMOVQ AX,DX\nANDQ $127,DX\nBTQ DX,(BX)", 0, 0},
		{"unbounded index", "MOVQ AX,72(SP)\nMOVQ AX,DX\nBTRQ DX,(BX)", 0, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\nLEAQ 72(SP),BX\nXORQ CX,CX\n" +
				row.body + "\nSETCS CL\nMOVQ CX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			proven, err := proveX86FixedLocal(file.Funcs[0], sig)
			if row.width == 0 {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved private bit string: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range proven.Instrs {
				stem, _, bitTest := amd64BitTestProperties(string(ins.Op))
				if !bitTest {
					continue
				}
				access, found := ins.x86FixedLocalMemory[1]
				if !found || access.width != row.width || access.nativeInput || access.write != (stem != "BT") {
					t.Fatalf("wrong bit-string access: %+v", access)
				}
				for _, offset := range access.offset {
					if offset != row.offset {
						t.Fatalf("wrong bit-string offset: got %d, want %d", offset, row.offset)
					}
				}
				return
			}
			t.Fatal("missing bit-test instruction")
		})
	}
}
