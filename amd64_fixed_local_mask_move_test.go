package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fixedLocalMaskMoveRow struct {
	op   Op
	mask Reg
	size int64
}

var fixedLocalMaskMoveRows = [...]fixedLocalMaskMoveRow{
	{"KMOVB", "K7", 1},
	{"KMOVW", "K5", 2},
	{"KMOVD", "K1", 4},
	{"KMOVQ", "K2", 8},
}

func (row fixedLocalMaskMoveRow) assembly(name, address string) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$64-16\nMOVQ a+0(FP),AX\nKMOVQ AX,%s\n", name, row.mask)
	if strings.Contains(address, "(BP)") {
		source.WriteString("LEAQ 48(SP),BP\nMOVQ $1,SI\n")
	}
	fmt.Fprintf(&source, "%s %s,%s\n%s %s,%s\n", row.op, row.mask, address, row.op, address, row.mask)
	fmt.Fprintf(&source, "KMOVQ %s,AX\nMOVQ AX,ret+8(FP)\nRET\n", row.mask)
	return source.String()
}

func TestGoAMD64FixedLocalMaskMoveOriginalFrameSelection(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range fixedLocalMaskMoveRows {
		for _, address := range []struct {
			number int64
			text   string
		}{
			{17, "17(SP)"},
			{35, "-17(BP)(SI*4)"},
		} {
			t.Run(string(row.op)+"/"+address.text, func(t *testing.T) {
				source := row.assembly("Value", address.text)
				requireX86GoAssemblerResult(t, "amd64", source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
					t.Fatal("original mask move did not select the private frame observer")
				}
				proven, err := proveX86FixedLocal(file.Funcs[0], sig)
				if err != nil {
					t.Fatal(err)
				}
				accesses := 0
				for _, ins := range proven.Instrs {
					for index, fact := range ins.x86FixedLocalMemory {
						if ins.Op != row.op || fact.owner != proven.x86FixedLocal || fact.nativeInput ||
							fact.width != row.size || fact.write != (index == 1) {
							t.Fatalf("unexpected private mask move fact: %v", fact)
						}
						for _, offset := range fact.offset {
							if offset != address.number {
								t.Fatalf("computed offset %d, want %d", offset, address.number)
							}
						}
						accesses++
					}
				}
				if accesses != 2 {
					t.Fatalf("expected one read and one write, got %d accesses", accesses)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalMaskMoveOriginalObjects(t *testing.T) {
	var source, declarations strings.Builder
	count := 0
	for _, row := range fixedLocalMaskMoveRows {
		for _, address := range []string{"17(SP)", "-17(BP)(SI*4)"} {
			name := fmt.Sprintf("Value%d", count)
			source.WriteString(row.assembly(name, address))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			count++
		}
	}
	fixedLocalCompleteVectorObjects(t, source.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalMaskMoveFrameGuards(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	row := fixedLocalMaskMoveRows[3]
	for _, change := range []struct{ name, original, changed string }{
		{"unknown mask input", "KMOVQ AX,K2\n", ""},
		{"short write", "KMOVQ K2,17(SP)", "KMOVD K2,17(SP)"},
		{"uninitialized read", "KMOVQ 17(SP),K2", "KMOVQ 18(SP),K2"},
		{"frame overrun", "KMOVQ K2,17(SP)", "KMOVQ K2,57(SP)"},
	} {
		t.Run(change.name, func(t *testing.T) {
			source := strings.Replace(row.assembly("Value", "17(SP)"), change.original, change.changed, 1)
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("invalid mask move gained a frame proof: %v", err)
			}
		})
	}
}
