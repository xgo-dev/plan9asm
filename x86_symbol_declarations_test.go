package plan9asm

import (
	"strings"
	"testing"
)

func TestX86SymbolDeclarationsCompleteOperandRoles(t *testing.T) {
	for _, row := range []struct {
		name, op, operand string
		want              bool
	}{
		{"plain read", "MOVL", "·cell(SB)", true},
		{"plain address", "PUSHL", "$·cell(SB)", true},
		{"base read", "MOVL", "·cell(SB)(AX)", true},
		{"index read", "MOVL", "·cell+8(SB)(CX*4)", true},
		{"base and index read", "MOVL", "·cell-8(SB)(AX)(CX*4)", true},
		{"base write", "POPL", "·cell(SB)(AX)", true},
		{"base address", "PUSHL", "$·cell(SB)(AX)", true},
		{"index address", "PUSHL", "$·cell+8(SB)(CX*4)", true},
		{"base and index address", "PUSHL", "$·cell-8(SB)(R8)(X1*4)", true},
		{"indirect call", "CALL", "*·cell(SB)", true},
		// The shared parser discards '*' on OpMem. Go's named grouped
		// CALL progedit gives this its branch role, not an indirect read.
		{"starred grouped branch", "CALL", "*·cell(SB)(AX)", false},
		{"direct call", "CALL", "·cell(SB)", false},
		{"grouped branch", "JMP", "·cell(SB)(AX)", false},
		{"parameter read", "MOVL", "cell+0(FP)(AX)", false},
		{"parameter address", "PUSHL", "$cell+0(FP)(AX)", false},
		{"auto read", "MOVL", "cell-8(SP)(AX)", false},
		{"auto address", "PUSHL", "$cell-8(SP)(AX)", false},
		{"unnamed read", "MOVL", "8(AX)(CX*4)", false},
		{"unnamed address", "PUSHL", "$8(AX)(CX*4)", false},
		{"integer", "PUSHL", "$8", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			operand, err := parseOperandForArch(ArchAMD64, row.operand)
			if err != nil {
				t.Fatal(err)
			}
			file := &File{Arch: ArchAMD64, Funcs: []Func{{
				Sym: "·Value", Instrs: []Instr{{Op: Op(row.op), Args: []Operand{operand}}},
			}}}
			var output strings.Builder
			emitExternSBGlobals(&output, file, testResolveSym("example"), nil)
			want := ""
			if row.want {
				want = "@\"example.cell\" = external global i8\n\n"
			}
			if output.String() != want {
				t.Fatalf("reference collection changed %s identity: got %q, want %q", row.operand, output.String(), want)
			}
		})
	}
}

func TestX86SymbolDeclarationsPreserveDefinitionsAndNamespace(t *testing.T) {
	const source = `TEXT ·Value(SB),4,$0-0
PUSHL $·cell(SB)(AX)
PUSHL $·cell+8(SB)(CX*4)
PUSHL $other·cell-8(SB)(R8)(X1*4)
PUSHL $private<>(SB)(AX)
PUSHL $·defined(SB)(AX)
PUSHL $·Value(SB)(AX)
PUSHL $·helper(SB)(AX)
RET
GLOBL ·defined(SB),16,$8
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	emitExternSBGlobals(&output, file, testResolveSym("example"), map[string]FuncSig{
		"example.helper": {Name: "example.helper", Ret: Void},
	})
	const want = "@\"example.cell\" = external global i8\n" +
		"@\"example.private\" = external global i8\n" +
		"@\"other.cell\" = external global i8\n\n"
	if output.String() != want {
		t.Fatalf("declaration ownership, deduplication, ordering or namespace changed: got %q, want %q", output.String(), want)
	}
}
