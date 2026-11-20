package plan9asm

import (
	"fmt"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

type x86ABI0Mode32BoolRuntimeRow struct {
	body string
	want byte
}

func x86ABI0Mode32BoolRuntimeRows() []x86ABI0Mode32BoolRuntimeRow {
	var rows []x86ABI0Mode32BoolRuntimeRow
	for _, values := range [][2]uint32{{0, 0}, {0, 1}, {1, 0}, {0x7fffffff, 0xffffffff}, {0x80000000, 1}, {0xffffffff, 0}} {
		a, b := values[0], values[1]
		r := a - b
		cf, zf, sf, of := a < b, r == 0, r>>31 != 0, ((a^b)&(a^r))>>31 != 0
		parity := byte(r)
		parity ^= parity >> 4
		parity ^= parity >> 2
		parity ^= parity >> 1
		pf := parity&1 == 0
		want := []bool{!cf, cf, zf, sf == of, !zf && sf == of, !cf && !zf, zf || sf != of, cf || zf, sf != of, sf, !zf, !of, of, !pf, !sf, pf}
		for index, condition := range amd64RegisterBoolConditions {
			row := x86ABI0Mode32BoolRuntimeRow{body: fmt.Sprintf("MOVL $%d,AX\nMOVL $%d,BX\nCMPL AX,BX\n%s ret+0(FP)", a, b, condition)}
			if want[index] {
				row.want = 1
			}
			rows = append(rows, row)
		}
	}
	for _, raw := range []int{2, 3, 255} {
		rows = append(rows, x86ABI0Mode32BoolRuntimeRow{body: fmt.Sprintf("MOVB $%d,ret+0(FP)\nMOVBLZX ret+0(FP),AX\nTESTL AX,AX\nSETNE ret+0(FP)", raw), want: 1})
	}
	return rows
}

func x86ABI0Mode32BoolRuntimeSource(rows []x86ABI0Mode32BoolRuntimeRow) (assembly, invalid, declarations, observers, observerDeclarations string) {
	var target, bad, declared, observed, observeDecl strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&target, "TEXT ·Bool%d(SB),4,$0-1\n%s\nRET\n", index, row.body)
		fmt.Fprintf(&declared, "func Bool%d() bool\n", index)
	}
	// These invalid bool representations are observed only by the raw caller,
	// never called as logical Go bools or normalized by the LLVM bool transport.
	for index, raw := range []int{2, 3, 255} {
		fmt.Fprintf(&bad, "TEXT ·Bad%d(SB),4,$0-1\nMOVB $%d,ret+0(FP)\nRET\n", index, raw)
		fmt.Fprintf(&declared, "func Bad%d() bool\n", index)
	}
	for index := 0; index < len(rows)+3; index++ {
		callee := fmt.Sprintf("Bool%d", index)
		if index >= len(rows) {
			callee = fmt.Sprintf("Bad%d", index-len(rows))
		}
		fmt.Fprintf(&observeDecl, "func Observe%d() uint64\n", index)
		fmt.Fprintf(&observed, `TEXT ·Observe%d(SB),4,$16-8
MOVL $0x5a5a5a5a,0(SP)
MOVL $0x11223344,4(SP)
CALL ·%s(SB)
MOVL 0(SP),AX
MOVL AX,ret+0(FP)
MOVL 4(SP),AX
MOVL AX,ret+4(FP)
RET
`, index, callee)
	}
	return target.String(), bad.String(), declared.String(), observed.String(), observeDecl.String()
}

// The portable inventory checks whole fixture members and independent expected
// outcomes. It is not an assembler, object, native caller or execution receipt.
func TestX86ABI0Mode32BoolRuntimeFixtureInventory(t *testing.T) {
	rows := x86ABI0Mode32BoolRuntimeRows()
	if len(rows) != 99 {
		t.Fatal("missing SETcc or raw-byte restoration rows", len(rows))
	}
	for condition := range amd64RegisterBoolConditions {
		seen := [2]bool{}
		for values := 0; values < 6; values++ {
			seen[rows[16*values+condition].want] = true
		}
		if !seen[0] || !seen[1] {
			t.Fatal("condition lacks independent true/false controls", amd64RegisterBoolConditions[condition])
		}
	}
	assembly, invalid, declarations, observers, observerDecl := x86ABI0Mode32BoolRuntimeSource(rows)
	for _, member := range []struct {
		source string
		prefix string
		count  int
	}{{assembly, "Bool", 99}, {invalid, "Bad", 3}, {observers, "Observe", 102}} {
		file, err := Parse(ArchAMD64, member.source)
		if err != nil || len(file.Funcs) != member.count || len(file.Data) != 0 || len(file.Globl) != 0 {
			t.Fatal("complete fixture member changed its TEXT/DATA inventory", member.prefix, err)
		}
		for index, fn := range file.Funcs {
			if fn.Sym != fmt.Sprintf("·%s%d", member.prefix, index) {
				t.Fatal("complete source member order changed", fn.Sym)
			}
		}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "bool.go", "package main\n"+declarations+observerDecl, 0); err != nil {
		t.Fatal("original Go bool/raw caller declarations are malformed", err)
	}
	if strings.Contains(assembly, "·Bad") || strings.Contains(invalid, "·Bool") || strings.Count(observers, "CALL ·Bool") != 99 || strings.Count(observers, "CALL ·Bad") != 3 {
		t.Fatal("valid and invalid complete original members or raw caller controls were merged/cropped")
	}
}
