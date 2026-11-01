package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const x86LegacyPackedLogicalMMXRuntimeSource = `TEXT legacypackedlogicalsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	STC
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PAND M0, M1
	MOVQ M1, 0(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PANDN M0, M1
	MOVQ M1, 8(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	POR M0, M1
	MOVQ M1, 16(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PXOR M0, M1
	MOVQ M1, 24(AX)
	EMMS
	SETCS 32(AX)
	RET
`

const x86PADDDGoAliasRuntimeSource = `TEXT padddaliassemantics(SB),$0-24
	MOVQ out+0(FP), AX
	STC
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PADDD M0, M1
	MOVQ M1, 0(AX)
	EMMS
	SETCS 8(AX)
	RET
`

func TestX86MMXOriginalScalarLogicalAndPADDDObjects(t *testing.T) {
	for _, fixture := range []struct{ name, source, declaration string }{
		{"logical", x86LegacyPackedLogicalMMXRuntimeSource, "func legacypackedlogicalsemantics(out *byte,a,b uint64)"},
		{"paddd", x86PADDDGoAliasRuntimeSource, "func padddaliassemantics(out *byte,a,b uint64)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			x86MMXOriginalFixtureObjects(t, fixture.source, fixture.declaration)
		})
	}
}

func TestX86MMXAverageOriginalFixtureObjects(t *testing.T) {
	var rows []x86AverageNumericCase
	for _, row := range x86AverageNumericCases() {
		if row.mmx {
			rows = append(rows, row)
		}
	}
	if len(rows) != 4 {
		t.Fatal("complete original MMX average denominator changed", len(rows))
	}
	source, _, _ := x86AverageNumericFixture(t, rows)
	var declarations strings.Builder
	for index := range rows {
		fmt.Fprintf(&declarations, "func average%d(out,a,b *byte,mask,flags uint64)\n", index)
	}
	x86MMXOriginalFixtureObjects(t, source, declarations.String())
}

func TestX86MMXWrappingAddOriginalFixtureObjects(t *testing.T) {
	var source, declarations strings.Builder
	count := 0
	for _, op := range []string{"PADDB", "PADDW", "PADDL"} {
		for _, input := range []string{"M1", "(BX)"} {
			name := fmt.Sprintf("Add%d", count)
			source.WriteString(x86PackedAddMMXAssembly(name, op, input))
			fmt.Fprintf(&declarations, "func %s(out,a,b *byte,mask uint64)\n", name)
			count++
		}
	}
	if count != 6 {
		t.Fatal("complete original MMX wrapping add denominator changed", count)
	}
	x86MMXOriginalFixtureObjects(t, source.String(), declarations.String())
}
