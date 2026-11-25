package arm64

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestARM64DeclarativeOpTableAndRawWordDecode(t *testing.T) {
	if len(DeclarativeOpNames()) < 40 {
		t.Fatalf("expected >=40 declarative arm64 ops, got %d", len(DeclarativeOpNames()))
	}
	if spec, ok := OpTable.Lookup("CRC32CX"); !ok || spec.ArchFeature != "+crc" {
		t.Fatalf("OpTable.Lookup(CRC32CX) = (%#v, %v)", spec, ok)
	}

	tests := []struct {
		word   uint32
		wantOp asm.Op
	}{
		{0xea00001f, "TST"},
		{0xf1004000, "SUBS"},
		{0xd503201f, "NOP"},
		{0x4e284820, "AESE"},
	}
	for _, tc := range tests {
		ins, ok := DecodeRawWord(tc.word)
		if !ok || !ins.DecodedFromRaw || ins.Op != tc.wantOp {
			t.Fatalf("DecodeRawWord(0x%08x) = (%#v, %v), want Op=%s", tc.word, ins, ok, tc.wantOp)
		}
	}

	// Verify decoded WORD lowers through TranslateFunc cleanly:
	// 0x8b010000 = ADD R1, R0, R0
	// 0x4e284820 = AESE V1.B16, V0.B16 (also verifies scanUsedRegs pre-allocates %v0/%v1)
	// 0xd5033bbf = DMB ISH, 0xd5033fdf = ISB (must emit memory fence, not silently drop)
	// 0xaa0103e0 = MOVD R1, R0 (lowerData), 0x1e612800 = FADDD F1, F0, F0 (lowerFP),
	// 0x9ac15000 = CRC32CX R1, R0 (lowerScalarDeclarative), 0x4ea18400 = VADD V1.S4, V0.S4, V0.S4
	file, err := asm.Parse(asm.ArchARM64, `TEXT ·raw(SB),NOSPLIT,$0-0
	WORD $0xd503201f
	WORD $0xd5033bbf
	WORD $0xd5033fdf
	WORD $0x8b010000
	WORD $0x4e284820
	WORD $0xaa0103e0
	WORD $0x1e612800
	WORD $0x9ac15000
	WORD $0x4ea18400
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := TranslateFunc(&b, file.Funcs[0], asm.FuncSig{Name: "example.raw", Ret: asm.I64}, testResolveSym("example"), nil, false); err != nil {
		t.Fatalf("TranslateFunc(WORD ADD+AESE) error = %v", err)
	}
	ir := b.String()
	for _, want := range []string{"fence seq_cst", "add i64", "%v0 = alloca <16 x i8>", "%v1 = alloca <16 x i8>"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("expected %q in IR:\n%s", want, ir)
		}
	}
}
