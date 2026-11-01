package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawUnscaledMemoryCompleteArchitecturalFamily(t *testing.T) {
	forms := []struct {
		word uint32
		op   Op
	}{
		{0xb84bf1a1, "MOVWU"}, // LDUR W1, [X13,#191]
		{0xf85c42c3, "MOVD"},  // LDUR X3, [X22,#-60]
		{0x3850122e, "MOVBU"}, // LDURB W14, [X17,#-255]
		{0x78480026, "MOVHU"}, // LDURH W6, [X1,#128]
		{0x38cde3c3, "MOVBW"}, // LDURSB W3, [X30,#222]
		{0x38896127, "MOVB"},  // LDURSB X7, [X9,#150]
		{0x78db717c, "MOVHW"}, // LDURSH W28, [X11,#-73]
		{0x789e101d, "MOVH"},  // LDURSH X29, [X0,#-31]
		{0xb88480d4, "MOVW"},  // LDURSW X20, [X6,#72]
		{0xb8022015, "MOVW"},  // STUR W21, [X0,#34]
		{0xf8177239, "MOVD"},  // STUR X25, [X17,#-137]
		{0x3801328f, "MOVB"},  // STURB W15, [X20,#19]
		{0x781b02eb, "MOVH"},  // STURH W11, [X23,#-80]
		{0x3c5df1b8, "FMOVB"}, // LDUR B24, [X13,#-33]
		{0x7c5c6395, "FMOVH"}, // LDUR H21, [X28,#-58]
		{0xbc46d027, "FMOVS"}, // LDUR S7, [X1,#109]
		{0xfc4e6221, "FMOVD"}, // LDUR D1, [X17,#230]
		{0x3cd8d26d, "FMOVQ"}, // LDUR Q13, [X19,#-115]
		{0x3c0ab0a7, "FMOVB"}, // STUR B7, [X5,#171]
		{0x7c10e340, "FMOVH"}, // STUR H0, [X26,#-242]
		{0xbc1f9118, "FMOVS"}, // STUR S24, [X8,#-7]
		{0xfc07c0fc, "FMOVD"}, // STUR D28, [X7,#124]
		{0x3c8912db, "FMOVQ"}, // STUR Q27, [X22,#145]
	}

	var source strings.Builder
	source.WriteString("TEXT rawUnscaledMemory(SB), $0-0\n")
	for _, form := range forms {
		ins := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(form.word)}}, Raw: fmt.Sprintf("WORD $%#08x", form.word)}
		decoded, err := decodeARM64RawWordInstruction(ins)
		if err != nil {
			t.Fatalf("decode %#08x: %v", form.word, err)
		}
		if decoded.Op != form.op {
			t.Fatalf("decode %#08x op = %s, want %s (%q)", form.word, decoded.Op, form.op, decoded.Raw)
		}
		fmt.Fprintf(&source, "\tWORD $%#08x\n", form.word)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawUnscaledMemory": {Name: "rawUnscaledMemory", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i8", "load i16", "load i32", "load i64", "load <16 x i8>", "store i8", "store i16", "store i32", "store i64", "store <16 x i8>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("unscaled memory lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-unscaled-memory.ll", "arm64-raw-unscaled-memory.o", ll)
		})
	}
}
