package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64VectorWideningAddSubtract(base uint32, elementBits, narrow, wide, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2}[elementBits]
	return base | size<<22 | uint32(narrow)<<16 | uint32(wide)<<5 | uint32(destination)
}

func TestTranslateARM64RawWideningAddSubtractCompleteArchitectureFamily(t *testing.T) {
	// These are the complete AdvSIMD three-different add/subtract-long and
	// add/subtract-wide rows in x/arch's ARM64 architecture table.
	families := []struct {
		name string
		base uint32
	}{
		{name: "VSADDL", base: 0x0e200000},
		{name: "VSADDL2", base: 0x4e200000},
		{name: "VSADDW", base: 0x0e201000},
		{name: "VSADDW2", base: 0x4e201000},
		{name: "VSSUBL", base: 0x0e202000},
		{name: "VSSUBL2", base: 0x4e202000},
		{name: "VSSUBW", base: 0x0e203000},
		{name: "VSSUBW2", base: 0x4e203000},
		{name: "VUADDL", base: 0x2e200000},
		{name: "VUADDL2", base: 0x6e200000},
		{name: "VUADDW", base: 0x2e201000},
		{name: "VUADDW2", base: 0x6e201000},
		{name: "VUSUBL", base: 0x2e202000},
		{name: "VUSUBL2", base: 0x6e202000},
		{name: "VUSUBW", base: 0x2e203000},
		{name: "VUSUBW2", base: 0x6e203000},
	}

	var source strings.Builder
	source.WriteString("TEXT ·wideningAddSubtractForms(SB), $0-0\n")
	for _, family := range families {
		for _, elementBits := range []int{8, 16, 32} {
			word := encodeARM64VectorWideningAddSubtract(family.base, elementBits, 30, 29, 28)
			decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			if err != nil {
				t.Fatalf("decode %s %d-bit: %v", family.name, elementBits, err)
			}
			if decoded.Op != Op(family.name) || len(decoded.Args) != 3 ||
				!strings.HasPrefix(string(decoded.Args[0].Reg), "V30.") ||
				!strings.HasPrefix(string(decoded.Args[1].Reg), "V29.") ||
				!strings.HasPrefix(string(decoded.Args[2].Reg), "V28.") {
				t.Fatalf("decoded %s %d-bit %#08x as %#v; want reversed Vm=V30, Vn=V29, Vd=V28", family.name, elementBits, word, decoded)
			}
			fmt.Fprintf(&source, "\tWORD $%#08x // %s %d-bit\n", word, family.name, elementBits)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"wideningAddSubtractForms": {Name: "wideningAddSubtractForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for operation, want := range map[string]int{
				" = zext <":          36,
				" = sext <":          36,
				" = add <":           24,
				" = sub <":           24,
				" = shufflevector <": 72,
			} {
				if got := strings.Count(ll, operation); got != want {
					t.Fatalf("%s emitted %d occurrences of %q, want %d:\n%s", triple, got, operation, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-widening-add-sub.ll", "arm64-widening-add-sub.o", ll)
		})
	}
}

func TestTranslateARM64WideningAddSubtractRejectsInvalidArrangements(t *testing.T) {
	for _, instruction := range []string{
		"VUADDL V0.B16, V1.B16, V2.H8",
		"VUADDL2 V0.B8, V1.B8, V2.H8",
		"VSADDL V0.B8, V1.H4, V2.H8",
		"VSSUBL V0.H4, V1.H4, V2.S2",
		"VUSUBW V0.B16, V1.H8, V2.H8",
		"VUSUBW2 V0.B8, V1.H8, V2.H8",
		"VSADDW V0.B8, V1.H8, V2.S4",
		"VSSUBW V0.B8, V1.H8",
		"VSSUBW.P V0.B8, V1.H8, V2.H8",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT ·badWidening(SB), $0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs:         map[string]FuncSig{"badWidening": {Name: "badWidening", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted invalid ARM64 widening add/subtract form %q", instruction)
			}
		})
	}
}
