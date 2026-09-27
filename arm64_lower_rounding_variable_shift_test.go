package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64VariableShift(base uint32, elementBits int, fullVector bool, shifts, value, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	word := base | size<<22 | uint32(shifts)<<16 | uint32(value)<<5 | uint32(destination)
	if fullVector {
		word |= 1 << 30
	}
	return word
}

func TestTranslateARM64RawVariableShiftCompleteArchitectureFamily(t *testing.T) {
	families := []struct {
		name string
		base uint32
	}{
		{name: "VSSHL", base: 0x0e204400},
		{name: "VSRSHL", base: 0x0e205400},
		{name: "VUSHL", base: 0x2e204400},
		{name: "VURSHL", base: 0x2e205400},
	}
	type form struct {
		elementBits int
		fullVector  bool
	}
	forms := []form{
		{elementBits: 8}, {elementBits: 8, fullVector: true},
		{elementBits: 16}, {elementBits: 16, fullVector: true},
		{elementBits: 32}, {elementBits: 32, fullVector: true},
		{elementBits: 64, fullVector: true},
	}

	var source strings.Builder
	source.WriteString("TEXT ·variableShiftArchitectureForms(SB), $0-0\n")
	for _, family := range families {
		for _, form := range forms {
			word := encodeARM64VariableShift(family.base, form.elementBits, form.fullVector, 30, 29, 28)
			decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			if err != nil {
				t.Fatalf("decode %s %d-bit Q=%v: %v", family.name, form.elementBits, form.fullVector, err)
			}
			if decoded.Op != Op(family.name) || len(decoded.Args) != 3 ||
				!strings.HasPrefix(string(decoded.Args[0].Reg), "V30.") ||
				!strings.HasPrefix(string(decoded.Args[1].Reg), "V29.") ||
				!strings.HasPrefix(string(decoded.Args[2].Reg), "V28.") {
				t.Fatalf("decoded %s %d-bit Q=%v %#08x as %#v; want reversed Vm=V30, Vn=V29, Vd=V28", family.name, form.elementBits, form.fullVector, word, decoded)
			}
			fmt.Fprintf(&source, "\tWORD $%#08x // %s %d-bit Q=%v\n", word, family.name, form.elementBits, form.fullVector)
		}
		// The architecture has one additional scalar D form. It shares the
		// size=3 encoding but has Q=0 and decodes to bare V registers.
		scalarBase := family.base | 0x50000000
		word := encodeARM64VariableShift(scalarBase, 64, false, 30, 29, 28)
		decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
		if err != nil {
			t.Fatalf("decode scalar %s: %v", family.name, err)
		}
		if decoded.Op != Op(family.name) || len(decoded.Args) != 3 || decoded.Args[0].Reg != "V30" || decoded.Args[1].Reg != "V29" || decoded.Args[2].Reg != "V28" {
			t.Fatalf("decoded scalar %s %#08x as %#v; want V30, V29, V28", family.name, word, decoded)
		}
		fmt.Fprintf(&source, "\tWORD $%#08x // scalar %s D\n", word, family.name)
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
					"variableShiftArchitectureForms": {Name: "variableShiftArchitectureForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{"sshl", "srshl", "ushl", "urshl"} {
				if got := strings.Count(ll, " = call "); got != 32 {
					t.Fatalf("%s emitted %d intrinsic calls, want 32:\n%s", triple, got, ll)
				}
				if !strings.Contains(ll, "@llvm.aarch64.neon."+intrinsic+".i64") || !strings.Contains(ll, "@llvm.aarch64.neon."+intrinsic+".v16i8") {
					t.Fatalf("%s omitted scalar or vector %s intrinsic:\n%s", triple, intrinsic, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-variable-shift.ll", "arm64-variable-shift.o", ll)
		})
	}
}

func TestTranslateARM64VariableShiftRejectsInvalidArchitectureForms(t *testing.T) {
	for _, instruction := range []string{
		"VSRSHL V0.B8, V1.B8",
		"VURSHL V0.B8, V1.B16, V2.B8",
		"VSRSHL V0.D1, V1.D1, V2.D1",
		"VURSHL V0, V1.D2, V2.D2",
		"VSRSHL.P V0.H8, V1.H8, V2.H8",
	} {
		file, err := Parse(ArchARM64, "TEXT ·badVariableShift(SB), $0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs:         map[string]FuncSig{"badVariableShift": {Name: "badVariableShift", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted invalid ARM64 variable-shift form %q", instruction)
		}
	}
}
