package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawZeroFrameTypedVoidPreservesFixedEntryRegisters(t *testing.T) {
	words := assembleARM64LLVMWords(t, []string{"add x28,sp,#0", "add x18,sp,#0"}, "")
	for index, reg := range []string{"g", "reserved_r18"} {
		t.Run(reg, func(t *testing.T) {
			source := arm64RawZeroFrameFixture(516, false, fmt.Sprintf("WORD $%#08x\nMOVD R4,(R1)\n", words[index]))
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := arm64RawZeroFrameSig()
			transport := &arm64PrivateFrameTransport{entry: sig}
			if arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], transport) {
				t.Fatal("typed void consumed an unrestored fixed entry register")
			}
		})
	}
}

func arm64RawZeroFixedFixture(t *testing.T, middle string) string {
	t.Helper()
	words := assembleARM64LLVMWords(t, []string{
		"stp x28,x18,[sp,#-16]!", "add x28,sp,#0", "add x18,sp,#0", "ldp x28,x18,[sp],#16",
	}, "")
	body := fmt.Sprintf("WORD $%#08x\nWORD $%#08x\nWORD $%#08x\n%s\nWORD $%#08x\nMOVD RSP,R9\nMOVD R4,(R1)\n", words[0], words[1], words[2], middle, words[3])
	return arm64RawZeroFrameFixture(516, false, body)
}

func TestARM64RawZeroFrameFixedRegisterSaveRestoreAndOverlap(t *testing.T) {
	source := arm64RawZeroFixedFixture(t, "")
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	transport := &arm64PrivateFrameTransport{entry: sig}
	if !arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], transport) {
		t.Fatal("original raw STP/LDP did not restore exact g/OS entry state")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "fixed-entry.ll", "fixed-entry.o", ir)
	}
	// Restore must preserve the complete eight-byte identity, not just a
	// pointer-shaped may-frame taint or the eventual SP/LR balance.
	for _, middle := range []string{
		"MOVB R4,0(RSP)", "MOVH R4,0(RSP)", "MOVW R4,0(RSP)", "MOVD R4,0(RSP)",
		"MOVB R4,8(RSP)", "MOVH R4,8(RSP)", "MOVW R4,8(RSP)", "MOVD R4,8(RSP)",
		"MOVB R4,16(RSP)", "MOVD R4,24(RSP)",
		"MOVD 0(RSP),R9\nMOVD R9,(R1)",
		"MOVD 8(RSP),R9\nMOVD R9,holder(SB)",
		"MOVD (RSP)(R0),R9", "WORD $0xffffffff", "CALL foreign(SB)",
		"CBZ R0,joined\nMOVB R4,0(RSP)\njoined:",
	} {
		t.Run(middle, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64RawZeroFixedFixture(t, middle))
			if err != nil {
				t.Fatal(err)
			}
			if arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], transport) {
				t.Fatal("partial/aliased/unknown save-cell write erased fixed entry identity")
			}
		})
	}
	for _, reg := range []string{"x18", "x28", "x29", "x30"} {
		word := assembleARM64LLVMWords(t, []string{"mov " + reg + ",#0"}, "")[0]
		broken := strings.Replace(source, "WORD $0xd65f03c0", fmt.Sprintf("WORD $%#08x\nWORD $0xd65f03c0", word), 1)
		requireARM64GoAssemblerResult(t, broken, true)
		file, err := Parse(ArchARM64, broken)
		if err != nil {
			t.Fatal(err)
		}
		if arm64RawZeroFrameUnexposedForTransport(file.Funcs[0], transport) {
			t.Fatalf("constant non-address overwrite lost preserved %s", reg)
		}
	}
}
