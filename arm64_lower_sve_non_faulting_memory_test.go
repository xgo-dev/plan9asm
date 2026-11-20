package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVENonFaultingMemoryCompleteGo127Forms() string {
	return `TEXT svenonfaultingmemoryforms(SB),$0-0
	ZLDNF1B (-VL*8)(R14), P4.Z, [Z13.B]
	ZLDNF1B (VL*7)(RSP), P3.Z, [Z12.H]
	ZLDNF1B (VL*0)(R4), P2.Z, [Z11.S]
	ZLDNF1B (-VL*2)(R5), P1.Z, [Z10.D]
	ZLDNF1H (VL*7)(R14), P4.Z, [Z13.H]
	ZLDNF1H (-VL*8)(RSP), P3.Z, [Z12.S]
	ZLDNF1H (VL*0)(R4), P2.Z, [Z11.D]
	ZLDNF1W (-VL*8)(R14), P4.Z, [Z13.S]
	ZLDNF1W (VL*7)(RSP), P3.Z, [Z12.D]
	ZLDNF1D (-VL*8)(R14), P4.Z, [Z13.D]
	ZLDNF1SB (VL*7)(RSP), P3.Z, [Z12.H]
	ZLDNF1SB (VL*0)(R4), P2.Z, [Z11.S]
	ZLDNF1SB (-VL*2)(R5), P1.Z, [Z10.D]
	ZLDNF1SH (VL*7)(R14), P4.Z, [Z13.S]
	ZLDNF1SH (-VL*8)(RSP), P3.Z, [Z12.D]
	ZLDNF1SW (VL*0)(R4), P2.Z, [Z11.D]
	RET
`
}

func TestTranslateARM64SVENonFaultingMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVENonFaultingMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svenonfaultingmemoryforms": {Name: "svenonfaultingmemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.ldnf1.nxv16i8",
				"@llvm.aarch64.sve.ldnf1.nxv8i16",
				"@llvm.aarch64.sve.ldnf1.nxv4i32",
				"@llvm.aarch64.sve.ldnf1.nxv2i64",
				" sext <vscale x ",
				" zext <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE non-faulting memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-non-faulting-memory.ll", "arm64-sve-non-faulting-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVENonFaultingMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLDNF1B (R14), P8.Z, [Z13.B]",
		"ZLDNF1B (R14), P4, [Z13.B]",
		"ZLDNF1B (R14), P4.Z, [Z13.B, Z14.B]",
		"ZLDNF1H (R14), P4.Z, [Z13.B]",
		"ZLDNF1W (R14), P4.Z, [Z13.H]",
		"ZLDNF1D (R14), P4.Z, [Z13.S]",
		"ZLDNF1SB (R14), P4.Z, [Z13.B]",
		"ZLDNF1SH (R14), P4.Z, [Z13.H]",
		"ZLDNF1SW (R14), P4.Z, [Z13.S]",
		"ZLDNF1B (R6)(R14), P4.Z, [Z13.B]",
		"ZLDNF1B (-VL*9)(R14), P4.Z, [Z13.B]",
		"ZLDNF1B (VL*8)(R14), P4.Z, [Z13.B]",
		"ZLDNF1B 6(R14), P4.Z, [Z13.B]",
		"ZLDNF1B.Z (R14), P4.Z, [Z13.B]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvenonfaultingmemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvenonfaultingmemory": {Name: "badsvenonfaultingmemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's non-faulting memory forms", instruction)
			}
		})
	}
}
