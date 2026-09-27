package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEFirstFaultMemoryCompleteGo127Forms() string {
	return `TEXT svefirstfaultmemoryforms(SB),$0-0
	ZLDFF1B (R7)(RSP), P4.Z, [Z13.B]
	ZLDFF1B (R6)(R14), P4.Z, [Z13.H]
	ZLDFF1B (R5)(R27), P3.Z, [Z6.S]
	ZLDFF1B (R2)(R3), P2.Z, [Z24.D]
	ZLDFF1B (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1B (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1B (Z5.D.SXTW)(R12), P2.Z, [Z11.D]
	ZLDFF1B (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLDFF1B (Z9.S.SXTW)(R8), P5.Z, [Z10.S]
	ZLDFF1B (Z7.S), P4.Z, [Z13.S]
	ZLDFF1B 31(Z7.D), P4.Z, [Z13.D]

	ZLDFF1H (R7<<1)(R14), P4.Z, [Z13.H]
	ZLDFF1H (R6<<1)(R14), P4.Z, [Z13.S]
	ZLDFF1H (R5<<1)(R27), P3.Z, [Z6.D]
	ZLDFF1H (Z10.D)(RSP), P3.Z, [Z15.D]
	ZLDFF1H (Z23.D<<1)(R24), P1.Z, [Z22.D]
	ZLDFF1H (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1H (Z5.D.SXTW<<1)(R12), P2.Z, [Z11.D]
	ZLDFF1H (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLDFF1H (Z9.S.SXTW<<1)(R8), P5.Z, [Z10.S]
	ZLDFF1H (Z7.S), P4.Z, [Z13.S]
	ZLDFF1H 62(Z7.D), P4.Z, [Z13.D]

	ZLDFF1W (R7<<2)(R14), P4.Z, [Z13.S]
	ZLDFF1W (R6<<2)(R14), P4.Z, [Z13.D]
	ZLDFF1W (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1W (Z23.D<<2)(R24), P1.Z, [Z22.D]
	ZLDFF1W (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1W (Z5.D.SXTW<<2)(R12), P2.Z, [Z11.D]
	ZLDFF1W (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLDFF1W (Z9.S.SXTW<<2)(R8), P5.Z, [Z10.S]
	ZLDFF1W (Z7.S), P4.Z, [Z13.S]
	ZLDFF1W 124(Z7.D), P4.Z, [Z13.D]

	ZLDFF1D (R7<<3)(R14), P4.Z, [Z13.D]
	ZLDFF1D (R6<<3)(R14), P4.Z, [Z13.D]
	ZLDFF1D (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1D (Z23.D<<3)(R24), P1.Z, [Z22.D]
	ZLDFF1D (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1D (Z5.D.SXTW<<3)(R12), P2.Z, [Z11.D]
	ZLDFF1D (Z7.D), P4.Z, [Z13.D]
	ZLDFF1D 248(Z7.D), P4.Z, [Z13.D]

	ZLDFF1SB (R7)(R14), P4.Z, [Z13.H]
	ZLDFF1SB (R6)(R14), P4.Z, [Z13.S]
	ZLDFF1SB (R5)(R27), P3.Z, [Z6.D]
	ZLDFF1SB (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1SB (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1SB (Z5.D.SXTW)(R12), P2.Z, [Z11.D]
	ZLDFF1SB (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLDFF1SB (Z9.S.SXTW)(R8), P5.Z, [Z10.S]
	ZLDFF1SB (Z7.S), P4.Z, [Z13.S]
	ZLDFF1SB 31(Z7.D), P4.Z, [Z13.D]

	ZLDFF1SH (R7<<1)(R14), P4.Z, [Z13.S]
	ZLDFF1SH (R6<<1)(R14), P4.Z, [Z13.D]
	ZLDFF1SH (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1SH (Z23.D<<1)(R24), P1.Z, [Z22.D]
	ZLDFF1SH (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1SH (Z5.D.SXTW<<1)(R12), P2.Z, [Z11.D]
	ZLDFF1SH (Z4.S.UXTW)(R3), P3.Z, [Z4.S]
	ZLDFF1SH (Z9.S.SXTW<<1)(R8), P5.Z, [Z10.S]
	ZLDFF1SH (Z7.S), P4.Z, [Z13.S]
	ZLDFF1SH 62(Z7.D), P4.Z, [Z13.D]

	ZLDFF1SW (R7<<2)(R14), P4.Z, [Z13.D]
	ZLDFF1SW (R6<<2)(R14), P4.Z, [Z13.D]
	ZLDFF1SW (Z10.D)(R19), P3.Z, [Z15.D]
	ZLDFF1SW (Z23.D<<2)(R24), P1.Z, [Z22.D]
	ZLDFF1SW (Z6.D.UXTW)(R14), P4.Z, [Z13.D]
	ZLDFF1SW (Z5.D.SXTW<<2)(R12), P2.Z, [Z11.D]
	ZLDFF1SW (Z7.D), P4.Z, [Z13.D]
	ZLDFF1SW 124(Z7.D), P4.Z, [Z13.D]
	RET
`
}

func TestTranslateARM64SVEFirstFaultMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVEFirstFaultMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefirstfaultmemoryforms": {Name: "svefirstfaultmemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.ldff1.nxv",
				"@llvm.aarch64.sve.ldff1.gather.nxv",
				"@llvm.aarch64.sve.ldff1.gather.index.nxv",
				"@llvm.aarch64.sve.ldff1.gather.uxtw.nxv",
				"@llvm.aarch64.sve.ldff1.gather.uxtw.index.nxv",
				"@llvm.aarch64.sve.ldff1.gather.sxtw.nxv",
				"@llvm.aarch64.sve.ldff1.gather.sxtw.index.nxv",
				"@llvm.aarch64.sve.ldff1.gather.scalar.offset.",
				" sext <vscale x ",
				" zext <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE first-fault memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-first-fault-memory.ll", "arm64-sve-first-fault-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVEFirstFaultMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLDFF1B (R6)(R14), P8.Z, [Z13.B]",
		"ZLDFF1H (R6)(R14), P4.Z, [Z13.H]",
		"ZLDFF1W (R6<<1)(R14), P4.Z, [Z13.S]",
		"ZLDFF1D (R6<<2)(R14), P4.Z, [Z13.D]",
		"ZLDFF1SB (R6)(R14), P4.Z, [Z13.B]",
		"ZLDFF1SH (R6<<1)(R14), P4.Z, [Z13.H]",
		"ZLDFF1SW (R6<<2)(R14), P4.Z, [Z13.S]",
		"ZLDFF1B (Z4.S)(R3), P3.Z, [Z4.S]",
		"ZLDFF1H (Z4.S.UXTW<<2)(R3), P3.Z, [Z4.S]",
		"ZLDFF1W (Z4.D.UXTW<<1)(R3), P3.Z, [Z4.D]",
		"ZLDFF1D (Z4.S.UXTW<<3)(R3), P3.Z, [Z4.D]",
		"ZLDFF1B -1(Z7.S), P4.Z, [Z13.S]",
		"ZLDFF1H 3(Z7.S), P4.Z, [Z13.S]",
		"ZLDFF1W 128(Z7.S), P4.Z, [Z13.S]",
		"ZLDFF1D 256(Z7.D), P4.Z, [Z13.D]",
		"ZLDFF1W 12(Z7.D), P4.Z, [Z13.S]",
		"ZLDFF1B (R6)(R14), P4.Z, [Z13.B-Z14.B]",
		"ZLDFF1B.Z (R6)(R14), P4.Z, [Z13.B]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefirstfaultmemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefirstfaultmemory": {Name: "badsvefirstfaultmemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's first-fault memory forms", instruction)
			}
		})
	}
}
