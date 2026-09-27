package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVENonTemporalMemoryCompleteGo127Forms() string {
	return `TEXT svenontemporalmemoryforms(SB),$0-0
	ZLDNT1B (R6)(R14), P4.Z, [Z13.B]
	ZLDNT1B (R6)(Z7.S), P4.Z, [Z13.S]
	ZLDNT1B (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1B (-VL*2)(R14), P4.Z, [Z13.B]
	ZLDNT1B (R5)(R27), PN12.Z, [Z6.B-Z7.B]
	ZLDNT1B (R2)(R3), PN10.Z, [Z24.B-Z27.B]
	ZLDNT1B (-VL*6)(R3), PN10.Z, [Z24.B-Z25.B]
	ZLDNT1B (VL*4)(RSP), PN10.Z, [Z16.B-Z19.B]
	ZLDNT1H (R6<<1)(R14), P4.Z, [Z13.H]
	ZLDNT1H (R6)(Z7.S), P4.Z, [Z13.S]
	ZLDNT1H (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1H (-VL*2)(R14), P4.Z, [Z13.H]
	ZLDNT1H (R5<<1)(R27), PN12.Z, [Z6.H-Z7.H]
	ZLDNT1H (R2<<1)(R3), PN10.Z, [Z24.H-Z27.H]
	ZLDNT1H (-VL*6)(R3), PN10.Z, [Z24.H-Z25.H]
	ZLDNT1H (VL*4)(RSP), PN10.Z, [Z16.H-Z19.H]
	ZLDNT1W (R6<<2)(R14), P4.Z, [Z13.S]
	ZLDNT1W (R6)(Z7.S), P4.Z, [Z13.S]
	ZLDNT1W (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1W (-VL*2)(R14), P4.Z, [Z13.S]
	ZLDNT1W (R5<<2)(R27), PN12.Z, [Z6.S-Z7.S]
	ZLDNT1W (R2<<2)(R3), PN10.Z, [Z24.S-Z27.S]
	ZLDNT1W (-VL*6)(R3), PN10.Z, [Z24.S-Z25.S]
	ZLDNT1W (VL*4)(RSP), PN10.Z, [Z16.S-Z19.S]
	ZLDNT1D (R6<<3)(R14), P4.Z, [Z13.D]
	ZLDNT1D (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1D (-VL*2)(R14), P4.Z, [Z13.D]
	ZLDNT1D (-VL*8)(R14), P4.Z, [Z12.D]
	ZLDNT1D (VL*7)(R14), P4.Z, [Z11.D]
	ZLDNT1D (R5<<3)(R27), PN12.Z, [Z6.D-Z7.D]
	ZLDNT1D (R2<<3)(R3), PN10.Z, [Z24.D-Z27.D]
	ZLDNT1D (-VL*6)(R3), PN10.Z, [Z24.D-Z25.D]
	ZLDNT1D (-VL*16)(R3), PN10.Z, [Z20.D-Z21.D]
	ZLDNT1D (VL*14)(R3), PN10.Z, [Z18.D-Z19.D]
	ZLDNT1D (VL*4)(RSP), PN10.Z, [Z16.D-Z19.D]
	ZLDNT1D (-VL*32)(RSP), PN10.Z, [Z8.D-Z11.D]
	ZLDNT1D (VL*28)(RSP), PN10.Z, [Z12.D-Z15.D]
	ZLDNT1SB (R6)(Z7.S), P4.Z, [Z13.S]
	ZLDNT1SB (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1SH (R6)(Z7.S), P4.Z, [Z13.S]
	ZLDNT1SH (R6)(Z7.D), P4.Z, [Z13.D]
	ZLDNT1SW (R6)(Z7.D), P4.Z, [Z13.D]
	ZSTNT1B [Z8.B], P3, (R6)(RSP)
	ZSTNT1B [Z8.S], P3, (R6)(Z15.S)
	ZSTNT1B [Z8.D], P3, (R6)(Z15.D)
	ZSTNT1B [Z8.B], P3, (-VL*2)(RSP)
	ZSTNT1B [Z14.B-Z15.B], PN12, (R20)(R17)
	ZSTNT1B [Z4.B-Z7.B], PN12, (R12)(RSP)
	ZSTNT1B [Z14.B-Z15.B], PN12, (-VL*4)(R17)
	ZSTNT1B [Z4.B-Z7.B], PN12, (VL*4)(RSP)
	ZSTNT1H [Z8.H], P3, (R6<<1)(RSP)
	ZSTNT1H [Z8.S], P3, (R6)(Z15.S)
	ZSTNT1H [Z8.D], P3, (R6)(Z15.D)
	ZSTNT1H [Z8.H], P3, (-VL*2)(RSP)
	ZSTNT1H [Z14.H-Z15.H], PN12, (R20<<1)(R17)
	ZSTNT1H [Z4.H-Z7.H], PN12, (R12<<1)(RSP)
	ZSTNT1H [Z14.H-Z15.H], PN12, (-VL*4)(R17)
	ZSTNT1H [Z4.H-Z7.H], PN12, (VL*4)(RSP)
	ZSTNT1W [Z8.S], P3, (R6<<2)(RSP)
	ZSTNT1W [Z8.S], P3, (R6)(Z15.S)
	ZSTNT1W [Z8.D], P3, (R6)(Z15.D)
	ZSTNT1W [Z8.S], P3, (-VL*2)(RSP)
	ZSTNT1W [Z14.S-Z15.S], PN12, (R20<<2)(R17)
	ZSTNT1W [Z4.S-Z7.S], PN12, (R12<<2)(RSP)
	ZSTNT1W [Z14.S-Z15.S], PN12, (-VL*4)(R17)
	ZSTNT1W [Z4.S-Z7.S], PN12, (VL*4)(RSP)
	ZSTNT1D [Z8.D], P3, (R6<<3)(RSP)
	ZSTNT1D [Z8.D], P3, (R6)(Z15.D)
	ZSTNT1D [Z8.D], P3, (-VL*2)(RSP)
	ZSTNT1D [Z8.D], P3, (-VL*8)(RSP)
	ZSTNT1D [Z8.D], P3, (VL*7)(RSP)
	ZSTNT1D [Z14.D-Z15.D], PN12, (R20<<3)(R17)
	ZSTNT1D [Z4.D-Z7.D], PN12, (R12<<3)(RSP)
	ZSTNT1D [Z14.D-Z15.D], PN12, (-VL*4)(R17)
	ZSTNT1D [Z14.D-Z15.D], PN12, (-VL*16)(R17)
	ZSTNT1D [Z14.D-Z15.D], PN12, (VL*14)(R17)
	ZSTNT1D [Z4.D-Z7.D], PN12, (VL*4)(RSP)
	ZSTNT1D [Z4.D-Z7.D], PN12, (-VL*32)(RSP)
	ZSTNT1D [Z4.D-Z7.D], PN12, (VL*28)(RSP)
	RET
`
}

func TestTranslateARM64SVENonTemporalMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVENonTemporalMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svenontemporalmemoryforms": {Name: "svenontemporalmemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.ldnt1.nxv",
				"@llvm.aarch64.sve.ldnt1.gather.scalar.offset.",
				"@llvm.aarch64.sve.ldnt1.pn.x2.",
				"@llvm.aarch64.sve.ldnt1.pn.x4.",
				"@llvm.aarch64.sve.stnt1.nxv",
				"@llvm.aarch64.sve.stnt1.scatter.scalar.offset.",
				"@llvm.aarch64.sve.stnt1.pn.x2.",
				"@llvm.aarch64.sve.stnt1.pn.x4.",
				" sext <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE non-temporal memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-non-temporal-memory.ll", "arm64-sve-non-temporal-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVENonTemporalMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLDNT1B (R6)(R14), P8.Z, [Z13.B]",
		"ZLDNT1D (R6<<2)(R14), P4.Z, [Z13.D]",
		"ZLDNT1SB (R6)(Z7.S), P4.Z, [Z13.D]",
		"ZLDNT1W (R5<<2)(R27), PN7.Z, [Z6.S-Z7.S]",
		"ZLDNT1W (R5<<2)(R27), PN12.Z, [Z6.S-Z8.S]",
		"ZSTNT1H [Z8.H], P8, (R6<<1)(RSP)",
		"ZSTNT1W [Z14.S-Z16.S], PN12, (R20<<2)(R17)",
		"ZSTNT1D [Z8.D], P3, (R6<<2)(RSP)",
		"ZSTNT1B [Z8.H], P3, (-VL*2)(RSP)",
		"ZLDNT1D (-VL*9)(R14), P4.Z, [Z13.D]",
		"ZLDNT1D (VL*3)(R3), PN10.Z, [Z24.D-Z25.D]",
		"ZLDNT1D (VL*2)(RSP), PN10.Z, [Z16.D-Z19.D]",
		"ZSTNT1D [Z8.D], P3, (VL*8)(RSP)",
		"ZSTNT1D [Z14.D-Z15.D], PN12, (VL*16)(R17)",
		"ZSTNT1D [Z4.D-Z7.D], PN12, (VL*32)(RSP)",
		"ZSTNT1D.Z [Z8.D], P3, (-VL*2)(RSP)",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvenontemporalmemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvenontemporalmemory": {Name: "badsvenontemporalmemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's non-temporal memory forms", instruction)
			}
		})
	}
}
