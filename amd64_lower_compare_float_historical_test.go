package plan9asm

import "testing"

func TestTranslate386LegacyFloatingCompareOfficialBarePredicate(t *testing.T) {
	const source = `GLOBL foo(SB),24,$20
DATA foo+4(SB)/8,$0x3ff0000000000000
DATA foo+12(SB)/8,$0x4000000000000000

TEXT ·Register(SB),4,$0-12
	MOVL p+0(FP),AX
	MOVL q+4(FP),CX
	MOVUPS (AX),X0
	MOVUPS (CX),X1
	CMPPD X0, X1, 4
	MOVL X1,AX
	MOVL AX,ret+8(FP)
	RET

TEXT ·Memory(SB),4,$0-8
	MOVL p+0(FP),AX
	MOVUPS (AX),X1
	CMPPD foo+4(SB), X1, 4
	MOVL X1,AX
	MOVL AX,ret+4(FP)
	RET
`
	const declaration = "func Register(p, q *[2]float64) uint32\nfunc Memory(p *[2]float64) uint32\n"
	goAssemblerOracleOutput(t, "386", source, "", true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(target, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", target, api)
					if err != nil {
						t.Fatal(err)
					}
					x86COMICompileOriginalFormatObjects(t, llc, target, "legacy-compare", ir)
				})
			}
		})
	}
}

func TestTranslateAMD64LegacyFloatingCompareHistoricalBarePredicate(t *testing.T) {
	source := "TEXT historicalcompare(SB),NOSPLIT,$0-0\n" +
		"\tCMPPD X1, X0, 1\n" +
		"\tCMPPS 8(AX), X0, 2\n" +
		"\tCMPSD X1, X0, 5\n" +
		"\tCMPSS 8(AX), X0, -1\n" +
		"\tRET\n"
	ll := x86UnboundVoidScalarFormatObject(t, source, "historicalcompare", "amd64", "x86_64-unknown-linux-gnu")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "historical-floating-compare.ll", "historical-floating-compare.o", ll)
}

func TestTranslateAMD64LegacyFloatingCompareRejectsInvalidBarePredicate(t *testing.T) {
	for _, instruction := range []string{
		"CMPPD X1, X0, predicate",
		"CMPPS X1, X0, 128",
		"CMPSD X1, X0, -129",
		"CMPSS X1, X0, 1+1",
	} {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted invalid historical predicate %q", instruction)
		}
	}
}
