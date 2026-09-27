package plan9asm

import "testing"

func TestTranslateAMD64LegacyFloatingCompareHistoricalBarePredicate(t *testing.T) {
	source := "TEXT historicalcompare(SB),NOSPLIT,$0-0\n" +
		"\tCMPPD X1, X0, 1\n" +
		"\tCMPPS 8(AX), X0, 2\n" +
		"\tCMPSD X1, X0, 5\n" +
		"\tCMPSS 8(AX), X0, -1\n" +
		"\tRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"historicalcompare": {Name: "historicalcompare", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
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
