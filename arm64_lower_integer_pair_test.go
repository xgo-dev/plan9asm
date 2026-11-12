package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64IntegerPairCompleteFormats(t *testing.T) {
	const source = `TEXT integerPairComplete(SB),$0-0
	LDP (R0), (R1, R2)
	LDP.W 16(R3), (R4, R5)
	LDP.P -16(R6), (R7, R8)
	LDP pairData(SB), (R9, R10)
	LDPW (R11), (R12, R13)
	LDPW.W 8(R14), (R15, R16)
	LDPW.P -8(R17), (R19, R20)
	LDPW pairData+8(SB), (R20, R21)
	LDPSW (R22), (R23, R24)
	LDPSW.W 8(R25), (R26, R27)
	LDPSW.P -8(R20), (R21, R22)
	LDPSW pairData+16(SB), (R1, R2)
	STP (R3, R4), (R5)
	STP.W (R6, R7), 16(R8)
	STP.P (R9, R10), -16(R11)
	STP (R12, R13), pairData+24(SB)
	STPW (R14, R15), (R16)
	STPW.W (R17, R19), 8(R20)
	STPW.P (R20, R21), -8(R22)
	STPW (R23, R24), pairData+40(SB)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"integerPairComplete": {Name: "integerPairComplete", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load i64", "load i32", "sext i32", "zext i32",
		"store i64", "store i32", "getelementptr i8", "pairData",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 integer-pair lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-integer-pair.ll", "arm64-integer-pair.o", ll)
}

func TestTranslateARM64IntegerPairRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"LDP (R0), R1",
		"LDP (R0)(R1), (R2, R3)",
		"LDP.W pairData(SB), (R1, R2)",
		"LDPSW (R0), (R1, V2)",
		"STP (R0), (R1)",
		"STPW (R0, R1), (R2)(R3)",
		"STPW.P (R0, R1), pairData(SB)",
		"STP.X (R0, R1), (R2)",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 integer-pair optab", instruction)
		}
	}
}
