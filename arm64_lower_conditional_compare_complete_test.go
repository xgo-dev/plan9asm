package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateARM64ConditionalCompareCompleteFormats(t *testing.T) {
	const source = `TEXT conditionalCompareComplete(SB),$0-0
	MOVD R30, R16
	MOVD R29, R17
	MOVD $1, R30
	MOVD $16, R29
	CMP R0, R0
	CCMN LE, R30, R12, $6
	CCMN MI, ZR, R1, $4
	CCMN PL, R2, $6, $1
	CCMNW AL, R3, $20, $11
	CCMNW EQ, R4, R5, $6
	CCMP LT, R6, R7, $7
	CCMP LE, R8, $19, $3
	CCMPW HS, R9, R10, $0
	CCMPW VS, R29, $15, $7
	MOVD R17, R29
	MOVD R16, R30
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"conditionalCompareComplete": {Name: "conditionalCompareComplete", Ret: Void},
		},
	}
	ll, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"add i64", "add i32", "sub i64", "sub i32", "select i1 true"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 conditional compare lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-conditional-compare.ll", "arm64-conditional-compare.o", ll)
	t.Run("missing-caller-LR", func(t *testing.T) {
		missingRestore := strings.Replace(source, "\tMOVD R16, R30\n", "", 1)
		unrestored, err := Parse(ArchARM64, missingRestore)
		if err != nil {
			t.Fatal(err)
		}
		if ir, err := Translate(unrestored, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("conditional compare accepted a return through the overwritten LR: %v", err)
		}
	})
}

func TestTranslateARM64ConditionalCompareRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"CCMN BAD, R0, R1, $0",
		"CCMN AL, RSP, R1, $0",
		"CCMN AL, R0, (R1), $0",
		"CCMN.P AL, R0, R1, $0",
		"CCMPW AL, R0, R1",
	} {
		source := "TEXT bad(SB),$0-0\n\tCMP R0, R0\n\t" + instruction + "\n\tRET\n"
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 conditional-compare optab", instruction)
		}
	}
}
