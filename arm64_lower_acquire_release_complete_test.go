package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64AcquireReleaseCompleteFormats(t *testing.T) {
	const source = `TEXT acquireReleaseComplete(SB),$0-0
	LDARB (R6), R7
	LDARH (R6), R7
	LDARW (R6), R7
	LDAR (R6), R7
	STLRB R5, (R6)
	STLRH R5, (R6)
	STLRW R5, (R6)
	STLR R5, (R6)
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
		Sigs: map[string]FuncSig{
			"acquireReleaseComplete": {Name: "acquireReleaseComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load atomic i8", "load atomic i16", "load atomic i32", "load atomic i64",
		"store atomic i8", "store atomic i16", "store atomic i32", "store atomic i64", " acquire", " release",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 acquire/release lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-acquire-release.ll", "arm64-acquire-release.o", ll)
}

func TestTranslateARM64AcquireReleaseRejectsOffsetMemory(t *testing.T) {
	for _, instruction := range []string{"LDARH 2(R1), R2", "STLRH R0, 2(R1)"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 acquire/release optab", instruction)
		}
	}
}
