package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64VectorBitReverseCompleteFormats(t *testing.T) {
	const source = `TEXT vectorBitReverse(SB),$0-0
	VRBIT V0.B8, V1.B8
	VRBIT V2.B16, V3.B16
	VRBIT V4.B16, V4.B16
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
		Sigs:         map[string]FuncSig{"vectorBitReverse": {Name: "vectorBitReverse", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@llvm.bitreverse.v8i8", "@llvm.bitreverse.v16i8"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 VRBIT lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-vector-bit-reverse.ll", "arm64-vector-bit-reverse.o", ll)
}

func TestTranslateARM64VectorBitReverseRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VRBIT V0.H4, V1.H4",
		"VRBIT V0.B8, V1.B16",
		"VRBIT V0, V1",
		"VRBIT R0, V1.B8",
		"VRBIT.P V0.B8, V1.B8",
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 VRBIT optab", instruction)
		}
	}
}
