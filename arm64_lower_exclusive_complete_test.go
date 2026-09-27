package plan9asm

import (
	"strings"
	"testing"
)

func arm64ExclusiveCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT exclusiveComplete(SB),$0-0\n")
	for _, prefix := range []string{"LDXR", "LDAXR"} {
		for _, width := range []string{"B", "H", "W", ""} {
			source.WriteString("\t" + prefix + width + " (R6), R7\n")
		}
	}
	for _, prefix := range []string{"STXR", "STLXR"} {
		for _, width := range []string{"B", "H", "W", ""} {
			source.WriteString("\t" + prefix + width + " R5, (R6), R7\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64ExclusiveCompleteFormats(t *testing.T) {
	source := arm64ExclusiveCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"exclusiveComplete": {Name: "exclusiveComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load atomic i8", "load atomic i16", "load atomic i32", "load atomic i64",
		" monotonic", " acquire", "cmpxchg ptr", " release monotonic",
		"store i1 true, ptr %exclusive_valid", "store i1 false, ptr %exclusive_valid",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 exclusive lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-exclusive-complete.ll", "arm64-exclusive-complete.o", ll)
}

func TestTranslateARM64ExclusiveRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"LDXR 8(R1), R2", "STXRH R0, (R1)", "LDXRQ (R1), R2"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 exclusive optab", instruction)
		}
	}
}
