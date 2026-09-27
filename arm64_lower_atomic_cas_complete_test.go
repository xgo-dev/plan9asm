package plan9asm

import (
	"strings"
	"testing"
)

func arm64AtomicCASCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT atomicCASComplete(SB),$0-0\n")
	for _, width := range []string{"B", "H", "W", "D"} {
		orders := []string{"", "AL"}
		if width == "W" || width == "D" {
			orders = []string{"", "A", "L", "AL"}
		}
		for _, order := range orders {
			opcode := "CAS" + order + width
			source.WriteString("\t" + opcode + " R5, (R6), R7\n")
			source.WriteString("\t" + opcode + " ZR, (RSP), ZR\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64AtomicCASCompleteFormats(t *testing.T) {
	source := arm64AtomicCASCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"atomicCASComplete": {Name: "atomicCASComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cmpxchg ptr", " i8 ", " i16 ", " i32 ", " i64 ",
		" monotonic monotonic", " acquire acquire", " release monotonic", " acq_rel acquire",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 complete CAS lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-cas-complete.ll", "arm64-cas-complete.o", ll)
}

func TestTranslateARM64AtomicCASRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"CASD R0, 8(R1), R2", "CASW R0, (R1)", "CASQ R0, (R1), R2"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 LSE CAS optab", instruction)
		}
	}
}
