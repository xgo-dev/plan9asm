package plan9asm

import (
	"strings"
	"testing"
)

func arm64AtomicRMWCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT atomicRMWComplete(SB),$0-0\n")
	for _, family := range []string{"SWP", "LDADD", "LDCLR", "LDOR", "LDEOR"} {
		for _, order := range []string{"", "A", "L", "AL"} {
			for _, width := range []string{"B", "H", "W", "D"} {
				opcode := family + order + width
				source.WriteString("\t" + opcode + " R5, (R6), R7\n")
				source.WriteString("\t" + opcode + " R5, (RSP), ZR\n")
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64AtomicRMWCompleteFormats(t *testing.T) {
	source := arm64AtomicRMWCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"atomicRMWComplete": {Name: "atomicRMWComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"atomicrmw xchg", "atomicrmw add", "atomicrmw and", "atomicrmw or", "atomicrmw xor",
		" i8 ", " i16 ", " i32 ", " i64 ", " monotonic", " acquire", " release", " acq_rel",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 complete atomic RMW lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-atomic-rmw-complete.ll", "arm64-atomic-rmw-complete.o", ll)
}

func TestTranslateARM64AtomicRMWRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"SWPD R0, 8(R1), R2", "LDADDW R0, (R1)", "LDCLRQ R0, (R1), R2"} {
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 LSE atomic RMW optab", instruction)
		}
	}
}
