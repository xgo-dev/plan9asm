package plan9asm

import (
	"strconv"
	"strings"
	"testing"
)

func arm64SaturatingShiftCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT saturatingShiftComplete(SB),$0-0\n")
	for _, op := range []string{"VSQSHL", "VUQSHL"} {
		for _, arrangement := range []struct {
			name     string
			maxShift int
		}{{"B8", 7}, {"B16", 7}, {"H4", 15}, {"H8", 15}, {"S2", 31}, {"S4", 31}, {"D2", 63}} {
			source.WriteString("\t" + op + " $" + strconv.Itoa(arrangement.maxShift) + ", V1." + arrangement.name + ", V2." + arrangement.name + "\n")
			source.WriteString("\t" + op + " V3." + arrangement.name + ", V4." + arrangement.name + ", V5." + arrangement.name + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SaturatingShiftCompleteFormats(t *testing.T) {
	source := arm64SaturatingShiftCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"saturatingShiftComplete": {Name: "saturatingShiftComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, intrinsic := range []string{"llvm.aarch64.neon.sqshl", "llvm.aarch64.neon.uqshl"} {
		if !strings.Contains(ll, intrinsic) {
			t.Fatalf("ARM64 saturating shift lowering omitted %q:\n%s", intrinsic, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-saturating-shift.ll", "arm64-saturating-shift.o", ll)
}

func TestTranslateARM64SaturatingShiftRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VSQSHL $8, V0.B8, V1.B8",
		"VSQSHL V0.B8, V1.B16, V2.B8",
		"VUQSHL $1, V0.D1, V1.D1",
		"VUQSHL R0, V1.S4, V2.S4",
		"VUQSHL.P V0.S4, V1.S4, V2.S4",
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
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 saturating-shift optab", instruction)
		}
	}
}
