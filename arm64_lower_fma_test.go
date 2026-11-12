package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64FusedMultiplyAddCompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT fusedmultiplyaddforms(SB),NOSPLIT,$0-0
	FMADDS F0, F1, F2, F3
	FMADDD F4, F5, F6, F7
	FMSUBS F8, F9, F10, F11
	FMSUBD F12, F13, F14, F15
	FNMADDS F16, F17, F18, F19
	FNMADDD F20, F21, F22, F23
	FNMSUBS F24, F25, F26, F27
	FNMSUBD F28, F29, F30, F31
	RET
`
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-arm64", triple: "arm64-apple-darwin"},
		{name: "linux-arm64", triple: "aarch64-unknown-linux-gnu"},
		{name: "windows-arm64", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"fusedmultiplyaddforms": {Name: "fusedmultiplyaddforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-fused-multiply-add-"+target.name+".ll", "arm64-fused-multiply-add-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64FusedMultiplyAddRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"FMADDS F0, F1, F2",
		"FMADDD F0, F1, F2, F3, F4",
		"FMSUBS 8(R0), F1, F2, F3",
		"FMSUBD F0, R1, F2, F3",
		"FNMADDS F0, F1, V2, F3",
		"FNMADDD F0, F1, F2, R3",
		"FNMSUBS.P F0, F1, F2, F3",
		"FNMSUBD F32, F1, F2, F3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 fused multiply-add table", instruction)
			}
		})
	}
}
