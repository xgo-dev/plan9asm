package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86InsertPSCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's yxshuf and _yvinsertps tables contain exactly:
	//   INSERTPS  imm8, X/m32, X
	//   VINSERTPS imm8, X/m32, X, X
	// VINSERTPS can select either its VEX (<16) or EVEX (<32) entry.
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			legacyLast := 15
			if target.goarch == "386" {
				legacyLast = 7
			}
			src := fmt.Sprintf(`TEXT insertpsforms(SB),NOSPLIT,$0-0
	INSERTPS $0, X0, X1
	INSERTPS $255, 4(AX), X%d
	VINSERTPS $0, X0, X1, X2
	VINSERTPS $255, 8(AX), X14, X15
	VINSERTPS $16, X20, X21, X22
	VINSERTPS $32, 12(AX), X30, X31
	RET
`, legacyLast)
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"insertpsforms": {Name: "insertpsforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "insertps-"+target.name+".ll", "insertps-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86InsertPSRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"INSERTPS X0, X1",
		"INSERTPS $-1, X0, X1",
		"INSERTPS $256, X0, X1",
		"INSERTPS $0, Y0, X1",
		"INSERTPS $0, X0, Y1",
		"INSERTPS.Z $0, X0, X1",
		"VINSERTPS $0, X0, X1",
		"VINSERTPS $0, X0, X1, X2, X3",
		"VINSERTPS $0, Y0, X1, X2",
		"VINSERTPS $0, X0, Y1, X2",
		"VINSERTPS $0, X0, X1, Y2",
		"VINSERTPS $0, X0, K1, X1",
		"VINSERTPS.Z $0, X0, X1, X2",
		"VINSERTPS.BCST $0, (AX), X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86InsertPSRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"INSERTPS $0, X8, X0",
		"INSERTPS $0, X0, X8",
	} {
		assertX86InsertPSRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86InsertPSRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's INSERTPS tables", instruction)
	}
}
