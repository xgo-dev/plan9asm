package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64BranchLinkCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT branchLinkForms(SB),$0-0
	BL local
resume:
	BL 1(PC)
afterPC:
	BL R3
	BL (R4)
	BL global(SB)
	CALL R5
	CALL (R6)
	CALL global(SB)
	B done
local:
	MOVD R30, R0
	B resume
done:
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

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
					"branchLinkForms": {Name: "branchLinkForms", Ret: Void},
					"global":          {Name: "global", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "blockaddress(@branchLinkForms, %resume)") ||
				!strings.Contains(ll, "store i64 %") || !strings.Contains(ll, "ptr %reg_R30") {
				t.Fatalf("local BL did not materialize its continuation in R30:\n%s", ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-branch-link-"+target.name+".ll", "arm64-branch-link-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64BranchLinkRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"BL 8(R1)",
		"BL RSP",
		"BL V0",
		"BL $1",
		"BL.P R1",
		"CALL 8(R1)",
		"BL target, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badBranchLink(SB),$0-0\n\t" + instruction + "\ntarget:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badBranchLink": {Name: "badBranchLink", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 BL table", instruction)
			}
		})
	}
}
