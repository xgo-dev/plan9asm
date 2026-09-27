package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SYSCompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT sysforms(SB),$0-0
	SYS $0
	SYS $0x37520, R3
	SYS $0x7ffe0, ZR
	SYSL $0, R12
	SYSL $0x7ffe0, ZR
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"sysforms": {Name: "sysforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "sys #0, c0, c0, #0, xzr"`,
				`asm sideeffect "sys #3, c7, c5, #1, $0"`,
				`asm sideeffect "sys #7, c15, c15, #7, xzr"`,
				`asm sideeffect "sysl $0, #0, c0, c0, #0"`,
				`asm sideeffect "sysl $0, #7, c15, c15, #7"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 SYS/SYSL lowering omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sys.ll", "arm64-sys.o", ll)
		})
	}
}

func TestTranslateARM64SYSRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"SYS $1",
		"SYS $0x80000",
		"SYS $0, R1, R2",
		"SYS R1",
		"SYS.P $0",
		"SYSL $0",
		"SYSL $0, $1",
		"SYSL $0, R1, R2",
		"SYSL.P $0, R1",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SYS/SYSL forms", instruction)
			}
		})
	}
}
