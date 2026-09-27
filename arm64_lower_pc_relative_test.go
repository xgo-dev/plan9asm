package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64PCRelativeAddressCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT pcRelativeAddressForms(SB),$0-0
	ADR target, R0
	ADRP target, R1
	ADR -2(PC), R2
	ADR 2(PC), R3
	ADRP -2(PC), R29
	ADRP 2(PC), R30
	ADR target, ZR
	ADRP target, ZR
target:
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
					"pcRelativeAddressForms": {Name: "pcRelativeAddressForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, "blockaddress("); got != 8 {
				t.Fatalf("emitted %d block addresses, want 8:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-pc-relative-"+target.name+".ll", "arm64-pc-relative-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64PCRelativeAddressRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"ADR R1, R2",
		"ADR $1, R2",
		"ADR target, RSP",
		"ADR target, V0",
		"ADR target",
		"ADR target, R1, R2",
		"ADRP 0(R1), R2",
		"ADRP.P target, R2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badPCRelativeAddress(SB),$0-0\n\t" + instruction + "\ntarget:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badPCRelativeAddress": {Name: "badPCRelativeAddress", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 ADR/ADRP table", instruction)
			}
		})
	}
}
