package plan9asm

import (
	"strings"
	"testing"
)

const arm64BarrierForms = `
TEXT barrierforms(SB),$0-0
	DMB $0
	DMB $1
	DMB $15
	DMB $255
	DMB $-1
	DSB $0
	DSB $7
	DSB $15
	DSB $255
	DSB $-1
	ISB $0
	ISB $1
	ISB $15
	ISB $255
	ISB $-1
	SB
	RET
`

func TestTranslateARM64BarrierCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64BarrierForms, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64BarrierForms)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"barrierforms": {Name: "barrierforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "dmb #0"`,
				`asm sideeffect "dmb #1"`,
				`asm sideeffect "dmb #15"`,
				`asm sideeffect "dsb #0"`,
				`asm sideeffect "dsb #7"`,
				`asm sideeffect "dsb #15"`,
				`asm sideeffect "isb #0"`,
				`asm sideeffect "isb #1"`,
				`asm sideeffect "isb #15"`,
				`asm sideeffect "hint #7"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 barrier lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			// Go masks C_VCON values to the low four encoded bits.
			if got := strings.Count(ll, `asm sideeffect "dmb #15"`); got != 3 {
				t.Fatalf("DMB low-four-bit lowering count = %d, want 3:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-barriers.ll", "arm64-barriers.o", ll)
		})
	}
}

func TestTranslateARM64BarrierRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"DMB",
		"DSB R0",
		"ISB $1, $2",
		"DMB.P $1",
		"SB $1",
		"SB.P",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's barrier forms", instruction)
		}
	}
}
