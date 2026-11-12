package plan9asm

import "testing"

func TestTranslateARM64StructureStoreLaneForms(t *testing.T) {
	const source = `TEXT structurestorelanes(SB),$0-0
	VST1.P V0.B[0], 1(R0)
	VST1.P V1.H[3], 2(R0)
	VST1.P V2.S[1], 4(R0)
	VST1.P V3.D[0], 8(R0)
	VST1 V4.B[15], (R0)
	VST1 V5.H[7], (R0)
	VST1 V6.S[3], (R0)
	VST1 V7.D[1], (R0)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"structurestorelanes": {Name: "structurestorelanes", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-structure-store-lanes.ll", "arm64-structure-store-lanes.o", ll)
		})
	}
}
