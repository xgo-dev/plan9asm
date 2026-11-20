package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64RawSMEOuterProductAndTileRegisterFields(t *testing.T) {
	if form, ok := decodeARM64RawSMEOuterProduct(0x80800020); !ok ||
		form.op != "fmopa" || form.first != 1 || form.second != 0 ||
		form.firstPred != 0 || form.secondPred != 0 || form.sourceBits != 32 {
		t.Fatalf("FMOPA ZA0.S with Z1/Z0 decode = %+v, %v", form, ok)
	}
	if form, ok := decodeARM64RawSMEOuterProduct(0x80c30002); !ok || form.tile != 2 || form.second != 3 || form.sourceBits != 64 {
		t.Fatalf("FMOPA ZA2.D decode = %+v, %v", form, ok)
	}
	if form, ok := decodeARM64RawSMETileWrite(0xc0808200); !ok ||
		form.destination != 16 || form.row != 12 || form.index != 0 || form.tile != 0 || !form.vertical {
		t.Fatalf("ZA vertical write from Z16 decode = %+v, %v", form, ok)
	}
	if form, ok := decodeARM64RawSMETileWrite(0xc080e063); !ok ||
		form.destination != 3 || form.row != 15 || form.index != 3 || form.tile != 0 || !form.vertical {
		t.Fatalf("ZA vertical write index 3 from Z3 decode = %+v, %v", form, ok)
	}
}

func TestTranslateARM64RawSMEOuterProductGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSMEOuterProduct(SB),$0-0
	MOVD $0, R12
	WORD $0xd503477f // SMSTART
	WORD $0x2598e3e0 // PTRUE P0.S
	WORD $0xc00800ff // ZERO {ZA}
	WORD $0x80800020 // FMOPA ZA0.S, P0/M, P0/M, Z1.S, Z0.S
	WORD $0x80810000 // FMOPA ZA0.S, P0/M, P0/M, Z0.S, Z1.S
	WORD $0xc0820000 // MOV Z0.S, P0/M, ZA0H.S[W12, 0]
	WORD $0x80c10000 // FMOPA ZA0.D, P0/M, P0/M, Z0.D, Z1.D
	WORD $0x81810000 // BFMOPA ZA0.S, P0/M, P0/M, Z0.H, Z1.H
	WORD $0xa0810000 // SMOPA ZA0.S, P0/M, P0/M, Z0.B, Z1.B
	WORD $0xa0a10000 // SUMOPA ZA0.S, P0/M, P0/M, Z0.B, Z1.B
	WORD $0xa1a10000 // UMOPA ZA0.S, P0/M, P0/M, Z0.B, Z1.B
	WORD $0xc080e000 // MOV ZA0V.S[W15, 0], P0/M, Z0.S
	WORD $0xd503467f // SMSTOP
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSMEOuterProduct": {Name: "rawSMEOuterProduct", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "fmopa`, `asm sideeffect "bfmopa`,
				`asm sideeffect "smopa`, `asm sideeffect "sumopa`,
				`asm sideeffect "umopa`, `za0h.s`, `za0v.s`, `+sme-f64f64`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("SME outer-product lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sme-mopa.ll", "arm64-raw-sme-mopa.o", ir)
		})
	}
}
