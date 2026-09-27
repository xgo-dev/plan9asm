package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEConvertGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSVEConvert(SB),$0-0
	WORD $0x6589a400 // FCVT Z0.S, P1/M, Z0.H
	WORD $0x659ca3ff // FCVTZS Z31.S, P0/M, Z31.S
	WORD $0x65bea308 // FMSB Z8.S, P0/M, Z24.S, Z30.S
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
					"rawSVEConvert": {Name: "rawSVEConvert", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var conversionCalls []string
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, "call ") && strings.Contains(line, "@llvm.aarch64.sve.fcvt") {
					conversionCalls = append(conversionCalls, line)
				}
			}
			if len(conversionCalls) != 2 {
				t.Fatalf("want two SVE conversion calls, got %v", conversionCalls)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-convert.ll", "arm64-raw-sve-convert.o", ir)
		})
	}
}
