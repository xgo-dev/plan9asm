package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64CheckedR20EntryUnknownGPDoesNotBecomeDefined(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc Value(uint64) uint64\n")
	for _, tc := range []struct{ name, body string }{
		{"copy", "MOVD R12,R20\nMOVD R20,R0"},
		{"arithmetic", "ADD $7,R12,R20\nMOVD R20,R0"},
		{"discarded_copy", "MOVD R12,R20\nMOVD $7,R20\nMOVD R20,R0"},
		{"join", "MOVD arg+0(FP),R8\nCBZ R8,other\nMOVD R12,R20\nB joined\nother:\nMOVD $7,R20\njoined:\nMOVD R20,R0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$496-16\n" + tc.body + "\nMOVD R0,ret+8(FP)\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			arm64LargeFrameCheckAPIs(t, source, pkg, nil, true, false)
		})
	}
}

func TestARM64CheckedR20SoftwareValuesAndTypedFPLoads(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc Value(uint64) uint64\n")
	for _, text := range []string{
		"TEXT ·Value(SB),4,$496-16",
		"TEXT ·Value(SB),4,$224-16",
		"TEXT ·Value(SB),4,$8-16",
		"TEXT ·Value(SB),4,$0-16",
		"TEXT ·Value(SB),516,$0-16",
	} {
		for _, body := range []string{
			"MOVD $7,R20",
			"MOVD arg+0(FP),R20",
			"MOVD arg+0(FP),R8\nADD $7,R8,R20",
		} {
			t.Run(fmt.Sprintf("%s/%s", text, body), func(t *testing.T) {
				source := text + "\n" + body + "\nMOVD R20,ret+8(FP)\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				arm64LargeFrameCheckAPIs(t, source, pkg, nil, false, true)
			})
		}
	}
}

func TestARM64CheckedR20SmallAndNoFrameHaveNoImplicitProducer(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc Value(uint64) uint64\n")
	for _, text := range []string{
		"TEXT ·Value(SB),4,$224-16",
		"TEXT ·Value(SB),4,$8-16",
		"TEXT ·Value(SB),4,$0-16",
		"TEXT ·Value(SB),516,$0-16",
	} {
		for _, body := range []string{
			"MOVD R20,ret+8(FP)",
			"WORD $0xf9400280\nMOVD R0,ret+8(FP)",
			"MOVD R12,R20\nMOVD R20,ret+8(FP)",
		} {
			t.Run(fmt.Sprintf("%s/%s", text, body), func(t *testing.T) {
				source := text + "\n" + body + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				arm64LargeFrameCheckAPIs(t, source, pkg, nil, true, false)
			})
		}
	}
}
