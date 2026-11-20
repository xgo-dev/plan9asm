package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEFloatReciprocalStepDiscoveryWord(t *testing.T) {
	const source = `TEXT rawreciprocalstep(SB),$0-0
	WORD $0x65851c83 // frsqrts z3.s, z4.s, z5.s
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"rawreciprocalstep": {Name: "rawreciprocalstep", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "@llvm.aarch64.sve.frsqrts.x.nxv4f32") {
		t.Fatalf("raw FRSQRTS did not use the typed reciprocal-step lowering:\n%s", ll)
	}
}

func TestTranslateARM64RawSVEFloatReciprocalStepCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawreciprocalsteps(SB),$0-0\n")
	for _, base := range []uint32{0x65001800, 0x65001c00} {
		for size := uint32(1); size <= 3; size++ {
			word := base | size<<22 | 5<<16 | 4<<5 | 3
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
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
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawreciprocalsteps": {Name: "rawreciprocalsteps", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.aarch64.sve.frecps.x.nxv8f16",
				"@llvm.aarch64.sve.frecps.x.nxv4f32",
				"@llvm.aarch64.sve.frecps.x.nxv2f64",
				"@llvm.aarch64.sve.frsqrts.x.nxv8f16",
				"@llvm.aarch64.sve.frsqrts.x.nxv4f32",
				"@llvm.aarch64.sve.frsqrts.x.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("raw reciprocal-step family omitted %q", want)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-reciprocal-step.ll", "arm64-raw-reciprocal-step.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEFloatReciprocalStepRejectsOtherForms(t *testing.T) {
	for _, word := range []uint32{
		0x65001800, // Byte lanes are not floating-point lanes.
		0x65001c00,
		0x65005800, // Pair variant does not belong to the Go table.
		0x65009c00, // Predicated variant does not belong to the Go table.
	} {
		if decoded, ok := decodeARM64RawSVEFloatReciprocalStep(word); ok {
			t.Fatalf("out-of-table reciprocal-step WORD %#08x decoded as %+v", word, decoded)
		}
	}
}
