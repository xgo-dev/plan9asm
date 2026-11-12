package plan9asm

import "testing"

func TestARM64RawSVEDupMDecoderCoversLogicalImmediateAndDestination(t *testing.T) {
	for immediateBits := 0; immediateBits < 1<<13; immediateBits++ {
		width, immediate, valid := decodeARM64SVELogicalImmediate(immediateBits)
		for destination := 0; destination < 32; destination++ {
			word := uint32(0x05c00000 | immediateBits<<5 | destination)
			got, ok := decodeARM64RawSVEDupM(word)
			if ok != valid {
				t.Fatalf("ZDUPM %#08x validity = %v, want %v", word, ok, valid)
			}
			if !valid {
				continue
			}
			reg, bits, regOK := arm64ParseSVEZElementReg(got.Args[1])
			if !regOK || reg != destination || bits != width || uint64(got.Args[0].Imm) != immediate {
				t.Fatalf("ZDUPM %#08x decoded as %+v", word, got)
			}
		}
	}
}

func TestTranslateARM64RawSVEDupMGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawSVEDupM(SB),$0-0
	WORD $0x05c02840 // MOV Z0.S, #0x38000000
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
					"rawSVEDupM": {Name: "rawSVEDupM", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-dupm.ll", "arm64-raw-sve-dupm.o", ir)
		})
	}
}
