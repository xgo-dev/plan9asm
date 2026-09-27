package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64RawStreamingModeControlDecoderCompleteArchitectureFamily(t *testing.T) {
	tests := []struct {
		word   uint32
		enable bool
		state  arm64StreamingState
	}{
		{word: 0xd503477f, enable: true, state: arm64StreamingStateBoth},
		{word: 0xd503437f, enable: true, state: arm64StreamingStateSM},
		{word: 0xd503457f, enable: true, state: arm64StreamingStateZA},
		{word: 0xd503467f, state: arm64StreamingStateBoth},
		{word: 0xd503427f, state: arm64StreamingStateSM},
		{word: 0xd503447f, state: arm64StreamingStateZA},
	}

	for _, test := range tests {
		form, ok := decodeARM64RawStreamingModeControl(test.word)
		if !ok {
			t.Fatalf("decoder rejected %#08x", test.word)
		}
		if form.enable != test.enable || form.state != test.state {
			t.Fatalf("decode %#08x = %+v", test.word, form)
		}
	}
}

func TestTranslateARM64RawStreamingModeControlCompleteArchitectureFamily(t *testing.T) {
	const source = `
TEXT rawStreamingModeControl(SB),$0-0
	WORD $0xd503477f // SMSTART
	WORD $0xd503437f // SMSTART SM
	WORD $0xd503457f // SMSTART ZA
	WORD $0xd503467f // SMSTOP
	WORD $0xd503427f // SMSTOP SM
	WORD $0xd503447f // SMSTOP ZA
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
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
					"rawStreamingModeControl": {Name: "rawStreamingModeControl", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "smstart"`,
				`asm sideeffect "smstart sm"`,
				`asm sideeffect "smstart za"`,
				`asm sideeffect "smstop"`,
				`asm sideeffect "smstop sm"`,
				`asm sideeffect "smstop za"`,
				`"target-features"="+sme"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw streaming-mode control IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-streaming-mode.ll", "arm64-raw-streaming-mode.o", ir)
		})
	}
}

func TestARM64RawStreamingModeControlDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0xd503407f, // CFINV.
		0xd503417f, // XAFLAG.
		0xd503487f, // AXFLAG.
		0xd503457e, // Reserved Rt field.
	} {
		if _, ok := decodeARM64RawStreamingModeControl(word); ok {
			t.Fatalf("streaming-mode decoder accepted adjacent encoding %#08x", word)
		}
	}
}
