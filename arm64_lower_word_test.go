package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64KnownRawWordsHaveRealSemantics(t *testing.T) {
	source := `
TEXT rawwordforms(SB),$0-0
	WORD $0xea00001f
	WORD $0xf1000400
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
		Sigs:         map[string]FuncSig{"rawwordforms": {Name: "rawwordforms", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"icmp eq i64", "sub i64"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("known ARM64 WORD omitted %q semantics:\n%s", want, ll)
		}
	}
}

func TestTranslateARM64UnknownRawEncodingFailsExplicitly(t *testing.T) {
	// Go accepts arbitrary integer payloads in WORD directives. A reserved
	// encoding must remain an explicit error rather than being swallowed by an
	// over-broad decoder and reported as successfully translated.
	source := "TEXT rawword(SB),$0-0\n\tWORD $0xffffffff\n\tRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"rawword": {Name: "rawword", Ret: Void}},
	}); err == nil || !strings.Contains(err.Error(), "unsupported ARM64 WORD encoding") {
		t.Fatalf("unknown ARM64 WORD did not fail explicitly: %v", err)
	}
}

func TestTranslateARM64UnreferencedWordDataAfterReturn(t *testing.T) {
	// Generated assembly may place a data word after the final RET. The
	// payload is not an instruction and must not be decoded as one.
	source := "TEXT deadword(SB),$0-0\n\tRET\n\tWORD $36473108\n\tWORD $0xffffffff\n"
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
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"deadword": {Name: "deadword", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, `c"\14\89,\02\FF\FF\FF\FF"`) {
				t.Fatal("unreferenced ARM64 data words were not preserved")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-dead-word.ll", "arm64-dead-word.o", ll)
		})
	}
}

func TestTranslateARM64LabeledWordDataAfterReturnRemainsData(t *testing.T) {
	source := "TEXT labeledword(SB),$0-0\n\tRET\nworddata:\n\tWORD $36473108\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"labeledword": {Name: "labeledword", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "labeledword.worddata.raw_data") {
		t.Fatalf("labeled ARM64 data word was not preserved: %s", ll)
	}
}

func TestTranslateARM64UnreferencedWordDataAfterJump(t *testing.T) {
	for _, jump := range []string{"B", "JMP"} {
		t.Run(jump, func(t *testing.T) {
			source := "TEXT jumpword(SB),$0-0\n\t" + jump + " done\n" +
				"\tWORD $34185040\n\tWORD $34192688\ndone:\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"jumpword": {Name: "jumpword", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, `[8 x i8] c"P\9F\09\02`) {
				prefix := ll
				if len(prefix) > 400 {
					prefix = prefix[:400]
				}
				t.Fatalf("anonymous ARM64 WORD island was not preserved as data: %q", prefix)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-jump-word.ll", "arm64-jump-word.o", ll)
		})
	}
}

func TestTranslateARM64PCRelativeTargetAfterReturnIsNotData(t *testing.T) {
	source := "TEXT targetword(SB),$0-0\n\tWORD $0x14000002\n\tRET\n\tWORD $36473108\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"targetword": {Name: "targetword", Ret: Void}},
	}); err == nil || !strings.Contains(err.Error(), "unsupported ARM64 WORD encoding") {
		t.Fatalf("PC-relative target after RET was misclassified as data: %v", err)
	}
}

func TestTranslateARM64RawDirectiveRejectsMalformedOrPartialEncoding(t *testing.T) {
	for _, instruction := range []string{"WORD", "WORD R0", "WORD $1, $2", "BYTE $0xd5"} {
		file, err := Parse(ArchARM64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate silently accepted raw directive %q", instruction)
		}
	}
}
