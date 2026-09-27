package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawExtendedPrefetchHints(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawExtendedPrefetch(SB),$0-0\n")
			codes := [][]byte{
				{0x0f, 0x18, 0x20},                   // /4, base register
				{0x0f, 0x18, 0x30},                   // /6, base register
				{0x0f, 0x18, 0x38},                   // /7, base register
				{0x65, 0x0f, 0x18, 0x74, 0x8b, 0xf9}, // /6, GS and SIB with disp8
			}
			if target.goarch == "amd64" {
				codes = append(codes, []byte{0x4d, 0x0f, 0x18, 0x7c, 0x8c, 0x10}) // /7, extended base/index
			}
			for _, code := range codes {
				for _, value := range code {
					fmt.Fprintf(&source, "BYTE $%#02x\n", value)
				}
			}
			source.WriteString("RET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawExtendedPrefetch": {Name: "rawExtendedPrefetch", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-extended-prefetch.ll", "raw-extended-prefetch.o", ir)
		})
	}
}

func TestX86RawExtendedPrefetchHintsRejectInvalidForms(t *testing.T) {
	for _, code := range [][]byte{
		{0x0f, 0x18, 0x28},             // /5 is reserved.
		{0x0f, 0x18, 0xf0},             // /6 requires memory.
		{0x67, 0x0f, 0x18, 0x30},       // Address-size override is not modeled.
		{0x0f, 0x18, 0x35, 0, 0, 0, 0}, // RIP-relative address has no proven source layout.
	} {
		var source strings.Builder
		source.WriteString("TEXT badRawPrefetch(SB),$0-0\n")
		for _, value := range code {
			fmt.Fprintf(&source, "BYTE $%#02x\n", value)
		}
		source.WriteString("RET\n")
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"badRawPrefetch": {Name: "badRawPrefetch", Ret: Void}},
		}); err == nil {
			t.Fatalf("accepted unsupported raw prefetch form %x", code)
		}
	}
}
