package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawSegmentAbsoluteMemory(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tc := range []struct {
		name string
		code []byte
		want string
	}{
		{name: "gs-absolute", code: []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0}, want: "48(GS)"},
		{name: "fs-absolute", code: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0}, want: "48(FS)"},
		{name: "gs-base", code: []byte{0x65, 0x48, 0x8b, 0x40, 0x30}, want: "48(AX)(GS)"},
		{name: "fs-base", code: []byte{0x64, 0x48, 0x8b, 0x40, 0x30}, want: "48(AX)(FS)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := x86asm.Decode(tc.code, 64)
			if err != nil {
				t.Fatal(err)
			}
			syntax, err := decodedX86GoSyntax(inst, tc.code)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(syntax, tc.want) {
				t.Fatalf("raw %x decoded as %q, want memory %s", tc.code, syntax, tc.want)
			}

			var source strings.Builder
			source.WriteString("TEXT rawSegmentMemory(SB),$0-0\n")
			for _, value := range tc.code {
				fmt.Fprintf(&source, "BYTE $%#02x\n", value)
			}
			source.WriteString("RET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"rawSegmentMemory": {Name: "rawSegmentMemory", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-segment-memory.ll", "raw-segment-memory.o", ir)
		})
	}
}
