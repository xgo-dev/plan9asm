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
		base bool
	}{
		{name: "gs-absolute", code: []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0}, want: "48(GS)"},
		{name: "fs-absolute", code: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0}, want: "48(FS)"},
		{name: "gs-base", code: []byte{0x65, 0x48, 0x8b, 0x40, 0x30}, want: "48(AX)(GS)", base: true},
		{name: "fs-base", code: []byte{0x64, 0x48, 0x8b, 0x40, 0x30}, want: "48(AX)(FS)", base: true},
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
			assembly := source.String()
			triple := "x86_64-unknown-linux-gnu"
			if tc.base {
				ir := x86UnboundVoidRawScalarFormatObject(t, assembly, "amd64", triple)
				x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
				assembly = strings.Replace(assembly, "\nBYTE", "\nMOVQ $0,AX\nBYTE", 1)
			}
			x86LEAActualTargetGoObject(t, "amd64", triple, assembly)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, assembly, "func rawSegmentMemory()", "amd64", triple, api)
				if err != nil {
					t.Fatal("raw hardware segment with all explicit numerical offsets", api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			}
		})
	}
}
