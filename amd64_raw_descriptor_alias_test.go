package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawDescriptorStoreAliases(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
		want string
	}{
		{name: "sldt-memory-amd64", code: []byte{0x0f, 0x00, 0x07}, mode: 64, want: "SLDTW"},
		{name: "sldt-memory-386", code: []byte{0x0f, 0x00, 0x07}, mode: 32, want: "SLDTW"},
		{name: "sldt-register-word", code: []byte{0x66, 0x0f, 0x00, 0xc0}, mode: 64, want: "SLDTW"},
		{name: "sldt-register-long", code: []byte{0x0f, 0x00, 0xc0}, mode: 64, want: "SLDTL"},
		{name: "sldt-register-quad", code: []byte{0x48, 0x0f, 0x00, 0xc0}, mode: 64, want: "SLDTQ"},
		{name: "str-memory-amd64", code: []byte{0x0f, 0x00, 0x0f}, mode: 64, want: "STRW"},
		{name: "str-memory-386", code: []byte{0x0f, 0x00, 0x0f}, mode: 32, want: "STRW"},
		{name: "str-register-word", code: []byte{0x66, 0x0f, 0x00, 0xc8}, mode: 64, want: "STRW"},
		{name: "str-register-long", code: []byte{0x0f, 0x00, 0xc8}, mode: 64, want: "STRL"},
		{name: "str-register-quad", code: []byte{0x48, 0x0f, 0x00, 0xc8}, mode: 64, want: "STRQ"},
		{name: "smsw-memory-amd64", code: []byte{0x0f, 0x01, 0x27}, mode: 64, want: "SMSWW"},
		{name: "smsw-memory-386", code: []byte{0x0f, 0x01, 0x27}, mode: 32, want: "SMSWW"},
		{name: "smsw-register-word", code: []byte{0x66, 0x0f, 0x01, 0xe0}, mode: 64, want: "SMSWW"},
		{name: "smsw-register-long", code: []byte{0x0f, 0x01, 0xe0}, mode: 64, want: "SMSWL"},
		{name: "smsw-register-quad", code: []byte{0x48, 0x0f, 0x01, 0xe0}, mode: 64, want: "SMSWQ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := x86asm.Decode(tc.code, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			syntax, err := decodedX86GoSyntax(inst, tc.code)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(syntax, tc.want+" ") {
				t.Fatalf("raw %x decoded as %q, want %s", tc.code, syntax, tc.want)
			}
		})
	}
}

func TestX86RawDescriptorStoreCompiles(t *testing.T) {
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
			source.WriteString("TEXT rawDescriptorStore(SB),$0-0\n")
			codes := [][]byte{
				{0x0f, 0x00, 0x07}, {0x0f, 0x00, 0x0f}, {0x0f, 0x01, 0x27},
				{0x66, 0x0f, 0x00, 0xc0}, {0x0f, 0x00, 0xc0},
				{0x66, 0x0f, 0x00, 0xc8}, {0x0f, 0x00, 0xc8},
				{0x66, 0x0f, 0x01, 0xe0}, {0x0f, 0x01, 0xe0},
			}
			if target.goarch == "amd64" {
				codes = append(codes,
					[]byte{0x48, 0x0f, 0x00, 0xc0},
					[]byte{0x48, 0x0f, 0x00, 0xc8},
					[]byte{0x48, 0x0f, 0x01, 0xe0},
				)
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
				Sigs: map[string]FuncSig{"rawDescriptorStore": {Name: "rawDescriptorStore", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-descriptor-store.ll", "raw-descriptor-store.o", ir)
		})
	}
}
