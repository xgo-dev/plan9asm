package plan9asm

import (
	"errors"
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
			word, move := 8, "MOVQ"
			if target.goarch == "386" {
				word, move = 4, "MOVL"
			}
			head := fmt.Sprintf("TEXT ·rawDescriptorStore(SB),4,$0-%d\n", word)
			setup := fmt.Sprintf("%s address+0(FP), DI\n", move)
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
			body := source.String()
			const decl = "func rawDescriptorStore(address *[2]byte)"
			bound := head + setup + body
			requireX86GoAssemblerResult(t, target.goarch, bound, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, bound, decl, target.goarch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(ir, "elementtype(i16)") != 3 {
						t.Fatalf("raw descriptor stores must preserve each m16 access:\n%s", ir)
					}
					for _, regForm := range []struct{ suffix, typ string }{{"w", "i16"}, {"l", "i32"}, {"q", "i64"}} {
						if regForm.suffix == "q" && target.goarch == "386" {
							continue
						}
						for _, stem := range []string{"sldt", "smsw", "str"} {
							prefix := fmt.Sprintf("call %s asm sideeffect %q", regForm.typ, stem+regForm.suffix+" $0")
							if !strings.Contains(ir, prefix) {
								t.Fatalf("raw descriptor register width missing %s:\n%s", prefix, ir)
							}
						}
					}
					compileLLVMToObject(t, llc, target.triple, "raw-descriptor-store.ll", "raw-descriptor-store.o", ir)

					if out, err := x86ScalarFPBitViewAPI(t, head+body, decl, target.goarch, target.triple, api); out != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("descriptor store with no address setup: %v\n%s", err, out)
					}
					const override = "BYTE $0x67\nBYTE $0x0f\nBYTE $0x00\nBYTE $0x07\nRET\n"
					if out, err := x86ScalarFPBitViewAPI(t, head+setup+override, decl, target.goarch, target.triple, api); out != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("descriptor store with an unbound address-size override: %v\n%s", err, out)
					}
				})
			}
		})
	}
}
