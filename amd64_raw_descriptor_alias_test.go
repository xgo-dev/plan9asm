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

func TestX86RawDescriptorTableOperandSize(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			for i, mnemonic := range []string{"sgdt", "sidt", "lgdt", "lidt"} {
				for _, prefix := range []bool{false, true} {
					name := fmt.Sprintf("%s%t", mnemonic, prefix)
					fmt.Fprintf(&declarations, "func %s(address *byte)\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s address+0(FP),BX\n", name, word, move)
					if prefix {
						source.WriteString("BYTE $0x66\n")
					}
					fmt.Fprintf(&source, "BYTE $0x0f\nBYTE $0x01\nBYTE $%#02x\nRET\n", i<<3|3)
				}
			}
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, mnemonic := range []string{"sgdt", "sidt", "lgdt", "lidt"} {
						override := "data16; " + mnemonic
						if strings.Count(ir, `"`+mnemonic+` $0"`) != 1 || strings.Count(ir, `"`+override+` $0"`) != 1 {
							t.Fatalf("%s lost its operand-size layout in %s", mnemonic, target.arch)
						}
					}
					memoryType := fmt.Sprintf("elementtype([%d x i8])", word+2)
					if strings.Count(ir, memoryType) != 8 {
						t.Fatalf("%s descriptor access width changed", target.arch)
					}
					compileLLVMToObject(t, llc, target.triple, "raw-table.ll", "raw-table.o", ir)
				})
			}
			for _, row := range []struct {
				body string
				code error
			}{
				{"BYTE $0x66\nBYTE $0x0f\nBYTE $0x01\nBYTE $0x13\nRET\n", ErrProbeNeedsContext},
				{move + " address+0(FP),BX\nLGDT.W (BX)\nRET\n", nil},
			} {
				head := fmt.Sprintf("TEXT ·descriptor(SB),4,$0-%d\n", word)
				ir, err := x86ScalarFPBitViewAPI(t, head+row.body, "func descriptor(address *byte)", target.arch, target.triple, "text")
				if ir != "" || err == nil || row.code != nil && !errors.Is(err, row.code) {
					t.Fatalf("%s accepted a missing descriptor address or a fabricated prefix: %v", target.arch, err)
				}
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
