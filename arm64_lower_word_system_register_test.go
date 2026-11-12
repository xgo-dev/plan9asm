package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeARM64RawSystemRegisterCompleteEncodingFields(t *testing.T) {
	for _, direction := range []struct {
		base uint32
		read bool
	}{{0xd5100000, false}, {0xd5300000, true}} {
		for encoding := 0; encoding <= 0x7fff; encoding++ {
			for reg := 0; reg < 32; reg++ {
				word := direction.base | uint32(encoding)<<5 | uint32(reg)
				got, ok := decodeARM64RawSystemRegister(word)
				if !ok || got.read != direction.read || got.encoding != uint16(encoding) || got.reg != reg {
					t.Fatalf("decode %#08x = %#v, %v", word, got, ok)
				}
			}
		}
	}
	for _, word := range []uint32{0xd5000000, 0xd5200000, 0xd5400000, 0xd4ffffff} {
		if got, ok := decodeARM64RawSystemRegister(word); ok {
			t.Fatalf("decodeARM64RawSystemRegister(%#08x) = %#v, true", word, got)
		}
	}
	if got := arm64EncodedSystemRegisterName(0x5e82); got != "S3_3_C13_C0_2" {
		t.Fatalf("TPIDR_EL0 encoding name = %q", got)
	}
}

func TestTranslateARM64RawSystemRegisterFamilyLLVM22(t *testing.T) {
	const source = `TEXT ·rawSystemRegisters(SB), $0-0
	WORD $0xd53bd040
	WORD $0xd51bd040
	WORD $0xd53bd05f
	WORD $0xd51bd05f
	RET
`
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"rawSystemRegisters": {Name: "rawSystemRegisters", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{"mrs $0, S3_3_C13_C0_2", "msr S3_3_C13_C0_2, $0"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("%s raw system-register IR omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, fmt.Sprintf("arm64-raw-system-register-%s.ll", strings.ReplaceAll(triple, "-", "_")), "arm64-raw-system-register.o", ll)
	}
}
