package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86UnreachableRawTailAfterReturn(t *testing.T) {
	const source = `
TEXT rawtail(SB),$0-0
	RET
GLOBL structtbl(SB),$8
	BYTE $0x7b; BYTE $0x7d; BYTE $0x5b; BYTE $0x5d
	BYTE $0x22; BYTE $0x3a; BYTE $0x2c; BYTE $0x27
GLOBL wordtbl(SB),$4
	BYTE $0x74; BYTE $0x68; BYTE $0x6e; BYTE $0x6b
`
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"rawtail": {Name: "rawtail", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "structtbl") || !strings.Contains(ll, "wordtbl") {
				t.Fatal("GLOBL declarations disappeared from IR")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "x86-raw-unreachable-tail.ll", "x86-raw-unreachable-tail.o", ll)
		})
	}
}

func TestTranslateX86LabeledRawTailRemainsReachable(t *testing.T) {
	const source = `
TEXT rawtail(SB),$0-0
	JMP tail
	RET
tail:
	BYTE $0x7b; BYTE $0x7d
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"rawtail": {Name: "rawtail", Ret: Void},
		},
	}); err == nil || !strings.Contains(err.Error(), "outside directive group") {
		t.Fatalf("reachable malformed raw tail was not rejected: %v", err)
	}
}

func TestTranslateX86AddressObservedRawTailFailsClosed(t *testing.T) {
	const source = `
TEXT rawtail(SB),$0-0
	RET
	BYTE $0x7b; BYTE $0x7d
TEXT address(SB),$0-0
	MOVQ $rawtail(SB), AX
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"rawtail": {Name: "rawtail", Ret: Void},
			"address": {Name: "address", Ret: Void},
		},
	}); err == nil || !strings.Contains(err.Error(), "address-observed raw tail") {
		t.Fatalf("accepted layout-sensitive raw tail: %v", err)
	}
}
