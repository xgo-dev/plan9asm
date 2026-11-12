package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMRawUndefinedInstructionEncodings(t *testing.T) {
	for _, word := range []uint32{
		0xe7f000f0, // ARM UDF #0, used by wireguard-go's NEON tail guard.
		0xe7f001f0, // Runtime's GDB-recognized software breakpoint.
		0xe7f123f4, // ARM UDF #0x1234.
		0xe7ffffff, // ARM UDF #0xffff.
		0xf7fabcfd, // Encoding emitted by Go 1.27 for named UNDEF.
	} {
		t.Run(fmt.Sprintf("%08x", word), func(t *testing.T) {
			src := fmt.Sprintf("TEXT rawundef(SB),NOSPLIT,$0-0\n\tWORD $%#08x\n", word)
			file, err := Parse(ArchARM, src)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "arm",
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{
					"rawundef": {Name: "rawundef", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`asm sideeffect "udf #0"`, "unreachable"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw UNDEF IR missing %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-undef.ll", "arm-raw-undef.o", ir)
		})
	}
}

func TestTranslateARMRawUndefinedRejectsUnrelatedWord(t *testing.T) {
	src := "TEXT rawunknown(SB),NOSPLIT,$0-0\n\tWORD $0xffffffff\n\tRET\n"
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{
			"rawunknown": {Name: "rawunknown", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate unexpectedly accepted an unrelated ARM WORD")
	}
}

func TestTranslateARMRawFPSCRTransferPair(t *testing.T) {
	src := `TEXT fpscr(SB),NOSPLIT,$0-0
	WORD $0xeef1ba10
	BIC $(1<<24), R11
	WORD $0xeee1ba10
	RET
`
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{
			Goarch:       "arm",
			TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"fpscr": {Name: "fpscr", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for _, want := range []string{`vmrs $0, fpscr`, `vmsr fpscr, $0`} {
			if !strings.Contains(ir, want) {
				t.Fatalf("%s raw FPSCR IR missing %q:\n%s", triple, want, ir)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm-raw-fpscr.ll", "arm-raw-fpscr.o", ir)
	}
}

func TestTranslateARMRawYieldHint(t *testing.T) {
	src := "TEXT yieldhint(SB),NOSPLIT,$0-0\n\tWORD $0xe320f001\n\tRET\n"
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf"} {
		ir, err := Translate(file, Options{
			Goarch:       "arm",
			TargetTriple: triple,
			Sigs: map[string]FuncSig{
				"yieldhint": {Name: "yieldhint", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		if !strings.Contains(ir, `.long 0xe320f001`) {
			t.Fatalf("%s raw YIELD encoding was not preserved:\n%s", triple, ir)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm-raw-yield.ll", "arm-raw-yield.o", ir)
	}
}
