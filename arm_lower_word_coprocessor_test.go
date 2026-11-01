package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMRawMRCWord(t *testing.T) {
	const source = `TEXT rawMRC(SB), $0-0
	WORD $0xee100f10 // mrc p15, 0, r0, c0, c0, 0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"rawMRC": {Name: "rawMRC", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mrc p15") {
		t.Fatalf("ARM raw MRC did not lower to inline asm:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-mrc.ll", "arm-raw-mrc.o", ir)
}

func TestTranslateARMRawMCRWord(t *testing.T) {
	const source = `TEXT rawMCR(SB), $0-0
	WORD $0xee000f10 // mcr p15, 0, r0, c0, c0, 0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"rawMCR": {Name: "rawMCR", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mcr p15") {
		t.Fatalf("ARM raw MCR did not lower to inline asm:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-mcr.ll", "arm-raw-mcr.o", ir)
}

func TestTranslateARMMRCNamedControlRegisters(t *testing.T) {
	const source = `TEXT ·namedMRC(SB), $0-0
	MRC $15, $0, R0, C13, C0, $3
	RET
`
	ir := translateARMForTest(t, source, map[string]FuncSig{
		"example.namedMRC": {Name: "example.namedMRC", Ret: Void},
	})
	if !strings.Contains(ir, `mrc p15, #0, $0, c13, c0, #3`) {
		t.Fatalf("named ARM MRC did not normalize control registers:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-named-mrc.ll", "arm-named-mrc.o", ir)
}
