package plan9asm

import (
	"strings"
	"testing"
)

func TestDecodeX86RawRDPIDCompleteRegisterFamily(t *testing.T) {
	registers := [...]string{
		"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
	}
	for _, mode := range []int{32, 64} {
		count := 8
		if mode == 64 {
			count = len(registers)
		}
		for register := 0; register < count; register++ {
			code := []byte{0xf3}
			if register >= 8 {
				code = append(code, 0x41)
			}
			code = append(code, 0x0f, 0xc7, byte(0xf8|register&7))
			decoded, err := decodeX86RawDirectiveGroup(code, mode, 0, "RDPID raw bytes", nil)
			if err != nil {
				t.Fatalf("mode %d, %x: %v", mode, code, err)
			}
			if len(decoded) != 1 || decoded[0].Op != "RDPID" || len(decoded[0].Args) != 1 ||
				decoded[0].Args[0].Reg != Reg(registers[register]) {
				t.Fatalf("mode %d, %x decoded as %+v", mode, code, decoded)
			}
		}
	}
}

func TestTranslateX86RawRDPIDReportedByteArena(t *testing.T) {
	const source = `TEXT rawRDPID(SB),$0-0
	BYTE $0xF3; BYTE $0x0F; BYTE $0xC7; BYTE $0xF9
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawRDPID": {Name: "rawRDPID", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@llvm.x86.rdpid()") {
		t.Fatalf("raw RDPID did not call the RDPID intrinsic:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-rdpid.ll", "raw-rdpid.o", ir)
}
