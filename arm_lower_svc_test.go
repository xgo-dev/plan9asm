package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMSVCAsLinuxSyscall(t *testing.T) {
	const source = `TEXT rawSVC(SB), $0-0
	SVC $0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"rawSVC": {Name: "rawSVC", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@syscall") {
		t.Fatalf("ARM SVC did not lower through syscall ABI:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-svc.ll", "arm-svc.o", ir)
}
