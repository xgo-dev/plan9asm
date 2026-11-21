package plan9asm

import (
	"strings"
	"testing"
)

func TestX86Mode32ZeroFrameStackFence(t *testing.T) {
	const source = `TEXT ·publish(SB),4,$0-4
	MOVL p+0(FP), BX
	MOVL $1, (BX)
	XORL CX, CX
	LOCK
	XADDL CX, (SP)
	RET
`
	const declaration = "func publish(p *uint32)\n"
	const target = "i386-unknown-linux-gnu"
	runtime386CoreGoObject(t, source)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", target, api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(ir, "fence seq_cst") != 1 {
				t.Fatal("the zero-add epilogue lost its full memory fence")
			}
			compileLLVMToObject(t, llc, target, "stack-fence.ll", "stack-fence.o", ir)
		})
	}
	for _, test := range []struct{ name, old, new string }{
		{"nonzero", "XORL CX, CX", "MOVL $1, CX"},
		{"different-register", "XORL CX, CX", "XORL DX, DX"},
		{"another-slot", "(SP)", "4(SP)"},
		{"named-slot", "(SP)", "local+0(SP)"},
		{"stack-address-escape", "XORL CX, CX", "MOVL SP, (BX)\nXORL CX, CX"},
		{"bypass-zero", "XORL CX, CX", "JMP 2(PC)\nXORL CX, CX"},
		{"unlocked", "\tLOCK\n", ""},
		{"live-result", "\tRET", "\tMOVL CX, (BX)\n\tRET"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := strings.Replace(source, test.old, test.new, 1)
			ir, _ := x86ScalarFPBitViewAPI(t, input, declaration, "386", target, "Go")
			if strings.Contains(ir, "fence seq_cst") {
				t.Fatal("a changed stack, data or control effect acquired the fence role")
			}
		})
	}
}
