package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The two loops use the same authenticated local length, without supplying an
// allocation extent. Every body read and result byte still needs caller proof.
func x86CallerCountedSCCAssembly(raw, diamond bool) string {
	first := "TESTB $3,R9\nJE first_done\nMOVL R9,AX\nANDL $3,AX\nXORL CX,CX"
	latch := "ADDQ $1,CX\nCMPL CX,AX\nJNE first_body"
	if raw {
		first = "LONG $0x03c1f641\nJE first_done\nWORD $0x8944; BYTE $0xc8\nWORD $0xe083; BYTE $0x03\nWORD $0xc931"
		latch = "LONG $0x01c18348\nWORD $0xc839\nJNE first_body"
	}
	body := "MOVQ (CX),R9\nXORL R10,R10\n" + first + `
first_body:
MOVL (DI),BX
MOVL (SI),R11
ADDL R11,BX
ADDL BX,R10
ADDQ $4,DI
ADDQ $4,SI
` + latch + "\nfirst_done:\n"
	if diamond {
		// The input value is numerically defined but not a partition constant.
		// Both feasible predecessors must initialize the value consumed below.
		body += `MOVL (DI),BX
CMPL BX,$0
JE other
MOVL $3,R11
JMP joined
other:
MOVL $5,R11
joined:
ADDL R11,R10
`
	}
	body += `TESTB $3,R9
JE done
MOVL R9,R13
ANDL $3,R13
XORL R12,R12
second_body:
MOVL (DI),BX
MOVL (SI),R11
ADDL R11,BX
ADDL BX,R10
ADDQ $4,DI
ADDQ $4,SI
ADDQ $1,R12
CMPL R12,R13
JNE second_body
done:
MOVL R10,(DX)`
	return strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", body, 1)
}

func x86CallerCountedSCCObjects(t *testing.T, source, assembly, triple string) {
	t.Helper()
	pkg, file := x86CallerCoreFixture(t, source, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	before := fmt.Sprintf("%#v %#v", file, sigs)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, llc, triple, "scc-text.ll", "scc-text.o", ir)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, llc, triple, "scc-module.ll", "scc-module.o", module.String())
	if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
		t.Fatal(err)
	}
	if before != fmt.Sprintf("%#v %#v", file, sigs) {
		t.Fatal("independent replay mutated original source or caller signatures")
	}
}

func TestX86GoCallerCountedSCCSerialLoopsAndDiamondThreeAPIs(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, diamond := range []bool{false, true} {
			assembly := x86CallerCountedSCCAssembly(raw, diamond)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				t.Run(fmt.Sprintf("raw=%t/diamond=%t/%s", raw, diamond, triple), func(t *testing.T) {
					x86CallerCountedSCCObjects(t, x86CallerCountedLoopScalarSource(), assembly, triple)
				})
			}
		}
	}
}
