package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Compose the existing mask-value, FLAGS and vector transports without a
// per-opcode initializer. The byte witnesses supply syntax, never input facts.
func x86OfficialKDataAssembly(arch string, cases []x86OfficialPackedCase) (string, string) {
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		w := fixture.witness
		fixture.symbol = fmt.Sprint("KData", index)
		fmt.Fprintf(&declarations, "func %s(out,a,b *byte)\n", fixture.symbol)
		prefix := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DX\n%s a+%d(FP),AX\n%s b+%d(FP),BX\n",
			fixture.symbol, 3*word, move, move, word, move, 2*word)
		gpSeed := ""
		for input, register := range []string{w.First, w.Second} {
			if register == "" || strings.Contains(register, "(") {
				continue
			}
			pointer := []string{"AX", "BX"}[input]
			if _, mask := amd64ParseKReg(Reg(register)); mask {
				prefix += fmt.Sprintf("KMOVQ (%s),%s\n", pointer, register)
			} else if isX86YrlRegisterForArch(Reg(register), arch) {
				gpSeed += fmt.Sprintf("%s (%s),%s\n", move, pointer, register)
			} else {
				prefix += fmt.Sprintf("VMOVUPS (%s),%s\n", pointer, register)
			}
		}
		// GP input may replace AX only after every pointer-dependent input.
		prefix += gpSeed
		fixture.line = line + strings.Count(prefix, "\n")
		body := prefix + w.Instruction + "\n"
		switch {
		case w.Destination == "":
			suffix := "Q"
			if arch == "386" {
				suffix = "L"
			}
			body += fmt.Sprintf("PUSHF%s\nPOP%s CX\nAND%s $0x8d5,CX\n%s CX,(DX)\n", suffix, suffix, suffix, move)
		case w.MaskResult:
			body += fmt.Sprintf("KMOVQ %s,(DX)\n", w.Destination)
		case w.Width != 0:
			// EVEX writes clear the complete wider alias, not only its low carrier.
			body += fmt.Sprintf("VMOVUPS Z%s,(DX)\n", w.Destination[1:])
		case !strings.Contains(w.Destination, "("):
			body += fmt.Sprintf("%s %s,(DX)\n", move, w.Destination)
		}
		body += "RET\n"
		source.WriteString(body)
		line += strings.Count(body, "\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialKDataRowsInitializedThreeAPIsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			x86OfficialPackedRowsObjectsForTarget(t, arch, triple, goasmrules.X86KDataRows, 87, 91, 0,
				func(cases []x86OfficialPackedCase) (string, string) { return x86OfficialKDataAssembly(arch, cases) },
				func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
					x86PackedStringCompileObject(t, llc, triple, ir, "-O2")
				})
		})
	}
}
