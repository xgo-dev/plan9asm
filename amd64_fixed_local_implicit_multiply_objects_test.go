package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalImplicitMultiplyProgram(triple string, privateLeaf bool) (string, string, string, string) {
	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	count := 0
	for _, stem := range []string{"MUL", "IMUL"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			inputs := []string{"CX", "AX", "DX", "8(SP)"}
			if width == "B" {
				inputs = append(inputs, "AH")
			}
			if width == "Q" {
				inputs = append(inputs, "(DX)")
			}
			for _, input := range inputs {
				name := fmt.Sprintf("Value%d", count)
				fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$64-32
MOVQ a+0(FP),AX
MOVQ b+8(FP),DX
MOVQ AX,0(SP)
MOVQ DX,8(SP)
MOVQ DX,CX
`, name)
				if input == "(DX)" {
					assembly.WriteString("LEAQ 8(SP),DX\n")
				}
				if privateLeaf && input == "(DX)" {
					// The source pointer addresses this caller's private frame.
					// The observed leaf never reads its own SP or a fabricated ABI.
					fmt.Fprintf(&assembly, "CALL multiply%d<>(SB)\n", count)
				} else {
					fmt.Fprintf(&assembly, "%s%s %s\n", stem, width, input)
				}
				assembly.WriteString(`MOVQ $0,R8
MOVQ $0,R9
SETCS R8
SETOS R9
MOVQ mode+16(FP),CX
CMPQ CX,$1
JEQ high
CMPQ CX,$2
JEQ carry
CMPQ CX,$3
JEQ overflow
CMPQ CX,$4
JEQ canary
JMP done
high:
MOVQ DX,AX
JMP done
carry:
MOVQ R8,AX
JMP done
overflow:
MOVQ R9,AX
JMP done
canary:
MOVQ 0(SP),AX
done:
MOVQ AX,ret+24(FP)
RET
`)
				if privateLeaf && input == "(DX)" {
					fmt.Fprintf(&assembly, "TEXT multiply%d<>(SB),4,$0-0\n%sQ (DX)\nRET\n", count, stem)
				}
				fmt.Fprintf(&declarations, "func %s(a,b,mode uint64) uint64\n", name)
				fmt.Fprintf(&goRows, "%s,\n", name)
				fmt.Fprintf(&cRows, "value%d,\n", count)
				label := runtimeCAsmLabel(prefix + "example.invalid/framefixture." + name)
				fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t,uint64_t,uint64_t) __asm__(%s);\n", count, label)
				count++
			}
		}
	}
	const values = `0,1,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,
0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,
0x8000000000000000,0xffffffffffffffff,0x8080808080808080,0x0123456789abcdef`
	original := `package main
import "fmt"
` + declarations.String() + `
func main() {
    rows := []func(uint64,uint64,uint64) uint64{
` + goRows.String() + `
    }
    values := []uint64{` + values + `}
    for n, call := range rows {
        for v, a := range values {
            b := values[(v+1)%len(values)]
            for mode := uint64(0); mode < 5; mode++ {
                got := call(a,b,mode)
                if mode == 4 && got != a { panic("private input canary changed") }
                fmt.Printf("%d %d %d %016x\n",n,v,mode,got)
            }
        }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
int main(void) {
    uint64_t (*const rows[])(uint64_t,uint64_t,uint64_t) = {
` + cRows.String() + `
    };
    const uint64_t values[] = {` + values + `};
    const unsigned count = sizeof(values)/sizeof(values[0]);
    for (unsigned n = 0; n < sizeof(rows)/sizeof(rows[0]); n++) {
        for (unsigned v = 0; v < count; v++) {
            for (unsigned mode = 0; mode < 5; mode++) {
                uint64_t got = rows[n](values[v],values[(v+1)%count],mode);
                if (mode == 4 && got != values[v]) { return 2; }
                printf("%u %u %u %016llx\n",n,v,mode,(unsigned long long)got);
            }
        }
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func TestGoAMD64FixedLocalImplicitMultiplyObjects(t *testing.T) {
	fixedLocalImplicitMultiplyObjects(t, false)
}

func fixedLocalImplicitMultiplyObjects(t *testing.T, privateLeaf bool) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, _, _ := fixedLocalImplicitMultiplyProgram("x86_64-unknown-linux-gnu", privateLeaf)
	helpers := 0
	if privateLeaf {
		helpers = 2
	}
	if strings.Count(assembly, "TEXT ·Value") != 36 || strings.Count(assembly, "TEXT multiply") != helpers {
		t.Fatal("incomplete independent multiply kernel/private-leaf inventory")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			var names []string
			for index := 0; index < 36; index++ {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "implicit-multiply.ll", "implicit-multiply.o", ir)
					compileLLVMToObject(t, llc, target.triple, "implicit-multiply-opt.ll", "implicit-multiply-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}
