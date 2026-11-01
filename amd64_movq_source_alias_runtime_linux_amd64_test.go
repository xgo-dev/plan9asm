//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Native Linux AMD64 owns execution. Other hosts run the portable source,
// original-object and LLVM-object tests; no host skip is runtime evidence.
func TestCrossLinuxRuntimeMatrixX86MOVQSourceAliasesOriginalAndLLVM(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 native runtime tools required")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	var source, declarations, prototypes, originals, checks strings.Builder
	count := 0
	for _, alias := range append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...) {
		for _, operation := range []string{"gp", "gp-x", "fp-x-clear", "native-gp", "native-x", "address"} {
			name, original, core := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count), fmt.Sprintf("OriginalBody%d", count)
			declaration := "func Value(x uint64) uint64"
			body := alias + " x+0(FP),CX\n" + alias + " CX,DX\n" + alias + " DX,ret+8(FP)\nRET"
			switch operation {
			case "gp-x":
				body = alias + " x+0(FP),CX\n" + alias + " CX,X0\n" + alias + " X0,DX\n" + alias + " DX,ret+8(FP)\nRET"
			case "fp-x-clear":
				body = alias + " x+0(FP),X0\n" + alias + " X0,X1\nPSRLO $8,X1\n" + alias + " X1,ret+8(FP)\nRET"
			case "native-gp", "native-x":
				declaration = "func Value(p *[8]byte) uint64"
				register := "DX"
				if operation == "native-x" {
					register = "X0"
				}
				body = "MOVQ p+0(FP),AX\nMOVL $1,CX\n" + alias + " -1(AX)(CX*1)," + register + "\n" + alias + " " + register + ",ret+8(FP)\nRET"
			case "address":
				body = alias + " x+0(FP),CX\n" + alias + " $8(CX),DX\n" + alias + " DX,ret+8(FP)\nRET"
			}
			_, _, _, assembly := x86ResultInitializationFixture(t, "amd64", declaration, body)
			encoded := x86OrderingHintGoBytes(t, "amd64", assembly)
			var literal []string
			for _, value := range encoded {
				literal = append(literal, fmt.Sprintf("0x%02x", value))
			}
			// Independently transport the SysV input into real Go ABI0 cells.
			// Execute complete bytes assembled from this exact original body.
			shim := ".text\n.globl " + core + "\n" + core + ":\n.byte " + strings.Join(literal, ",") + "\n" +
				".globl " + original + "\n" + original + ":\nsubq $24,%rsp\nmovq %rdi,0(%rsp)\ncallq " + core +
				"\nmovq 8(%rsp),%rax\naddq $24,%rsp\nretq\n"
			fmt.Fprintf(&originals, "__asm__(%q);\n", shim)
			source.WriteString(strings.ReplaceAll(assembly, "·Value", "·"+name))
			declarations.WriteString(strings.Replace(declaration, "Value", name, 1) + "\n")
			argument, expected := "pattern", "pattern"
			parameter := "uint64_t"
			if strings.HasPrefix(operation, "native-") {
				parameter, argument = "const uint64_t*", "&backing[1]"
			}
			if operation == "fp-x-clear" {
				expected = "0"
			} else if operation == "address" {
				expected = "pattern+UINT64_C(8)"
			}
			fmt.Fprintf(&prototypes, "extern uint64_t %s(%s);\nextern uint64_t %s(%s);\n", name, parameter, original, parameter)
			fmt.Fprintf(&checks, "{uint64_t native=%s(%s),translated=%s(%s),expected=%s;\n"+
				"if(native!=expected || translated!=native || backing[0]!=canary || backing[1]!=pattern || backing[2]!=canary) {\n"+
				"fprintf(stderr,\"alias=%s op=%s sample=%%u native=%%llx LLVM=%%llx expected=%%llx\\n\",sample,"+
				"(unsigned long long)native,(unsigned long long)translated,(unsigned long long)expected);return 1;}}\n",
				original, argument, name, argument, expected, alias, operation)
			count++
		}
	}
	if count != 18 {
		t.Fatal("complete original source-alias runtime inventory changed", count)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
` + originals.String() + prototypes.String() + `
int main(void) {
    const uint64_t patterns[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0xffffffff00000000),UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210)};
    const uint64_t canary=UINT64_C(0x9876543210abcdef);
    for(unsigned sample=0;sample<7;sample++) {
        uint64_t pattern=patterns[sample],backing[3]={canary,pattern,canary};
` + checks.String() + `
    }
    puts("126 original Go/LLVM MOVQ source-alias cases");
    return 0;
}

`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			executable := execution.compileLLVM(t, "source-movq-alias-"+api, ir, driver, level)
			output := x86FloatCompareCaptureCommand(t, exec.Command(executable))
			if string(output) != "126 original Go/LLVM MOVQ source-alias cases\n" {
				t.Fatalf("incomplete original/LLVM source alias runtime receipt: %s", output)
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86MOVQSourceAliasesCountedProvenance(t *testing.T) {
	aliases := append([]string{"MOVQ"}, x86OriginalMOVQAliases(t)...)
	t.Run("original Go", func(t *testing.T) { runX86CallerCountedLoopOriginalValues(t, aliases) })
	t.Run("LLVM", func(t *testing.T) { runX86CallerCountedLoopLLVMValues(t, aliases) })
}
