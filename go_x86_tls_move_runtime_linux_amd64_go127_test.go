//go:build go1.27 && linux && amd64

package plan9asm

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// This is the required native Linux AMD64 owner. Other hosts retain portable
// source/object coverage and this explicit cross-runtime counterpart. Missing
// tools on the selected native owner fail rather than skipping execution.
func TestCrossLinuxRuntimeMatrixX86TLSNoopPreservesWideGP(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 runtime tools required")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	pkg, file, options, original, request := x86TLSMoveSourceFixture(t, "linux/amd64", false,
		"func Value(a uint64) uint64", "MOVQ a+0(FP),CX\nMOVL TLS,CX\nMOVQ TLS,CX\nMOVD TLS,CX\nMOVDQ2Q TLS,CX\nMOVQ CX,ret+8(FP)\nRET")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	observed, err := CaptureGoX86TLSMoveSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	if len(observed.noops) != 4 || len(observed.texts[0]) != 1 || len(observed.texts[0][0].Relocations) != 0 {
		t.Fatal("runtime oracle lacks its complete relocation-free original NOP body")
	}
	bound, err := observed.BindTLSMoves(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	var encoded []string
	for _, value := range observed.texts[0][0].Code {
		encoded = append(encoded, fmt.Sprintf("0x%02x", value))
	}
	core, shim := "tls_original_body", "tls_original"
	if strings.Contains(execution.triple, "apple") {
		core, shim = "_"+core, "_"+shim
	}
	// The independent SysV shim allocates actual Go ABI0 input/result cells.
	// The bytes inside core come directly from the original source object;
	// they are not reconstructed from the normalized LLVM or a mnemonic list.
	assembly := ".text\n.globl " + core + "\n" + core + ":\n.byte " + strings.Join(encoded, ",") + "\n" +
		".globl " + shim + "\n" + shim + ":\nsubq $24,%rsp\nmovq %rdi,0(%rsp)\ncallq " + core +
		"\nmovq 8(%rsp),%rax\naddq $24,%rsp\nretq\n"
	main := fmt.Sprintf("__asm__(%q);\n", assembly) + `
#include <stdint.h>
#include <stdio.h>
extern uint64_t Value(uint64_t);
extern uint64_t tls_original(uint64_t);
int main(void) {
    const uint64_t patterns[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0xffffffff00000000),UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210)};
    for(unsigned i=0;i<sizeof(patterns)/sizeof(*patterns);++i) {
        uint64_t native=tls_original(patterns[i]),translated=Value(patterns[i]);
        if(native!=patterns[i] || translated!=native) {
            fprintf(stderr,"TLS NOP case=%u native=%llx LLVM=%llx expected=%llx\n",
                i,(unsigned long long)native,(unsigned long long)translated,(unsigned long long)patterns[i]);
            return 1;
        }
    }
    puts("7 original Go/LLVM TLS NOP wide-register patterns");
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86TLSMoveBoundAPI(t, pkg, file, original, bound, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, optimization := range []string{"-O0", "-O2"} {
			executable := execution.compileLLVM(t, "tls-nop-"+api, ir, main, optimization)
			output := x86FloatCompareCaptureCommand(t, exec.Command(executable))
			if string(output) != "7 original Go/LLVM TLS NOP wide-register patterns\n" {
				t.Fatalf("incomplete native/LLVM runtime receipt: %s", output)
			}
		}
	}
	t.Logf("actual original Go ABI0 bytes and LLVM NOP consumer; execution host=%s/%s", runtime.GOOS, runtime.GOARCH)
}
