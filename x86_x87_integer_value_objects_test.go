package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86X87ExactIntegerCarrierFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		for _, mode := range []X87Mode{X87Software, X87Hardware} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mode%d/%s", target.triple, mode, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, x86X87SignedI64IdentitySource,
						x86X87SignedI64IdentityDeclaration, target.arch, target.triple, api, mode)
					if err != nil || ir == "" {
						t.Fatal("complete identity did not reach object compilation", err)
					}
					if mode == X87Hardware && !strings.Contains(ir, "fildll $2") {
						t.Fatal("hardware integer path projected the exact payload through double")
					}
					for _, level := range []string{"0", "2"} {
						input := ir
						if level == "2" {
							input = x86DwordProductIROptimize(t, input)
						}
						for _, backend := range []string{"0", "2"} {
							t.Run("IR"+level+"/backend"+backend, func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, "-O"+backend)
							})
						}
					}
				})
			}
		}
	}
}

func TestX86X87ExactIntegerCarrierHostSoftwareExecution(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang are required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	const driver = `
#include <stdint.h>
#include <stdio.h>
extern int64_t Value(int64_t);
int main(void) {
  volatile int64_t input[]={0,1,-1,INT64_C(9007199254740993),
    -INT64_C(9007199254740993),INT64_MAX,INT64_MIN,
    INT64_C(0x5555555555555555),-INT64_C(0x5555555555555555)};
  for (unsigned i=0;i<sizeof(input)/sizeof(input[0]);i++) {
    int64_t value=input[i], got=Value(value);
    if(got!=value) {
      fprintf(stderr,"input[%u]=%lld got=%lld\n",i,(long long)value,(long long)got);
      return 1;
    }
  }
  return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/IR-O2-%t", api, optimized), func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, x86X87SignedI64IdentitySource,
					x86X87SignedI64IdentityDeclaration, "amd64", triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("complete identity did not reach host Software execution", err)
				}
				if optimized {
					ir = x86DwordProductIROptimize(t, ir)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "x87-exact-integer", triple, ir, driver, nil)
			})
		}
	}
}
