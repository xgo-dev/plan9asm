package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
)

func TestX86OrdinaryNumericTuplePortableDefinedCallerValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, row := range []struct{ typ, move, register, llvm, seed, bits string }{
		{"uint32", "MOVL", "AX", "i32", "uint32_t", "0, 1, UINT32_C(0x80000000), UINT32_MAX"},
		{"float64", "MOVSD", "X0", "double", "uint64_t", "0, UINT64_C(0x8000000000000000), UINT64_C(0x3ff8000000000000), UINT64_C(0x7ff8000000000042)"},
	} {
		for _, statusFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/status-first=%t", row.typ, statusFirst), func(t *testing.T) {
				declaration, source, sig, _ := x86NumericTuplePartialFixture(t, arch, row.typ, row.move, row.register, statusFirst)
				goAssemblerOracleOutput(t, arch, source, "", true)
				statusIndex, valueIndex := 0, 1
				if !statusFirst {
					statusIndex, valueIndex = 1, 0
				}
				statusType := sig.Frame.Results[statusIndex].Type
				convert := "  %bits = zext i32 %value to i64\n"
				argument := "i32 %input"
				if row.llvm == "double" {
					convert = "  %bits = bitcast double %value to i64\n"
					argument = "double %payload"
				}
				prepare := ""
				if row.llvm == "double" {
					prepare = "  %payload = bitcast i64 %input to double\n"
				}
				caller := fmt.Sprintf(`
define i64 @ObserveNumericTuple(i32 %%fail, %s %%input) {
entry:
%s  %%pair = call %s @Value(i32 %%fail, %s)
  %%status = extractvalue %s %%pair, %d
  %%failed = icmp slt %s %%status, 0
  br i1 %%failed, label %%failure, label %%success
failure:
  %%errorOK = icmp eq %s %%status, -1
  %%errorResult = select i1 %%errorOK, i64 81985529216486895, i64 0
  ret i64 %%errorResult
success:
  %%successOK = icmp eq %s %%status, 0
  %%value = extractvalue %s %%pair, %d
%s  %%result = select i1 %%successOK, i64 %%bits, i64 0
  ret i64 %%result
}
`, map[bool]string{true: "i64", false: "i32"}[row.llvm == "double"], prepare,
					sig.Ret, argument, sig.Ret, statusIndex, statusType, statusType,
					statusType, sig.Ret, valueIndex, convert)
				// The failure branch observes only the written status. Its payload
				// is neither extracted nor compared, including incidental zeroes.
				driver := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern uint64_t ObserveNumericTuple(uint32_t, %s);
int main(void) {
    const %s input[] = {%s};
    const uint32_t failure[] = {0, 1, UINT32_MAX};
    for (unsigned f = 0; f < 3; ++f) {
        for (unsigned i = 0; i < 4; ++i) {
            uint64_t want = failure[f] ? UINT64_C(0x0123456789abcdef) : (uint64_t)input[i];
            uint64_t got = ObserveNumericTuple(failure[f], input[i]);
            if (got != want) {
                fprintf(stderr, "numeric tuple fail=%%u row=%%u got=%%llx want=%%llx\n",
                    failure[f], i, (unsigned long long)got, (unsigned long long)want);
                return 1;
            }
        }
    }
    return 0;
}
`, row.seed, row.seed, row.bits)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil {
							t.Fatal(err)
						}
						ir += caller
						for _, optimized := range []bool{false, true} {
							t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
								text := ir
								if optimized {
									text = x86DwordProductIROptimize(t, ir)
								}
								for _, level := range []int{0, 2} {
									t.Run(fmt.Sprintf("backend-O%d", level), func(t *testing.T) {
										compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "numeric-tuple-caller", triple, text, driver, nil, level)
									})
								}
							})
						}
					})
				}
			})
		}
	}
}
