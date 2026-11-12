package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

const amd64VirtualArgumentValueDeclarations = amd64VirtualArgumentsDeclarations + `
func SliceLength(a []byte) uint64
func SliceCapacity(a []byte) uint64
func SecondSliceLength(a, b []byte) uint64
func SecondSliceCapacity(a, b []byte) uint64
func StringLength(a string) uint64
`

const amd64VirtualArgumentValueSource = amd64VirtualArgumentsSource + `
TEXT ·SliceLength<ABIInternal>(SB),4,$0
	MOVQ BX, AX
	RET

TEXT ·SliceCapacity<ABIInternal>(SB),4,$0
	MOVQ CX, AX
	RET

TEXT ·SecondSliceLength<ABIInternal>(SB),4,$0
	MOVQ SI, AX
	RET

TEXT ·SecondSliceCapacity<ABIInternal>(SB),4,$0
	MOVQ R8, AX
	RET

TEXT ·StringLength<ABIInternal>(SB),4,$0
	MOVQ BX, AX
	RET
`

// The scalar C ABI shims construct the actual grouped LLVM arguments. They
// append independent callers to the unchanged translated definitions; they
// neither flatten/rewrite those definitions nor claim stock-Go native entry.
func amd64VirtualArgumentScalarShims() string {
	var result strings.Builder
	for _, row := range []struct {
		name, entry string
		arguments   int
		slice       bool
	}{
		{"virtual_compare_slices", "CompareSlices", 2, true},
		{"virtual_compare_strings", "CompareStrings", 2, false},
		{"virtual_slice_length", "SliceLength", 1, true},
		{"virtual_slice_capacity", "SliceCapacity", 1, true},
		{"virtual_second_length", "SecondSliceLength", 2, true},
		{"virtual_second_capacity", "SecondSliceCapacity", 2, true},
		{"virtual_string_length", "StringLength", 1, false},
	} {
		typ, fields := "{ ptr, i64 }", 2
		if row.slice {
			typ, fields = "{ ptr, i64, i64 }", 3
		}
		var parameters, arguments []string
		for argument := 0; argument < row.arguments; argument++ {
			parameters = append(parameters, fmt.Sprintf("ptr %%p%d, i64 %%n%d", argument, argument))
			if row.slice {
				parameters = append(parameters, fmt.Sprintf("i64 %%c%d", argument))
			}
			arguments = append(arguments, fmt.Sprintf("%s %%a%d_%d", typ, argument, fields-1))
		}
		fmt.Fprintf(&result, "\ndefine i64 @%s(%s) {\n", row.name, strings.Join(parameters, ", "))
		for argument := 0; argument < row.arguments; argument++ {
			fmt.Fprintf(&result, "  %%a%d_0 = insertvalue %s poison, ptr %%p%d, 0\n", argument, typ, argument)
			fmt.Fprintf(&result, "  %%a%d_1 = insertvalue %s %%a%d_0, i64 %%n%d, 1\n", argument, typ, argument, argument)
			if row.slice {
				fmt.Fprintf(&result, "  %%a%d_2 = insertvalue %s %%a%d_1, i64 %%c%d, 2\n", argument, typ, argument, argument)
			}
		}
		fmt.Fprintf(&result, "  %%value = call i64 @%q(%s)\n  ret i64 %%value\n}\n",
			amd64VirtualArgumentsPackage+"."+row.entry, strings.Join(arguments, ", "))
	}
	return result.String()
}

func amd64VirtualArgumentValueIR(t *testing.T, triple, api string, preprocessed bool) string {
	t.Helper()
	pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, amd64VirtualArgumentValueDeclarations)
	ir, err := amd64VirtualArgumentsRequest(t, pkg, []byte(amd64VirtualArgumentValueSource), triple, api, preprocessed, nil)
	if err != nil {
		t.Fatal("complete original virtual argument source", err)
	}
	if strings.Count(ir, "define ") != 7 {
		t.Fatal("the complete seven public entries were cropped or a private node became a callable entry", ir)
	}
	for _, name := range []string{"CompareSlices", "CompareStrings", "SliceLength", "SliceCapacity", "SecondSliceLength", "SecondSliceCapacity", "StringLength"} {
		if !strings.Contains(ir, "define i64 @"+fmt.Sprintf("%q", pkg.Path+"."+name)+"(") {
			t.Fatal("original grouped entry missing", name, ir)
		}
	}
	return ir
}

func TestGoModuleAMD64VirtualArgumentsCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete virtual argument objects require LLVM22 llc")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				for _, preprocessed := range []bool{false, true} {
					ir := amd64VirtualArgumentValueIR(t, triple, api, preprocessed) + amd64VirtualArgumentScalarShims()
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, input, level)
						}
					}
				}
			})
		}
	}
}

func TestGoModuleAMD64VirtualArgumentsPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("portable virtual argument execution requires LLVM22 llc/clang")
	}
	// This runs numerical/opaque-pointer transport on the actual LLVM host.
	// Large descriptor lengths/capacities test word-width transport only: no
	// memory is read, and they are not claims about live Go heap allocations.
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler := []string{clang}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	const driver = `#include <stdint.h>
#include <stdio.h>

extern int64_t virtual_compare_slices(const void *, uint64_t, uint64_t,
                                      const void *, uint64_t, uint64_t);
extern int64_t virtual_compare_strings(const void *, uint64_t,
                                       const void *, uint64_t);
extern uint64_t virtual_slice_length(const void *, uint64_t, uint64_t);
extern uint64_t virtual_slice_capacity(const void *, uint64_t, uint64_t);
extern uint64_t virtual_second_length(const void *, uint64_t, uint64_t,
                                       const void *, uint64_t, uint64_t);
extern uint64_t virtual_second_capacity(const void *, uint64_t, uint64_t,
                                         const void *, uint64_t, uint64_t);
extern uint64_t virtual_string_length(const void *, uint64_t);

int main(void) {
    const uint64_t values[] = {
        0, 1, 63, 64, UINT64_C(0x7fffffff), UINT64_C(0xffffffff),
        UINT64_C(0x100000000), INT64_MAX
    };
    volatile uint8_t canaries[128];
    for (unsigned i = 0; i < sizeof(canaries); ++i) canaries[i] = (uint8_t)(3*i+7);
    const void *a = (const void *)&canaries[1];
    const void *b = (const void *)&canaries[63];
    if (virtual_compare_slices(NULL,0,0,NULL,0,0) != 0 ||
        virtual_compare_strings(NULL,0,NULL,0) != 0 ||
        virtual_slice_length(NULL,0,0) != 0 ||
        virtual_slice_capacity(NULL,0,0) != 0 ||
        virtual_string_length(NULL,0) != 0) return 3;
    for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
        for (unsigned j = 0; j < sizeof(values)/sizeof(values[0]); ++j) {
            uint64_t al = values[i], bl = values[j];
            uint64_t ac = al + (al < INT64_MAX);
            uint64_t bc = bl < INT64_MAX-3 ? bl+3 : bl;
            int64_t want = (al > bl) - (al < bl);
            if (virtual_compare_slices(a,al,ac,b,bl,bc) != want ||
                virtual_compare_strings(a,al,b,bl) != want ||
                virtual_slice_length(a,al,ac) != al ||
                virtual_slice_capacity(a,al,ac) != ac ||
                virtual_second_length(a,al,ac,b,bl,bc) != bl ||
                virtual_second_capacity(a,al,ac,b,bl,bc) != bc ||
                virtual_string_length(a,al) != al) {
                fprintf(stderr,"virtual parameter mismatch i=%u j=%u\n",i,j);
                return 1;
            }
            for (unsigned k = 0; k < sizeof(canaries); ++k) {
                if (canaries[k] != (uint8_t)(3*k+7)) {
                    fprintf(stderr,"pointer transport wrote caller memory\n");
                    return 2;
                }
            }
        }
    }
    return 0;
}
`
	for _, api := range []string{"public", "owned-context"} {
		ir := amd64VirtualArgumentValueIR(t, triple, api, true) + amd64VirtualArgumentScalarShims()
		for _, optimized := range []bool{false, true} {
			input := ir
			if optimized {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/IR_O2=%t/backendO%d", api, optimized, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler,
						"virtual-go-arguments", triple, input, driver, nil, level)
				})
			}
		}
	}
}
