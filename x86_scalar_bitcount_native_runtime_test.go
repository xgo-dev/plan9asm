package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86ScalarCountHostExecution(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	execution := x86FloatCompareExecution{llc: llc, triple: triple,
		compiler: []string{clang, "-target", triple}}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		command := runtimeOracleNativeCCommand(t, ctx, clang, "-target", triple)
		cancel()
		execution.compiler = command.Args
	}
	return execution
}

func TestX86ScalarBitCountNativeReadPortableValuesAndFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch, cWord, originalTriple := "amd64", "uint64_t", "x86_64-unknown-linux-gnu"
	if strconv.IntSize == 32 {
		arch, cWord, originalTriple = "386", "uint32_t", "i386-unknown-linux-gnu"
	}
	var assembly, declarations, prototypes, values, callbacks, faults strings.Builder
	count := 0
	for kind, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
		widths := []struct {
			suffix string
			bits   int
		}{{"W", 16}, {"L", 32}}
		if arch == "amd64" {
			widths = append(widths, struct {
				suffix string
				bits   int
			}{"Q", 64})
		}
		for _, width := range widths {
			for _, dead := range []bool{false, true} {
				name := fmt.Sprint("Count", count)
				source, declaration := x86ScalarCountNativeFixture(arch, family+width.suffix, dead)
				// Keep the indexed address for value observations. The same
				// function receives a source five bytes before the guarded input.
				assembly.WriteString(strings.ReplaceAll(source, "Value", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
				fmt.Fprintf(&prototypes, "extern %s %s(const uint8_t*);\n", cWord, name)
				fmt.Fprintf(&values, "{%s,%d,%d,%t},\n", name, width.bits, kind, dead)
				if dead {
					fmt.Fprintf(&callbacks, "static int run%d(const uint8_t *p) {\n", count)
					// Integer address arithmetic avoids constructing an
					// out-of-object C pointer by subtracting from NULL.
					fmt.Fprintf(&callbacks, "    return %s((const uint8_t*)((uintptr_t)p-5))==7 ? 0 : 91;\n}\n", name)
					fmt.Fprintf(&faults, "{run%d,%d,%d},\n", count, width.bits/8, width.bits/8-1)
				}
				count++
			}
		}
	}
	want := 18
	if arch == "386" {
		want = 12
	}
	if count != want {
		t.Fatal("incomplete live/dead scalar count directory", count, want)
	}
	x86LEAActualTargetGoObject(t, arch, originalTriple, assembly.String())
	valueDriver := strings.ReplaceAll(x86ScalarCountNativeValueDriver, "COUNT_WORD", cWord)
	valueDriver = strings.ReplaceAll(valueDriver, "PROTOTYPES", prototypes.String())
	valueDriver = strings.ReplaceAll(valueDriver, "ROWS", values.String())
	faultDriver := x86MemoryFaultDriver(prototypes.String()+callbacks.String(), faults.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, passes := range []string{"default", "O2"} {
				text := ir
				if passes == "O2" {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(passes+level, func(t *testing.T) {
						execution.compileAndRunLLVM(t, "count-values", text, valueDriver, level)
						executable := execution.compileLLVM(t, "count-faults", text, faultDriver, level)
						x86CheckMemoryFaultMatrix(t, execution, executable, count/2)
					})
				}
			}
		})
	}
	t.Log("live/dead counts, exact W/L/Q native reads, immutable inputs and canaries; actual-host portable LLVM, not original x86 execution")
}

const x86ScalarCountNativeValueDriver = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
PROTOTYPES
struct kernel { COUNT_WORD (*run)(const uint8_t*); unsigned bits,kind; bool dead; };
static const struct kernel kernels[] = { ROWS };

static unsigned independent_count(uint64_t value, unsigned bits, unsigned kind) {
    if (kind==0) {
        unsigned count=0;
        for (unsigned bit=0;bit<bits;++bit) count+=(unsigned)(value>>bit)&1;
        return count;
    }
    for (unsigned count=0;count<bits;++count) {
        unsigned bit=kind==1 ? bits-1-count : count;
        if ((value>>bit)&1) return count;
    }
    return bits;
}

int main(void) {
    for (unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);++k) {
        for (unsigned sample=0;sample<257;++sample) {
            const struct kernel *kernel=&kernels[k];
            uint64_t value=UINT64_C(0x9e3779b97f4a7c15)*sample;
            if (sample<64) value=UINT64_C(1)<<sample;
            if (sample==64) value=0;
            if (sample==65) value=UINT64_MAX;
            uint8_t input[64],before[64];
            memset(input,0xa5,sizeof(input));
            memcpy(input+5,&value,kernel->bits/8);
            memcpy(before,input,sizeof(input));
            COUNT_WORD expected=kernel->dead ? 7 : independent_count(value,kernel->bits,kernel->kind);
            COUNT_WORD got=kernel->run(input);
            if (got!=expected || memcmp(input,before,sizeof(input))) {
                fprintf(stderr,"kernel=%u sample=%u bits=%u kind=%u got=%llu want=%llu\n",
                    k,sample,kernel->bits,kernel->kind,(unsigned long long)got,(unsigned long long)expected);
                return 1;
            }
        }
    }
    return 0;
}
`
