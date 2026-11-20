package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"
)

func x86NumericAddressProgram(arch string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations string
	for _, row := range []struct {
		name, parameter string
		indirect, store bool
	}{
		{"NumericLoad", "uintptr", false, false},
		{"IndirectLoad", "*uintptr", true, false},
		{"NumericStore", "uintptr", false, true},
		{"IndirectStore", "*uintptr", true, true},
	} {
		source += fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n", row.name, word+4, move)
		if row.indirect {
			source += move + " (AX),AX\n"
		}
		if row.store {
			source += "MOVL $42,(AX)\nMOVL $42,CX\n"
		} else {
			source += "MOVL (AX),CX\n"
		}
		source += fmt.Sprintf("MOVL CX,ret0+%d(FP)\nRET\n", word)
		declarations += fmt.Sprintf("func %s(p %s) uint32\n", row.name, row.parameter)
	}
	return source, declarations
}

const x86NumericAddressPrototypes = `
#include <stdint.h>
extern uint32_t NumericLoad(uintptr_t);
extern uint32_t IndirectLoad(const uintptr_t*);
extern uint32_t NumericStore(uintptr_t);
extern uint32_t IndirectStore(const uintptr_t*);
`

func x86NumericAddressRuntimeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc and clang are required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	execution := x86FloatCompareExecution{llc: llc, triple: triple,
		compiler: []string{clang, "-target", triple}}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		execution.compiler = runtimeOracleNativeCCommand(t, ctx, clang, "-target", triple).Args
	}
	return execution
}

func TestX86InitializedNumericNativeAddressValues(t *testing.T) {
	execution := x86NumericAddressRuntimeTools(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	source, declarations := x86NumericAddressProgram(arch)
	driver := x86NumericAddressPrototypes + `
#include <string.h>
int main(void) {
    for (unsigned seed = 0; seed < 257; ++seed) {
        for (unsigned offset = 0; offset < 4; ++offset) {
            uint8_t data[16], before[16];
            for (unsigned i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)(seed + i * 17);
            memcpy(before, data, sizeof(data));
            uintptr_t address = (uintptr_t)(data + offset);
            uint32_t expected;
            memcpy(&expected, data + offset, sizeof(expected));
            if (NumericLoad(address) != expected || IndirectLoad(&address) != expected) return 1;
            if (memcmp(data, before, sizeof(data))) return 2;
            if (NumericStore(address) != 42) return 3;
            memcpy(before + offset, &(uint32_t){42}, sizeof(uint32_t));
            if (memcmp(data, before, sizeof(data))) return 4;
            memset(data + offset, 0xa5, sizeof(uint32_t));
            if (IndirectStore(&address) != 42 || memcmp(data, before, sizeof(data))) return 5;
        }
    }
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				input := ir
				if level == "-O2" {
					input = x86DwordProductIROptimize(t, input)
				}
				executable := execution.compileLLVM(t, "numeric-address-values", input, driver, level)
				execution.run(t, executable)
			}
		})
	}
}

func TestX86InitializedNumericNativeAddressFaults(t *testing.T) {
	execution := x86NumericAddressRuntimeTools(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	source, declarations := x86NumericAddressProgram(arch)
	callbacks := x86NumericAddressPrototypes + `
static int load(const uint8_t *p) {
    volatile uint32_t value = NumericLoad((uintptr_t)p);
    (void)value;
    return 0;
}
static int indirect_load(const uint8_t *p) {
    uintptr_t address = (uintptr_t)p;
    volatile uint32_t value = IndirectLoad(&address);
    (void)value;
    return 0;
}
static int store(const uint8_t *p) {
    return NumericStore((uintptr_t)p) == 42 ? 0 : 91;
}
static int indirect_store(const uint8_t *p) {
    uintptr_t address = (uintptr_t)p;
    return IndirectStore(&address) == 42 ? 0 : 91;
}
`
	driver := x86MemoryFaultDriver(callbacks, "{load,4,3},{indirect_load,4,3},{store,4,3},{indirect_store,4,3},")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				input := ir
				if level == "-O2" {
					input = x86DwordProductIROptimize(t, input)
				}
				executable := execution.compileLLVM(t, "numeric-address-faults", input, driver, level)
				x86CheckMemoryFaultMatrix(t, execution, executable, 4)
			}
		})
	}
	t.Logf("portable memory execution on %s/%s; no original x86 execution claim", runtime.GOOS, runtime.GOARCH)
}
