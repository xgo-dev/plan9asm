//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Called from the existing dead-read fault root, retaining its cross-runtime
// owner. Original Go checks valid unaligned accesses; the shared independent
// byte reference checks NULL and short-page faults in owned child processes.
func fixedLocalNativeNumericAddressRuntime(t *testing.T) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	triple := testTargetTriple(runtime.GOOS, "amd64")
	assembly, declarations := fixedLocalNativeNumericRuntimeSources(t)
	var goCalls, prototypes, rows, validCalls strings.Builder
	prefix := ""
	if strings.Contains(execution.triple, "apple") {
		prefix = "_"
	}
	for ordinal := 0; ordinal < 8; ordinal++ {
		width := 1 << uint(ordinal%4)
		fmt.Fprintf(&goCalls, `
    for i := range buffer { buffer[i] = 0x91 }
    if Value%d(&address,&output,0) != 23063 { t.Fatal("original value %d") }
`, ordinal, ordinal)
		if ordinal >= 4 {
			fmt.Fprintf(&goCalls, `
    for i, value := range buffer {
        want := byte(0x91)
        if i >= 1 && i < 1+%d { want = 0 }
        if i == 1 { want = 17 }
        if value != want { t.Fatal("original exact store", %d, i, value, want) }
    }
`, width, ordinal)
		}
		fmt.Fprintf(&prototypes, "extern uint64_t value%d(const uint64_t *,uint64_t *,uint64_t) __asm__(%q);\n",
			ordinal, prefix+"example.invalid/framefixture.Value"+fmt.Sprint(ordinal))
		// The first pointer is always a valid local word. Only the loaded
		// initialized NUM word contains the faulting effective address.
		fmt.Fprintf(&prototypes, `
static int run%d(const uint8_t *p) {
    uint64_t address = (uint64_t)(uintptr_t)p, output = 0;
    return value%d(&address, &output, 0) != 23063;
}
`, ordinal, ordinal)
		fmt.Fprintf(&rows, "{run%d,%d,%d},\n", ordinal, width, width-1)
		fmt.Fprintf(&validCalls, "memset(buffer,0x91,sizeof buffer);\nif(value%d(&address,&output,0)!=23063)return %d;\n", ordinal, 10+ordinal)
		if ordinal >= 4 {
			fmt.Fprintf(&validCalls, `
for(unsigned i=0;i<sizeof buffer;i++) {
    unsigned want=0x91;
    if(i>=1 && i<1+%d) want=0;
    if(i==1) want=17;
    if(buffer[i]!=want) return %d;
}
`, width, 30+ordinal)
		} else {
			validCalls.WriteString("for(unsigned i=0;i<sizeof buffer;i++)if(buffer[i]!=0x91)return 50;\n")
		}
	}
	original := `package framefixture
import (
    "runtime"
    "testing"
    "unsafe"
)
var originalNumericBuffer *[17]byte
func TestOriginal(t *testing.T) {
    buffer := [17]byte{}
    originalNumericBuffer = &buffer
    address := uint64(uintptr(unsafe.Pointer(&buffer[1])))
    output := uint64(0)
` + goCalls.String() + `
    runtime.KeepAlive(&buffer)
}
`
	fixedLocalPackedRunOriginal(t, execution, assembly, declarations, original, true)
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", triple)
	fixedLocalConversionPrepareToolCache(t, request)
	driver := x86MemoryFaultDriver(prototypes.String(), rows.String())
	// This independent valid-input executable owns all post-call byte checks.
	// A fault probe never reads its invalid pointer after the translated call.
	validDriver := "#include <stdint.h>\n#include <string.h>\n" + prototypes.String() + `
int main(void) {
    uint8_t buffer[17];
    uint64_t address=(uint64_t)(uintptr_t)&buffer[1],output=0;
` + validCalls.String() + "return 0;\n}\n"
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, pipeline := range []struct{ name, level, source string }{
			{"backend_O0", "-O0", ir},
			{"IR_O2_backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
		} {
			t.Run(pipeline.name, func(t *testing.T) {
				compileLLVMToObject(t, execution.llc, triple, "native-numeric-fault.ll", "native-numeric-fault.o", pipeline.source)
				execution.compileAndRunLLVM(t, "native-numeric-valid", pipeline.source, validDriver, pipeline.level)
				executable := execution.compileLLVM(t, "native-numeric-fault", pipeline.source, driver, pipeline.level)
				x86CheckMemoryFaultMatrix(t, execution, executable, 8)
			})
		}
	})
}
