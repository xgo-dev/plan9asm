package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Execute the complete actual Go encoder bytes through an explicitly bound
// ABI0 stack adapter, not a claimed Go entry or a translator memory permission.
// The unchanged body's PUSHF observes real DF=1 and all six status bits. The
// adapter also captures real return DF before clearing it defensively; either
// a missing CLD or a changed stack canary traps instead of corrupting the C ABI.
func x86NativeLEAWOriginalABI0Adapter(t *testing.T, variant string) string {
	t.Helper()
	source, _ := x86NativeLEAWRetainedPointerSource("amd64", variant, "")
	var bytes []string
	for _, value := range amd64RegisterBoolOriginalBytes(t, source) {
		bytes = append(bytes, fmt.Sprintf("0x%02x", value))
	}
	name := "Retain" + variant
	body := "OriginalLEAW" + variant
	assembly := ".text\n" + body + ":\n.byte " + strings.Join(bytes, ",") + "\n.globl " + name + "\n" + name + ":\n" +
		"pushq %rbx\nsubq $32,%rsp\n" +
		"movq %rdi,0(%rsp)\nmovq %rsi,8(%rsp)\nmovq %rdx,16(%rsp)\nmovl %ecx,24(%rsp)\n" +
		"movl $0x5a5a5a5a,28(%rsp)\ncallq " + body + "\n" +
		"pushfq\npopq %rax\ncld\ntestq $1024,%rax\njnz .Lbad" + variant + "\n" +
		"cmpl $0x5a5a5a5a,28(%rsp)\njne .Lbad" + variant + "\n" +
		"addq $32,%rsp\npopq %rbx\nretq\n.Lbad" + variant + ":\nud2\n"
	return fmt.Sprintf("__asm__(%q);\n", assembly)
}

func TestCrossLinuxRuntimeMatrixX86LEAWRetainedPointerOriginalBytesAndNativeDF(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	if len(execution.prefix) != 0 || execution.triple != "x86_64-unknown-linux-gnu" {
		t.Fatal("retained-pointer native DF needs direct Linux AMD64 execution", execution)
	}
	source, declarations := x86NativeLEAWRetainedPointerBatch("amd64", "")
	x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
	// The numerical model, complete 300 input vectors, FLAGS/DF=1 and byte
	// canaries remain unchanged. Add only a hardware DF=0 return observation.
	call := "programs[op](packet+16,(const uint8_t*)bases[b],(const uint8_t*)oldValues[old],indexes[index]);"
	if strings.Count(x86NativeLEAWRetainedPointerC, call) != 1 {
		t.Fatal("native DF observer lost the unique original call boundary")
	}
	driver := strings.Replace(x86NativeLEAWRetainedPointerC, call, call+`
        uintptr_t returnFlags;
        __asm__ volatile("pushfq; popq %0; cld" : "=r"(returnFlags) :: "cc", "memory");
        if (returnFlags&UINT32_C(0x400)) return 4;`, 1)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("unchanged native source rejected before real DF execution", err)
			}
			ir = x86NativeLEAWRetainedPointerLogicalDF(t, ir, false)
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
				{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "retained-leaw-native", pipeline.ir, driver, pipeline.level)
					if string(output) != "LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS\n" {
						t.Fatal("native LEAW/FLAGS/DF/canary observation incomplete", string(output))
					}
					t.Logf("native retained LEAW LLVM execution: %s", output)
				})
			}
		})
	}
	t.Run("OriginalGoBytes", func(t *testing.T) {
		var adapters strings.Builder
		for _, variant := range []string{"Direct", "Copied", "Alias"} {
			adapters.WriteString(x86NativeLEAWOriginalABI0Adapter(t, variant))
		}
		// No translated instruction bodies participate in this independent
		// reference: all three original Go functions execute as actual bytes.
		ir := "target triple = \"x86_64-unknown-linux-gnu\"\n"
		output := execution.compileAndRunLLVM(t, "retained-leaw-original", ir, adapters.String()+driver, "-O2")
		if string(output) != "LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS\n" {
			t.Fatal("actual Go bytes did not establish real DF=1/status/canaries and DF=0 return", string(output))
		}
		t.Logf("native retained LEAW actual Go bytes execution: %s", output)
	})
	t.Log("300 inputs: actual Go bytes/explicit ABI0 stack adapter observe hardware DF=1 inside and DF=0 at return; original native LLVM bodies retain STD/CLD and check packed logical DF/status plus hardware DF=0 return, with all byte canaries")
	x87IA32RequireNativeHost(t)
}
