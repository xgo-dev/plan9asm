package plan9asm

import (
	"os"
	"strings"
	"testing"
)

// Actual Linux AMD64/IA32 execution of private LLVM register mathematics only.
// In particular, this is not execution of an original Go LEAVE/RET stack ABI.
func TestCrossLinuxRuntimeMatrixX86LeavePrivateEmitterWidthsAndFlags(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("required private LEAVE IA32/AMD64 execution needs LLVM22")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			execution, word := x86FloatCompareExecutionTools(t), 8
			if arch == "386" {
				execution = x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
					compiler: []string{"i686-linux-gnu-gcc", "-static", "-no-pie"}}
				word = 4
			}
			if len(execution.prefix) != 0 || execution.preserveArgv0 {
				t.Fatal("private LEAVE native-width counterpart forbids guest/emulator execution")
			}
			source, signatures := x86LeavePrivateWidthProgram(arch)
			x86LEAActualTargetGoObject(t, arch, execution.triple, source)
			ir := x86PhysicalSPPrivateEmitter(t, source, signatures, arch, execution.triple)
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
				{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					executable := execution.compileLLVM(t, "private-leave-native-width", pipeline.ir, x86LeavePrivateWidthC(word), pipeline.level)
					var output []byte
					if arch == "386" {
						output = x87IA32RunDirect(t, x86NativeOracleIA32Executable(t, execution, executable), nil, os.Environ())
					} else {
						output = execution.run(t, executable)
					}
					const marker = "PRIVATE_LEAVE_128_WIDTH_VALUES_FLAGS_CANARIES_PASS\n"
					if string(output) != marker {
						t.Fatal("private LEAVE width/value/FLAGS/canary observation was incomplete", strings.TrimSpace(string(output)))
					}
					t.Logf("private LEAVE numerical completion arch=%s: %s", arch, output)
				})
			}
		})
	}
	x87IA32RequireNativeHost(t)
}
