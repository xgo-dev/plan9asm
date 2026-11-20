//go:build go1.27 && (amd64 || arm64)

package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64LinuxSyscallGPNZCV(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	if triple != "aarch64-unknown-linux-gnu" {
		t.Fatal("kernel oracle requires actual Linux ARM64 execution")
	}
	directory, packagePath, declarations, assembly := arm64LinuxSyscallEffectFixture(t)
	arm64LinuxSyscallEffectOriginalObjects(t, directory, packagePath)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	arguments := []string{"test", "-p=1", "-mod=readonly", "-run=^TestOriginalLinuxSyscallEffects$", "-count=1", "-v"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "-exec="+quoted)
	}
	ctx, release := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, request.GoBinary, append(arguments, ".")...)
	command.Dir, command.Env = directory, request.Environment
	output, err := runtimeOracleCombinedOutput(ctx, command)
	release()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestOriginalLinuxSyscallEffects") {
		t.Fatalf("ORIGINAL_KERNEL_PRECONDITION: %v\n%s", err, output)
	}
	for _, test := range arm64LinuxSyscallEffectCases() {
		if !arm64LinuxSyscallEffectHasOriginalMarker(string(output), test.name) {
			t.Fatalf("ORIGINAL_KERNEL_PRECONDITION: complete GP/NZCV axis absent: %s\n%s", test.name, output)
		}
	}
	t.Logf("ORIGINAL_KERNEL_OUTPUT_BEGIN\n%sORIGINAL_KERNEL_OUTPUT_END", output)
	// Original processes have different PIDs. Each checks its own true PID;
	// only numerical canaries and independently calculated flags are compared.
	pkg := mustGoPackage(t, packagePath, declarations)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := arm64LinuxSyscallEffectTranslate(t, api, pkg, assembly)
			if err != nil {
				t.Fatalf("SYSCALL_EFFECT_CONSUMER_RED after actual original kernel P: %v", err)
			}
			for _, optimization := range []int{0, 2} {
				t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
					for _, test := range arm64LinuxSyscallEffectCases() {
						t.Run(test.name, func(t *testing.T) {
							shim, driver := arm64LinuxSyscallEffectRuntimeChecks(packagePath, test)
							compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "kernel_effects", triple,
								ir+shim, driver, runner, optimization)
							// Compilation/linking alone never establishes this marker.
							t.Logf("LLVM_KERNEL_AXIS_PASS %s %s O%d", test.name, api, optimization)
						})
					}
				})
			}
		})
	}
}
