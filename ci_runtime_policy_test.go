package plan9asm

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCIFullSuitesHaveExplicitTimeout(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for line, command := range strings.Split(string(data), "\n") {
		if !strings.Contains(command, "go test ") || !strings.Contains(command, "./...") {
			continue
		}
		var timeout time.Duration
		for _, field := range strings.Fields(command) {
			if strings.HasPrefix(field, "-timeout=") {
				timeout, err = time.ParseDuration(strings.TrimPrefix(field, "-timeout="))
				if err != nil {
					t.Errorf("line %d: invalid timeout: %v", line+1, err)
				}
			}
		}
		if timeout < 20*time.Minute {
			t.Errorf("line %d: full suite requires an explicit timeout of at least 20m: %s", line+1, strings.TrimSpace(command))
		}
	}
	driver, err := os.ReadFile("scripts/test-linux-cli-module-ci.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"go run ./cmd/plan9asmtest -module", "-dir=cmd/$module",
		"-shards=8 -workers=2 -timeout=30m -module-root-partitions=4", "-verify-module="} {
		if !strings.Contains(string(driver), required) {
			t.Errorf("complete CLI protocol lost its original command budget/inventory: %s", required)
		}
	}
}

// Follow the actual reusable workflow, checking each execution/reader job on
// its own. A caller's setup cannot stand in for a missing callee dependency.
func ciFullSuiteJob(t *testing.T, source, name string) (string, bool) {
	t.Helper()
	if strings.HasPrefix(name, "linux-cli-") {
		data, err := os.ReadFile(".github/workflows/linux-cli-module.yml")
		if err != nil {
			t.Fatal(err)
		}
		return ciWorkflowJob(string(data), strings.TrimPrefix(name, "linux-cli-"))
	}
	return ciWorkflowJob(source, name)
}

func TestCIShellScriptsUseLFOnEveryHost(t *testing.T) {
	attributes, err := os.ReadFile(".gitattributes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(attributes), "*.sh text eol=lf") {
		t.Fatal("executed and inspected shell scripts require LF checkout on Windows too")
	}
}

func TestCIFullSuitesInstallWASMExecutionRuntime(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cross-runtime", "cross-runtime-verify", "test", "linux-cli-root-parts", "linux-cli-complete", "race", "coverage", "module-completion"} {
		job, found := ciFullSuiteJob(t, string(data), name)
		if !found {
			t.Fatalf("full-suite job %s is missing", name)
		}
		if !strings.Contains(job, "uses: ./.github/actions/setup-node22") || !strings.Contains(job, "timeout-minutes: 10") {
			t.Errorf("%s must install the required wasm execution runtime, not depend on a runner's incidental PATH", name)
		}
	}
}

func TestCIFullSuitesInstallIA32ExecutionToolchain(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test", "linux-cli-root-parts", "linux-cli-complete", "race", "coverage"} {
		t.Run(name, func(t *testing.T) {
			job, found := ciFullSuiteJob(t, string(data), name)
			if !found {
				t.Fatalf("full-suite job %s is missing", name)
			}
			// These suites include native Linux/386 tests even when the
			// optional cross-execution matrix is not enabled.
			install := "bash scripts/install-ci-llvm22-ubuntu.sh gcc-i686-linux-gnu libc6-dev-i386-cross"
			installer := strings.Index(job, install)
			runner := strings.Index(job, "bash scripts/test-module-ci.sh")
			if strings.HasPrefix(name, "linux-cli-") {
				runner = strings.Index(job, "bash scripts/test-linux-cli-module-ci.sh")
			}
			if installer < 0 || runner < 0 || installer >= runner {
				t.Fatal("required IA32 compiler and libc must be installed before the complete module suite")
			}
		})
	}
}

func TestCICrossRuntimeUsesPinnedQEMU(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	cross, found := ciWorkflowJob(string(data), "cross-runtime")
	if !found {
		t.Fatal("cross-runtime job not found")
	}
	if !strings.Contains(cross, "bash scripts/install-ci-qemu.sh") || strings.Contains(cross, "qemu-user") {
		t.Fatal("cross-runtime must install checksum-pinned QEMU, not Ubuntu 24.04's broken 8.2 dot-product implementation")
	}
	script, err := os.ReadFile("scripts/install-ci-qemu.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"version=10.2.3",
		"release=deploy/v10.2.3-68",
		"checksum=8e7d8f4c0c7809fc3fea0085199fd6b16f671e7c73d9bf6bec711e1cb535920a",
		"sha256sum --check --status",
		"tools=(qemu-aarch64 qemu-arm qemu-i386)",
		"GITHUB_PATH",
	} {
		if !strings.Contains(string(script), required) {
			t.Errorf("QEMU installer missing %q", required)
		}
	}
}

func TestCIFullSuitesInstallRequiredQEMU(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test", "linux-cli-root-parts", "linux-cli-complete", "race", "coverage", "module-completion"} {
		t.Run(name, func(t *testing.T) {
			job, found := ciFullSuiteJob(t, string(data), name)
			if !found {
				t.Fatal("missing complete suite", name)
			}
			install := strings.Index(job, "bash scripts/install-ci-qemu.sh")
			runner := strings.Index(job, "bash scripts/test-module-ci.sh")
			if strings.HasPrefix(name, "linux-cli-") {
				runner = strings.Index(job, "bash scripts/test-linux-cli-module-ci.sh")
			}
			if install < 0 || runner < 0 || install >= runner {
				t.Fatal("complete Linux suites require pinned QEMU before their 386 runtime tests")
			}
			stepStart := strings.LastIndex(job[:install], "\n      - ")
			if stepStart < 0 {
				t.Fatal("QEMU installer has no actual workflow step")
			}
			step := job[stepStart:install]
			// Scope comparison binds the actual process PATH. Every owner and
			// its aggregate must install the same runtimes in the same order.
			condition := ""
			if name == "test" {
				condition = "if: runner.os == 'Linux'\n"
			}
			if !strings.Contains(step, condition) || strings.Contains(step, "matrix.") ||
				condition == "" && strings.Contains(step, "if:") {
				t.Fatal("all module owners and the aggregate need identical QEMU provisioning")
			}
			if node := strings.Index(job, "uses: ./.github/actions/setup-node22"); node < 0 || install >= node {
				t.Fatal("all module roles must install QEMU before Node to retain identical PATH order")
			}
		})
	}
}

func ciWorkflowJob(source, name string) (string, bool) {
	source = strings.ReplaceAll(source, "\r\n", "\n")
	_, job, found := strings.Cut(source, "\n  "+name+":\n")
	if !found {
		return "", false
	}
	lines := strings.Split(job, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '#' {
			return strings.Join(lines[:index], "\n"), true
		}
	}
	return job, true
}

func TestCIWorkflowJobLineEndings(t *testing.T) {
	const source = "jobs:\n  first:\n    run: first\n\n  second:\n    run: second\n"
	for _, ending := range []string{"\n", "\r\n"} {
		text := strings.ReplaceAll(source, "\n", ending)
		job, found := ciWorkflowJob(text, "first")
		if !found || !strings.Contains(job, "run: first") || strings.Contains(job, "second") {
			t.Fatalf("line ending %q: job=%q found=%v", ending, job, found)
		}
		if _, found := ciWorkflowJob(text, "absent"); found {
			t.Fatal("missing job accepted")
		}
	}
}
