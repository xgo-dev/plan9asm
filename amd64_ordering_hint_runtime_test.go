package plan9asm

import (
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86OrderingHintsOriginalWindowsExecutable(t *testing.T) {
	declarations, assembly, driver, _ := x86OrderingHintRuntimeFixture(64)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "windows", "amd64", declarations, assembly, driver)
	if filepath.Ext(original) != ".exe" {
		t.Fatal("Windows original oracle requires its exact executable suffix", original)
	}
	object, err := pe.Open(original)
	if err != nil {
		t.Fatal("actual Windows oracle executable", err)
	}
	defer object.Close()
	if object.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || object.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
		t.Fatal("original Windows oracle is not an AMD64 executable")
	}
}

// These observations establish exact GP, six status bits and MXCSR retention,
// not an empirical proof of the architecture's concurrent memory model.
func TestCrossLinuxRuntimeMatrixX86OrderingHintsOriginalAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declarations, assembly, driver, reference := x86OrderingHintRuntimeFixture(64)
	dir := t.TempDir()
	original := x86OrderingHintBuildOriginal(t, dir, runtime.GOOS, "amd64", declarations, assembly, driver)
	if output := execution.run(t, original); string(output) != "original ordering observations 256\n" {
		t.Fatalf("actual original Go ordering/status/canary oracle: %q", output)
	}
	t.Log("256 original Go observations: four instructions, two complementary six-bit seeds, 32 repetitions")
	ir := x86NarrowOracleIR(t, assembly, declarations, execution.triple)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "ordering", ir, reference, level)
			if string(output) != "ordering observations 256\n" {
				t.Fatalf("independent GP/full-status/MXCSR/canary oracle: %q", output)
			}
			t.Log("256 independent LLVM observations: five GPs, six status flags, MXCSR and canary")
		})
	}
}

func x86OrderingHintBuildOriginal(t *testing.T, dir, goos, arch, declarations, assembly, driver string) string {
	t.Helper()
	for name, contents := range map[string]string{
		"go.mod":  "module ordering\n\ngo 1.20\n",
		"decl.go": declarations, "ordering_" + arch + ".s": assembly,
		"main.go": driver,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	if goos == "windows" {
		executable += ".exe"
	}
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch,
		"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	return executable
}

func TestX86OrderingHintsOriginal386StaticELFCompileOnly(t *testing.T) {
	declarations, assembly, driver, _ := x86OrderingHintRuntimeFixture(32)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386", declarations, assembly, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual original Go IA32 ELF bytes=%d SHA256=%x; compile only, required native execution is separate",
		sealed.size, sealed.hash)
}

// The independent reference constants never come from the production spec.
// Each sample resets every output byte and both complementary status seeds.
func x86OrderingHintRuntimeFixture(bits int) (declarations, assembly, driver, reference string) {
	word, suffix, pop, push := "uint64", "Q", "POPFQ", "PUSHFQ"
	values := []string{"0x123456789abcdef0", "0x2468ace013579bdf", "0x3141592653589793", "0x7e6d5c4b3a291807", "0xa1b2c3d4e5f60718"}
	canary := "0x13579bdf2468ace0"
	if bits == 32 {
		word, suffix, pop, push = "uint32", "L", "POPFL", "PUSHFL"
		values = []string{"0x9abcdef0", "0x13579bdf", "0x53589793", "0x3a291807", "0xe5f60718"}
		canary = "0x2468ace0"
	}
	var decl, asm, names strings.Builder
	decl.WriteString("package main\n")
	step := bits / 8
	for _, op := range []string{"LFENCE", "MFENCE", "SFENCE", "PAUSE"} {
		for index, seed := range []uint64{0x8c7, 0x12} {
			name := fmt.Sprintf("%s_%d", strings.ToLower(op), index)
			fmt.Fprintf(&decl, "func %s(out *[8]%s)\n", name, word)
			fmt.Fprintf(&names, "%s,\n", name)
			fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\n", name, step, suffix)
			for r, reg := range []string{"AX", "BX", "CX", "DX", "SI"} {
				fmt.Fprintf(&asm, "MOV%s $%s,%s\n", suffix, values[r], reg)
			}
			fmt.Fprintf(&asm, "PUSH%s $%d\n%s\n%s\n", suffix, seed, pop, op)
			for r, reg := range []string{"AX", "BX", "CX", "DX", "SI"} {
				fmt.Fprintf(&asm, "MOV%s %s,%d(DI)\n", suffix, reg, r*step)
			}
			fmt.Fprintf(&asm, "%s\nPOP%s SI\nMOV%s SI,%d(DI)\nSTMXCSR %d(DI)\nRET\n", push, suffix, suffix, 5*step, 6*step)
		}
	}
	decl.WriteString("func csr() uint32\n")
	asm.WriteString("TEXT ·csr(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\n")
	driver = fmt.Sprintf(`package main

import (
    "fmt"
    "runtime"
)

func main() {
    runtime.LockOSThread()
    samples := []func(*[8]%s){
        %s
    }
    want := [5]%s{%s}
    seeds := [2]%s{0x8c7, 0x12}
    observations := 0
    for index, sample := range samples {
        for iteration := 0; iteration < 32; iteration++ {
            out := [8]%s{0, 0, 0, 0, 0, 0, 0, %s}
            before := csr()
            sample(&out)
            after := csr()
            for register := 0; register < 5; register++ {
                if out[register] != want[register] {
                    panic(fmt.Sprintf("original GP kernel=%%d register=%%d out=%%x", index, register, out))
                }
            }
            if out[5]&0x8d5 != seeds[index%%2]&0x8d5 ||
                    out[6] != %s(before) || after != before || out[7] != %s {
                panic(fmt.Sprintf("original status/CSR/canary kernel=%%d out=%%x before=%%x after=%%x", index, out, before, after))
            }
            observations++
        }
    }
    fmt.Printf("original ordering observations %%d\n", observations)
}
`, word, names.String(), word, strings.Join(values, ", "), word, word, canary, word, canary)
	var prototypes strings.Builder
	for _, op := range []string{"lfence", "mfence", "sfence", "pause"} {
		for index := 0; index < 2; index++ {
			fmt.Fprintf(&prototypes, "extern void %s_%d(%s_t *);\n", op, index, word)
		}
	}
	reference = fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>

%s
int main(void) {
    void (*samples[])(%s_t *) = {
        %s
    };
    const %s_t want[5] = {%s};
    const %s_t seeds[2] = {0x8c7, 0x12};
    unsigned observations = 0;
    for (unsigned index = 0; index < 8; index++) {
        for (unsigned iteration = 0; iteration < 32; iteration++) {
            %s_t out[8] = {0, 0, 0, 0, 0, 0, 0, %s};
            unsigned before, after;
            __asm__ volatile("stmxcsr %%0" : "=m"(before));
            samples[index](out);
            __asm__ volatile("stmxcsr %%0" : "=m"(after));
            for (unsigned reg = 0; reg < 5; reg++) {
                if (out[reg] != want[reg]) {
                    fprintf(stderr, "GP kernel=%%u register=%%u got=%%llx\n",
                        index, reg, (unsigned long long)out[reg]);
                    return 1;
                }
            }
            if ((out[5] & 0x8d5) != (seeds[index %% 2] & 0x8d5) ||
                    out[6] != before || after != before || out[7] != %s) {
                fprintf(stderr, "status/CSR/canary kernel=%%u flags=%%llx CSR=%%llx/%%x/%%x\n",
                    index, (unsigned long long)out[5], (unsigned long long)out[6], before, after);
                return 2;
            }
            observations++;
        }
    }
    printf("ordering observations %%u\n", observations);
    return 0;
}
`, prototypes.String(), word, names.String(), word, strings.Join(values, ", "), word, word, canary, canary)
	return decl.String(), asm.String(), driver, reference
}
