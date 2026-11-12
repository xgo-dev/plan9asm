package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ConformanceMRSFeatureRegisters(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if !(runtime.GOOS == "linux" && runtime.GOARCH == "arm64") && !cross {
		t.Skip("EL1 feature access requires Linux/arm64; required Linux cross-runtime CI executes this oracle")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compiler := []string{findLLVM22Tool("clang")}
	var runner []string
	if cross {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	var main strings.Builder
	main.WriteString(`#define _GNU_SOURCE
#include <asm/hwcap.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
`)
	for index, register := range arm64FeatureRegisters {
		physical := arm64EncodedSystemRegisterName(uint16((register.word >> 5) & 0x7fff))
		fmt.Fprintf(&main, `extern uint64_t read_feature_%[1]d(void);
static uint64_t native_feature_%[1]d(void) {
  uint64_t value;
  __asm__ volatile("mrs %%0, %[2]s" : "=r"(value) :: "memory");
  return value;
}
`, index, physical)
	}
	main.WriteString(`int main(void) {
  if (!(getauxval(AT_HWCAP) & HWCAP_CPUID)) {
    fputs("required kernel CPUID register access unavailable\n", stderr);
    return 1;
  }
  cpu_set_t allowed, selected;
  if (sched_getaffinity(0, sizeof(allowed), &allowed)) return 2;
  CPU_ZERO(&selected);
  for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
    if (CPU_ISSET(cpu, &allowed)) { CPU_SET(cpu, &selected); break; }
  }
  if (sched_setaffinity(0, sizeof(selected), &selected)) return 3;
  if (((native_feature_0() >> 16) & 15) != 15) return 4;
  for (int iteration = 0; iteration < 16; iteration++) {
`)
	for index, register := range arm64FeatureRegisters {
		fmt.Fprintf(&main, `    if (read_feature_%[1]d() != native_feature_%[1]d()) {
      fputs("translated %[2]s differs from native MRS\n", stderr);
      return %[3]d;
    }
`, index, register.name, index+10)
	}
	main.WriteString("  }\n  return 0;\n}\n")
	for _, raw := range []bool{false, true} {
		for _, cfg := range []bool{false, true} {
			file, sigs := arm64MRSFeatureFixture(t, raw, cfg)
			for _, directModule := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw=%v/cfg=%v/module=%v", raw, cfg, directModule), func(t *testing.T) {
					options := Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: sigs}
					var ir string
					if directModule {
						ir = translateARM64MRSModule(t, file, options)
					} else {
						var err error
						ir, err = Translate(file, options)
						if err != nil {
							t.Fatal(err)
						}
					}
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "mrs_feature", options.TargetTriple, ir, main.String(), runner)
				})
			}
		}
	}
}
