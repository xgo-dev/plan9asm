package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func amd64RegisterResultMatrix(t *testing.T) (source, declarations, checks string) {
	t.Helper()
	var asm, decl, calls strings.Builder
	count := 0
	for _, family := range []struct {
		suffix string
		width  int
	}{{"B", 1}, {"W", 2}, {"D", 4}, {"Q", 8}} {
		for _, prefix := range []string{"", "V"} {
			for lane := 0; lane < 16/family.width; lane++ {
				name := fmt.Sprint("lane", count)
				asm.WriteString(strings.ReplaceAll(amd64RegisterLaneFixture(prefix+"PINSR"+family.suffix, lane), "·view", "·"+name))
				fmt.Fprintf(&decl, "func %s(value,seed uint64) uint64\n", name)
				fmt.Fprintf(&calls, "if(check(%s,%d,%d)){fprintf(stderr,\"%s failed\\n\");return 1;}\n", name, family.width, lane, name)
				count++
			}
		}
	}
	if count != 60 {
		t.Fatal("incomplete register-entry scalar insertion matrix", count)
	}
	return asm.String(), decl.String(), calls.String()
}

func requireAMD64RegisterResultGoObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "source.s"), filepath.Join(dir, "source.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	// The shared flag probe handles Go 1.20's explicit -compiling-runtime.
	args := append(arm64ClosureGoAsmArgs(t), "-o", object, input)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, "amd64"); failure != nil {
		t.Fatalf("original Go register-entry object: %v\n%s", failure, output)
	}
}

func TestAMD64RegisterResultThreeTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	source, declarations, _ := amd64RegisterResultMatrix(t)
	requireAMD64RegisterResultGoObject(t, source)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, optimized := range []bool{false, true} {
					text := ir
					if optimized {
						text = x86MulDivRoundOptimize(t, text)
					}
					x86ResultInitializationObject(t, llc, triple, text, "register-result")
				}
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixAMD64RegisterResultScalarLanes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	source, declarations, checks := amd64RegisterResultMatrix(t)
	var header strings.Builder
	header.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	for index := 0; index < 60; index++ {
		fmt.Fprintf(&header, "extern uint64_t lane%d(uint64_t,uint64_t);\n", index)
	}
	const reference = `
static int check(uint64_t (*fn)(uint64_t,uint64_t), unsigned width, unsigned lane) {
  const uint64_t values[] = {0, UINT64_MAX, UINT64_C(0x8070605040302010),
                            UINT64_C(0xfedcba9876543210)};
  for (unsigned a = 0; a < 4; a++) {
    for (unsigned b = 0; b < 4; b++) {
      uint8_t bytes[16] = {0};
      uint64_t low, high;
      memcpy(bytes, &values[b], 8);
      memcpy(bytes + width * lane, &values[a], width);
      memcpy(&low, bytes, 8);
      memcpy(&high, bytes + 8, 8);
      uint64_t got = fn(values[a], values[b]);
      if (got != (low ^ high)) {
        fprintf(stderr, "width=%u lane=%u a=%u b=%u got=%llx want=%llx\n",
                width, lane, a, b, (unsigned long long)got, (unsigned long long)(low ^ high));
        return 1;
      }
    }
  }
  return 0;
}
`
	main := header.String() + reference + "int main(void){\n" + checks + "return 0;}\n"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86MulDivRoundOptimize(t, text)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "register-results", triple, text, main, prefix)
			}
		})
	}
	t.Log("60 register-entry forms × 16 independent byte inputs × 3 APIs × O0/O2; portable lowering, not a physical Go call bridge")
}
