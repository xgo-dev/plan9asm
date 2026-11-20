package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const x86LoweredVectorEntryOriginalTests = `package oracle
import "testing"
func TestOriginalLoweredVectorEntry(t *testing.T) {
    calls := 0
    for n := uint64(1); n <= 2; n++ {
        for first := 0; first < 256; first++ {
            for _, second := range []byte{0, 127, 128, 255} {
                input := [2]byte{byte(first), second}
                before := input
                invalid := -1
                for i := 0; i < int(n); i++ {
                    if input[i] >= 128 { invalid = i; break }
                }
                at, ok := MaskTail(&input[0], n)
                if ok != (invalid < 0) || invalid >= 0 && at != uint64(invalid) {
                    t.Fatalf("mask n=%d input=%x at=%d ok=%t invalid=%d", n, input, at, ok, invalid)
                }
                output := [8]byte{204, 204, 204, 204, 204, 204, 204, 204}
                want := output
                want[1] = input[0]
                if n == 2 { want[2], want[3], want[4] = input[1], input[0], input[1] }
                RepeatTail(&output[1], &input[0], n)
                if input != before || output != want {
                    t.Fatalf("repeat n=%d input=%x output=%x want=%x", n, input, output, want)
                }
                calls++
            }
        }
    }
    if calls != 2048 { t.Fatal("incomplete caller denominator", calls) }
    t.Logf("actual original Go tail caller pairs=%d; values, invalid-byte indices and canaries pass", calls)
}
`

// The declared caller observes at only on failure. No observation depends on
// an unspecified vector entry byte or the unwritten numerical success result.
func TestCrossLinuxRuntimeMatrixX86LoweredVectorEntryOriginalGo(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	formatted, err := format.Source([]byte(x86LoweredVectorEntryOriginalTests))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":        "module oracle\n\ngo 1.20\n",
		"value.go":      "package oracle\n" + x86LoweredVectorMaskDeclaration + x86LoweredVectorRepeatDeclaration,
		"value_amd64.s": x86LoweredVectorMaskSource + x86LoweredVectorRepeatSource,
		"value_test.go": string(formatted),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original.test")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "test", "-c", "-p=1", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=",
		"CGO_ENABLED=0", "GOARCH=amd64", "GOOS="+runtime.GOOS)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual original Go build/asmdecl: %v\n%s", err, output)
	}
	if linked, err := x86OriginalGoLinkedAMD64(binary); err != nil || !linked {
		t.Fatal("original caller must be a current-SDK linked AMD64 executable", linked, err)
	}
	output = execution.run(t, binary, "-test.run=^TestOriginalLoweredVectorEntry$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginalLoweredVectorEntry") ||
		!strings.Contains(string(output), "tail caller pairs=2048") {
		t.Fatal("missing complete original Go caller results", string(output))
	}
	t.Log(strings.TrimSpace(string(output)))
}

// Keep the mixed tuple inside LLVM and expose only the caller's written
// component, rather than guessing an external C aggregate ABI.
const x86LoweredVectorEntryCallerIR = `
define i64 @ObserveMask(ptr %src, i64 %n) {
entry:
  %pair = call { i64, i1 } @MaskTail(ptr %src, i64 %n)
  %ok = extractvalue { i64, i1 } %pair, 1
  br i1 %ok, label %success, label %failure
success:
  ret i64 -1
failure:
  %at = extractvalue { i64, i1 } %pair, 0
  ret i64 %at
}
`

const x86LoweredVectorEntryCallerC = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint64_t ObserveMask(const uint8_t *, uint64_t);
extern void RepeatTail(uint8_t *, const uint8_t *, uint64_t);
int main(void) {
    const uint8_t second[] = {0, 127, 128, 255};
    unsigned calls = 0;
    for (uint64_t n = 1; n <= 2; ++n) {
        for (unsigned first = 0; first < 256; ++first) {
            for (unsigned sample = 0; sample < 4; ++sample) {
                uint8_t input[2] = {(uint8_t)first, second[sample]}, before[2];
                uint8_t output[8], want[8];
                memcpy(before, input, sizeof input);
                uint64_t invalid = UINT64_MAX;
                for (unsigned i = 0; i < n; ++i) {
                    if (input[i] >= 128) { invalid = i; break; }
                }
                uint64_t got = ObserveMask(input, n);
                if (got != invalid) {
                    fprintf(stderr, "mask n=%llu first=%u second=%u got=%llu want=%llu\n",
                        (unsigned long long)n, first, second[sample],
                        (unsigned long long)got, (unsigned long long)invalid);
                    return 1;
                }
                memset(output, 204, sizeof output);
                memcpy(want, output, sizeof output);
                want[1] = input[0];
                if (n == 2) { want[2] = input[1]; want[3] = input[0]; want[4] = input[1]; }
                RepeatTail(output + 1, input, n);
                if (memcmp(input, before, sizeof input) || memcmp(output, want, sizeof output)) {
                    fprintf(stderr, "repeat/canary n=%llu first=%u second=%u\n",
                        (unsigned long long)n, first, second[sample]);
                    return 1;
                }
                ++calls;
            }
        }
    }
    if (calls != 2048) return 1;
    puts("tail caller pairs=2048 failures=0");
    return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86LoweredVectorEntryCallerValues(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source := x86LoweredVectorMaskSource + x86LoweredVectorRepeatSource
	declarations := x86LoweredVectorMaskDeclaration + x86LoweredVectorRepeatDeclaration
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("missing ordinary tail caller IR", err)
			}
			ir += x86LoweredVectorEntryCallerIR
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
					text := ir
					if optimized {
						text = x86DwordProductIROptimize(t, ir)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							output := execution.compileAndRunLLVM(t, "vector-entry", text, x86LoweredVectorEntryCallerC, level)
							if string(output) != "tail caller pairs=2048 failures=0\n" {
								t.Fatal("tail values, invalid indices or escaped canaries differ", string(output))
							}
						})
					}
				})
			}
		})
	}
}
