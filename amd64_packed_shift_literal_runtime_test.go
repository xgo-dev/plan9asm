package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Native legacy SSE is the independent counterpart. Virtual Y/Z object checks
// above do not stand in for executing hardware AVX512. The existing execution
// route owns explicit Linux QEMU or a truthful host-inapplicable result.
func TestCrossLinuxRuntimeMatrixX86PackedShiftLiteralMasksOriginalGoAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, declarations, kernels := x86ShiftLiteralMaskProgram(true)
	if len(kernels) != 36 {
		t.Fatal("incomplete original legacy W/D/Q × 3 logical × 4 shift union", len(kernels))
	}
	var goCases, cDeclarations, cCases strings.Builder
	for _, kernel := range kernels {
		fmt.Fprintf(&goCases, "{%q,%s,%d,%d,%d},\n", kernel.name, kernel.name, kernel.shift, kernel.mode, kernel.mask)
		fmt.Fprintf(&cDeclarations, "extern uint32_t %s(const uint8_t *);\n", kernel.name)
		fmt.Fprintf(&cCases, "{%q,%s,%d,%d,%d},\n", kernel.name, kernel.name, kernel.shift, kernel.mode, kernel.mask)
	}
	program := `package main

import "fmt"

` + declarations + `
type kernel struct {
    name string
    call func(*byte) uint32
    shift uint
    mode int
    mask byte
}

var kernels = []kernel{
` + goCases.String() + `}

func main() {
    for _, test := range kernels {
        for sample := 0; sample < 256; sample++ {
            input := [3]byte{0xa5, byte(sample), 0x5a}
            before := input
            want := byte(sample) >> test.shift
            switch test.mode {
            case 0:
                want &= test.mask
            case 1:
                want = ^want & test.mask
            case 2:
                want |= test.mask
            }
            got := test.call(&input[1])
            if got != uint32(want) || input != before {
                panic(fmt.Sprintf("%s sample=%d got=%x want=%x input=%x", test.name, sample, got, want, input))
            }
        }
    }
    fmt.Println("original legacy shift masks: 36x256 PASS")
}
`
	formatted, err := format.Source([]byte(program))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module original_shift_masks\n\ngo 1.20\n",
		"main.go": string(formatted), "masks_amd64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goos := "linux"
	if strings.Contains(execution.triple, "apple") {
		goos = "darwin"
	} else if strings.Contains(execution.triple, "windows") {
		goos = "windows"
	}
	original := filepath.Join(directory, "original")
	if goos == "windows" {
		original += ".exe"
	}
	environment := []string{"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=" + goos}
	dataGlobalAlignmentCommand(t, directory, environment, "go", "build", "-p=2", "-o", original, ".")
	if output := string(execution.run(t, original)); strings.TrimSpace(output) != "original legacy shift masks: 36x256 PASS" {
		t.Fatal("missing actual original-Go oracle completion", output)
	}
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + cDeclarations.String() + `
struct Case {
    const char *name;
    uint32_t (*call)(const uint8_t *);
    unsigned shift, mode;
    uint8_t mask;
};
static const struct Case cases[] = {
` + cCases.String() + `};

int main(void) {
    for (unsigned c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
        const struct Case *test = cases + c;
        for (unsigned sample = 0; sample < 256; sample++) {
            uint8_t input[3] = {0xa5, (uint8_t)sample, 0x5a};
            uint8_t before[3];
            memcpy(before, input, sizeof(input));
            uint8_t want = (uint8_t)sample >> test->shift;
            if (test->mode == 0) want &= test->mask;
            if (test->mode == 1) want = (uint8_t)~want & test->mask;
            if (test->mode == 2) want |= test->mask;
            uint32_t got = test->call(input + 1);
            if (got != want || memcmp(input, before, sizeof(input))) {
                fprintf(stderr, "%s sample=%u got=%x want=%x\n", test->name, sample, got, (unsigned)want);
                return 1;
            }
        }
    }
    puts("LLVM legacy shift masks: 36x256 PASS");
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(api+"/"+level, func(t *testing.T) {
				if output := string(execution.compileAndRunLLVM(t, "shift-literal-masks", ir, main, level)); strings.TrimSpace(output) != "LLVM legacy shift masks: 36x256 PASS" {
					t.Fatal("missing actual LLVM oracle completion", output)
				}
			})
		}
	}
	t.Log("36 original Go legacy SSE kernels × all 256 byte values; independent C byte oracle; 3 APIs × llc O0/O2; other vector bytes intentionally not initialized")
}
