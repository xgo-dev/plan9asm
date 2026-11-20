//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarDataResultsOriginalGoAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	goos := "linux"
	if strings.Contains(execution.triple, "apple") {
		goos = "darwin"
	}
	bodies := x86ScalarResultDataReadBodies("amd64")
	var names []string
	for name := range bodies {
		names = append(names, name)
	}
	sort.Strings(names)
	var source, declarations, calls, cDeclarations strings.Builder
	source.WriteString(x86ScalarResultDataTable)
	var functions []string
	for _, name := range names {
		body := strings.ReplaceAll(bodies[name], "PXOR X1,X1", "MOVOU table<>(SB),X1")
		body = strings.ReplaceAll(body, "PXOR X0,X0", "MOVOU table<>(SB),X0")
		for lane := 0; lane < 4; lane++ {
			function := fmt.Sprintf("dataResult%d", len(functions))
			functions = append(functions, function)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n%sPEXTRD $%d,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", function, body, lane)
			fmt.Fprintf(&declarations, "func %s() uint32\n", function)
			fmt.Fprintf(&calls, "fmt.Println(%s())\n", function)
			fmt.Fprintf(&cDeclarations, "extern uint32_t %s(void);\n", function)
		}
	}
	program := "package main\nimport \"fmt\"\n" + declarations.String() + "func main(){\n" + calls.String() + "}\n"
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module scalar_data_oracle\n\ngo 1.20\n", "main.go": program, "data.s": source.String(),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(directory, "original")
	environment := []string{"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=" + goos}
	dataGlobalAlignmentCommand(t, directory, environment, "go", "build", "-p=2", "-o", original, ".")
	results := strings.Fields(string(execution.run(t, original)))
	if len(results) != len(functions) {
		t.Fatalf("original Go executed %d results, want %d", len(results), len(functions))
	}
	var checks strings.Builder
	for index, function := range functions {
		value, err := strconv.ParseUint(results[index], 10, 32)
		if err != nil {
			t.Fatal("original Go result is not a uint32", err)
		}
		fmt.Fprintf(&checks, "if (%s()!=UINT32_C(%d)) { fprintf(stderr,%q); return 1; }\n",
			function, value, function+" differs from actual original Go\n")
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDeclarations.String() + "int main(void){\n" + checks.String() + "return 0;\n}\n"
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(api+"/"+level, func(t *testing.T) {
				execution.compileAndRunLLVM(t, "scalar-data-result", ir, main, level)
			})
		}
	}
	t.Logf("%d actual Go linked DATA-backed scalar results compared with three LLVM APIs at both optimization levels", len(functions))
}
