package plan9asm

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRuntimeOracleWindowsBinaryOutputSetup(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM22 clang required")
	}
	directory := t.TempDir()
	// Only declarations: this checks the Windows-target constructor and its
	// error branches, not a Windows CRT execution. The byte protocol below
	// separately runs against the actual host CRT, including Windows CI.
	for name, contents := range map[string]string{
		"stdio.h":   "typedef struct FILE FILE;\nextern FILE *stdout, *stderr;\n",
		"io.h":      "int _fileno(struct FILE*);\nint _setmode(int,int);\n",
		"fcntl.h":   "#define _O_BINARY 32768\n",
		"process.h": "__attribute__((noreturn)) void _exit(int);\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	source := runtimeOracleProcessSource(t, directory)
	irPath := filepath.Join(directory, "process.ll")
	x86FloatCompareCaptureCommand(t, exec.Command(clang, "-target", "x86_64-pc-windows-msvc", "-nostdinc",
		"-I", directory, "-O0", "-S", "-emit-llvm", source, "-o", irPath))
	ir, err := os.ReadFile(irPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(ir)
	if strings.Count(text, "call i32 @_setmode(") != 2 || !strings.Contains(text, "@stdout") ||
		!strings.Contains(text, "@stderr") || !strings.Contains(text, "@llvm.global_ctors") ||
		len(regexp.MustCompile(`icmp eq i32 [^\n]+, -1`).FindAll(ir, -1)) != 2 ||
		!regexp.MustCompile(`call void @_exit\(i32[^\n]*125\)`).Match(ir) {
		t.Fatalf("Windows oracle lacks checked binary stdout/stderr setup before main:\n%s", ir)
	}
}

func TestCrossLinuxRuntimeMatrixOracleBinaryOutput(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const source = `#include <stdio.h>
int main(void) {
    const unsigned char bytes[] = {0x41, 10, 13, 10, 0, 0x1a, 0xff};
    if (fwrite(bytes, 1, sizeof(bytes), stdout) != sizeof(bytes)) return 1;
    if (fflush(stdout) != 0) return 2;
    return 0;
}
`
	output := execution.compileAndRunLLVM(t, "binary_output", "define i32 @unused() { ret i32 0 }\n", source, "-O2")
	if !bytes.Equal(output, []byte{0x41, 10, 13, 10, 0, 0x1a, 0xff}) {
		t.Fatalf("oracle transport changed original stdout bytes: %x", output)
	}
}
