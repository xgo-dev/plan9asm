package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixQEMUOriginalGoAndCArguments(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/amd64 QEMU execution counterpart")
	}
	arguments := []string{"numeric", "with space", "", "--option", "quote\"backslash\\", "中文"}
	for _, target := range []struct {
		arch, compiler, qemu, sysroot string
	}{
		{"arm64", "aarch64-linux-gnu-gcc", "qemu-aarch64", "/usr/aarch64-linux-gnu"},
		{"arm", "arm-linux-gnueabihf-gcc", "qemu-arm", "/usr/arm-linux-gnueabihf"},
		{"386", "i686-linux-gnu-gcc", "qemu-i386", "/usr/i686-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			for _, tool := range []string{target.compiler, target.qemu} {
				if _, err := exec.LookPath(tool); err != nil {
					t.Fatal("required guest tool:", err)
				}
			}
			dir := t.TempDir()
			goSource := `package main
import (
    "encoding/json"
    "os"
)
func main() {
    if err := json.NewEncoder(os.Stdout).Encode(os.Args); err != nil {
        panic(err)
    }
}
`
			for name, content := range map[string]string{
				"go.mod":  "module example.com/guest-arguments\n\ngo 1.20\n",
				"main.go": goSource,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			goProgram := filepath.Join(dir, "original-go")
			ctx, cancel := runtimeOracleStageContext(t)
			build := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", goProgram, ".")
			build.Dir = dir
			build.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0",
				"GOOS=linux", "GOARCH="+target.arch, "GOARM=7")
			output, err := runtimeOracleCombinedOutput(ctx, build)
			cancel()
			if err != nil {
				t.Fatalf("actual original Go guest build: %v\n%s", err, output)
			}
			prefix := []string{target.qemu, "-L", target.sysroot}
			command := runtimeOracleGuestArguments(t, prefix, goProgram, arguments...)
			ctx, cancel = runtimeOracleStageContext(t)
			output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, command[0], command[1:]...))
			cancel()
			if err != nil {
				t.Fatalf("original Go guest execution: %v\n%s", err, output)
			}
			want := append([]string{goProgram}, arguments...)
			expected, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(output)) != string(expected) {
				t.Errorf("original Go argv got %s want %s", output, expected)
			}

			cProgram := filepath.Join(dir, "original-c")
			var constants strings.Builder
			for _, argument := range append([]string{cProgram}, arguments...) {
				fmt.Fprintf(&constants, "    %q,\n", argument)
			}
			cSource := fmt.Sprintf(`#include <stdio.h>
#include <string.h>
static const char *expected[] = {
%s};
int main(int argc, char **argv) {
    int count = sizeof(expected) / sizeof(expected[0]);
    if (argc != count) {
        fprintf(stderr, "argc got=%%d want=%%d\n", argc, count);
        return 1;
    }
    for (int i = 0; i < count; i++) {
        if (strcmp(argv[i], expected[i])) {
            fprintf(stderr, "argv[%%d] got=%%s want=%%s\n", i, argv[i], expected[i]);
            return 2;
        }
    }
    return 0;
}
`, constants.String())
			cPath := filepath.Join(dir, "main.c")
			if err := os.WriteFile(cPath, []byte(cSource), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel = runtimeOracleStageContext(t)
			output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx,
				target.compiler, cPath, "-O2", "-o", cProgram))
			cancel()
			if err != nil {
				t.Fatalf("original C guest build: %v\n%s", err, output)
			}
			command = runtimeOracleGuestArguments(t, prefix, cProgram, arguments...)
			ctx, cancel = runtimeOracleStageContext(t)
			output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, command[0], command[1:]...))
			cancel()
			if err != nil {
				t.Errorf("original C guest argv: %v\n%s", err, output)
			}
		})
	}
}
