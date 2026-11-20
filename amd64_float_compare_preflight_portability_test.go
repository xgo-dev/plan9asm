package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86FloatingComparePreflightWindowsResourceBoundary(t *testing.T) {
	_, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("actual LLVM22 clang required for preflight preprocessing")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sys"), 0700); err != nil {
		t.Fatal(err)
	}
	// These headers deliberately supply only declarations. This is actual
	// LLVM22 preprocessing/object compilation of the entire original helper,
	// not a MinGW SDK, Windows link/runtime or synthetic ISA capability grant.
	for name, contents := range map[string]string{
		"stdint.h":       "typedef unsigned long long uint64_t;\n",
		"stdio.h":        "typedef struct FILE FILE;\nextern FILE *stdout;\nint printf(const char*,...);\nint fflush(FILE*);\n",
		"cpuid.h":        "int __get_cpuid(unsigned,unsigned*,unsigned*,unsigned*,unsigned*);\nint __get_cpuid_count(unsigned,unsigned,unsigned*,unsigned*,unsigned*,unsigned*);\n",
		"sys/resource.h": "#error plan9asm_portability_poison_resource_header\n",
		"preflight.c":    "#define REQUIRED_AXIS 1\n" + x86FloatCompareOpcodePreflightC,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := func(flags ...string) ([]byte, error) {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		args := []string{"-target", "x86_64-unknown-linux-gnu", "-nostdinc", "-I", dir}
		args = append(args, flags...)
		args = append(args, filepath.Join(dir, "preflight.c"))
		return runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, clang, args...))
	}

	t.Run("windows-poison-header", func(t *testing.T) {
		output, err := command("-D_WIN32=1", "-E", "-P")
		if err != nil {
			t.Fatalf("_WIN32 preflight accessed unavailable POSIX header: %v\n%s", err, output)
		}
		for _, token := range []string{"setrlimit", "RLIMIT_CORE", "struct rlimit"} {
			if strings.Contains(string(output), token) {
				t.Fatal("Windows preflight retained a POSIX resource operation", token)
			}
		}
		for _, opcode := range []string{"vcmpps $0", "vcmppd $0", "vcmpss $0", "vcmpsd $0", "xgetbv", "required_state(axis"} {
			if !strings.Contains(string(output), opcode) {
				t.Fatal("platform guard reduced original capability/opcode preflight", opcode)
			}
		}
		object := filepath.Join(dir, "windows-macro.o")
		if output, err := command("-D_WIN32=1", "-O0", "-c", "-o", object); err != nil {
			t.Fatalf("actual compiler could not compile full Windows-macro preflight: %v\n%s", err, output)
		}
		if info, err := os.Stat(object); err != nil || info.Size() == 0 {
			t.Fatal("missing actual compiler object", err)
		}
	})

	t.Run("posix-poison-header", func(t *testing.T) {
		output, err := command("-U_WIN32", "-E", "-P")
		// A plain concrete compiler rejection, not a timeout/cleanup/tool error,
		// proves POSIX still consumes the very header forbidden under _WIN32.
		exit, ok := err.(*exec.ExitError)
		// Clang joins the exact -I argument with the slash-spelled include,
		// also on Windows; filepath.Join would invent backslashes in the tail.
		if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), dir+"/sys/resource.h:1:2: error: plan9asm_portability_poison_resource_header") {
			t.Fatalf("lost exact POSIX header-selection witness: %v\n%s", err, output)
		}
	})

	t.Run("posix-core-zero-preserved", func(t *testing.T) {
		const checked = "struct rlimit { unsigned long rlim_cur, rlim_max; };\n#define RLIMIT_CORE 9917\n#define setrlimit plan9asm_posix_setrlimit_fixture\nint plan9asm_posix_setrlimit_fixture(int,const struct rlimit*);\n"
		if err := os.WriteFile(filepath.Join(dir, "sys", "resource.h"), []byte(checked), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := command("-U_WIN32", "-E", "-P")
		if err != nil {
			t.Fatalf("POSIX checked resource header failed: %v\n%s", err, output)
		}
		compact := strings.Join(strings.Fields(string(output)), "")
		if !strings.Contains(compact, "structrlimitno_core={0,0};if(plan9asm_posix_setrlimit_fixture(9917,&no_core))return77;") {
			t.Fatal("POSIX preflight changed its zero soft/hard limit or error exit")
		}
		irPath := filepath.Join(dir, "posix-core.ll")
		if output, err := command("-U_WIN32", "-O0", "-S", "-emit-llvm", "-o", irPath); err != nil {
			t.Fatalf("POSIX resource consumer did not compile: %v\n%s", err, output)
		}
		ir, err := os.ReadFile(irPath)
		if err != nil || strings.Count(string(ir), "call i32 @plan9asm_posix_setrlimit_fixture(") != 1 {
			t.Fatalf("actual compiled POSIX preflight lost the resource consumer: %v\n%s", err, ir)
		}
	})
}
