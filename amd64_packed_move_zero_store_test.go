package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Independent EVEX opcodes whose Go-accepted .Z memory destination requires
// architectural #UD. Intel XED's memory patterns require ZEROING=0 for both
// packed moves and all six compression opcodes. VMOVDQA/DQU are VEX-only.
var x86PackedZeroStoreOpcodes = []string{
	"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS",
	"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
	"VCOMPRESSPS", "VCOMPRESSPD", "VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ",
}

func x86PackedZeroStoreInstruction(name, instruction string) string {
	return fmt.Sprintf("TEXT %s(SB),4,$0-0\n%s\nRET\n", name, instruction)
}

func x86PackedZeroStoreSource() (string, map[string]FuncSig, []string) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var names []string
	for _, opcode := range x86PackedZeroStoreOpcodes {
		for _, bank := range []string{"X", "Y", "Z"} {
			name := "fault" + opcode + bank
			source.WriteString(x86PackedZeroStoreInstruction(name, fmt.Sprintf("%s.Z %s0,K1,(AX)", opcode, bank)))
			sigs[name] = FuncSig{Name: name, Ret: Void}
			names = append(names, name)
		}
	}
	return source.String(), sigs, names
}

func TestX86PackedZeroMemoryStorePreservesUndefinedOpcode(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, sigs, names := x86PackedZeroStoreSource()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source, true)
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			trap := `call void asm sideeffect "ud2", "~{memory}"()`
			if strings.Count(ir, trap) != len(names) || strings.Contains(ir, "call void @llvm.masked.store.") {
				t.Fatalf("Go-accepted EVEX.z memory stores must deliver #UD before reading registers or memory; traps=%d want=%d", strings.Count(ir, trap), len(names))
			}
			compileLLVMToObject(t, llc, target.triple, "zero-store.ll", "zero-store.o", ir)
		})
	}
}

func TestX86PackedZeroMemoryStoreFaultPrecedesFPBoundsAndMaskReads(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range x86PackedZeroStoreOpcodes {
			t.Run(arch+"/"+opcode, func(t *testing.T) {
				instruction := Instr{Op: Op(opcode + ".Z"), Args: []Operand{
					{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "K1"},
					{Kind: OpFP, FPOffset: 1 << 20},
				}}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before := output.Len()
				lower := ctx.lowerPackedVectorMove
				if strings.Contains(opcode, "COMPRESS") {
					lower = ctx.lowerPackedCompress
				}
				recognized, terminated, err := lower(instruction.Op, instruction)
				if !recognized || !terminated || err != nil || output.String()[before:] != "  call void asm sideeffect \"ud2\", \"~{memory}\"()\n  unreachable\n" {
					t.Fatalf("%s invalid encoding evaluated nonexistent FP/mask/register data before #UD: %t/%t/%v", arch, recognized, terminated, err)
				}
			})
		}
	}
}

func x86PackedFirstGoInstructionBytes(t *testing.T, arch, instruction string) []byte {
	t.Helper()
	listing, err := x86ScalarLiteralGoListing(t, arch, "TEXT probe(SB),4,$0-0\n"+instruction+"\nRET\n")
	if err != nil {
		t.Fatalf("actual Go packed-move object: %v\n%s", err, listing)
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[0] != "0x0000" || len(fields[1]) != 2 {
			continue
		}
		bytes := make([]byte, 6)
		for index := range bytes {
			value, err := strconv.ParseUint(fields[index+1], 16, 8)
			if err != nil {
				t.Fatalf("actual Go object byte: %v\n%s", err, listing)
			}
			bytes[index] = byte(value)
		}
		return bytes
	}
	t.Fatalf("actual Go object lacks packed-move bytes:\n%s", listing)
	return nil
}

func TestX86PackedZeroMemoryStoreActualGoAndLLVM22Encoding(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc not found")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, opcode := range x86PackedZeroStoreOpcodes {
			for _, bank := range []string{"X", "Y", "Z"} {
				instruction := fmt.Sprintf("%s %s0,K1,(AX)", opcode, bank)
				normal := x86PackedFirstGoInstructionBytes(t, arch, instruction)
				zero := x86PackedFirstGoInstructionBytes(t, arch, strings.Replace(instruction, " ", ".Z ", 1))
				if normal[0] != 0x62 || normal[3]&0x80 != 0 || zero[3]&0x80 == 0 {
					t.Fatalf("%s %s lacks independent EVEX.z witness: normal=%x zero=%x", arch, instruction, normal, zero)
				}
				wantW := strings.HasSuffix(opcode, "64") || opcode == "VMOVDQU16" || strings.HasSuffix(opcode, "PD") ||
					opcode == "VPCOMPRESSW" || opcode == "VPCOMPRESSQ"
				if (normal[2]&0x80 != 0) != wantW {
					t.Fatalf("actual Go object changed the native element selector: %s %s bytes=%x", arch, instruction, normal)
				}
				for index := range normal {
					wanted := normal[index]
					if index == 3 {
						wanted |= 0x80
					}
					if zero[index] != wanted {
						t.Fatalf(".Z changed more than the native EVEX.z bit: %s %s", arch, instruction)
					}
				}
				for _, test := range []struct {
					bytes   []byte
					invalid bool
				}{{normal, false}, {zero, true}} {
					var input strings.Builder
					for _, value := range test.bytes {
						fmt.Fprintf(&input, "0x%02x ", value)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple,
						"--mattr=+avx512f,+avx512bw,+avx512vl,+avx512vbmi2")
					command.Stdin = strings.NewReader(input.String())
					command.WaitDelay = 2 * time.Second
					output, err := command.CombinedOutput()
					cancel()
					// llvm-mc can return zero while diagnosing rejected bytes.
					invalid := strings.Contains(string(output), "invalid instruction encoding")
					family := "VMOV"
					if strings.Contains(opcode, "COMPRESS") {
						family = "COMPRESS"
					}
					if err != nil || invalid != test.invalid || !test.invalid && !strings.Contains(strings.ToUpper(string(output)), family) {
						t.Fatalf("%s %s invalid=%t: LLVM 22 diagnostic mismatch: %v\n%s", arch, instruction, test.invalid, err, output)
					}
					// LLVM 22's 32-bit decoder aliases some W1 move spellings
					// to W0 names. Verify the independent W byte above and the
					// exact opcode in 64-bit decode, not the aliased 32-bit name.
					if !test.invalid {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=x86_64-unknown-linux-gnu",
							"--mattr=+avx512f,+avx512bw,+avx512vl,+avx512vbmi2")
						command.Stdin = strings.NewReader(input.String())
						command.WaitDelay = 2 * time.Second
						output, err := command.CombinedOutput()
						cancel()
						if err != nil || !strings.Contains(strings.ToUpper(string(output)), opcode) || strings.Contains(string(output), "invalid instruction encoding") {
							t.Fatalf("actual Go object does not decode as the exact opcode: %s %s: %v\n%s", arch, instruction, err, output)
						}
					}
				}
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86PackedZeroMemoryStoreFault(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 packed-move fault oracle")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source, sigs, names := x86PackedZeroStoreSource()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	var oracle strings.Builder
	oracle.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

`)
	for _, name := range names {
		fmt.Fprintf(&oracle, "extern void %s(void);\n", name)
	}
	oracle.WriteString("\nstatic void (*fault_functions[])(void) = {\n")
	for _, name := range names {
		fmt.Fprintf(&oracle, "    %s,\n", name)
	}
	oracle.WriteString(`};

int main(int argc, char **argv) {
#ifdef _WIN32
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc == 2) {
        unsigned index = (unsigned)strtoul(argv[1], 0, 10);
        if (index >= sizeof(fault_functions)/sizeof(fault_functions[0])) return 6;
        fault_functions[index]();
        return 3;
    }
    for (unsigned i = 0; i < sizeof(fault_functions)/sizeof(fault_functions[0]); i++) {
        char index[16];
        snprintf(index, sizeof(index), "%u", i);
        intptr_t status = _spawnl(_P_WAIT, argv[0], argv[0], index, NULL);
        if ((uint32_t)status != UINT32_C(0xc000001d)) return 5;
    }
#else
    (void)argc;
    (void)argv;
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 1;
    for (unsigned i = 0; i < sizeof(fault_functions)/sizeof(fault_functions[0]); i++) {
        pid_t child = fork();
        if (child < 0) return 2;
        if (!child) { fault_functions[i](); _exit(3); }
        int status;
        if (waitpid(child, &status, 0) != child) return 4;
        if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGILL) return 5;
    }
#endif
    return 0;
}
`)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-zero-store-fault", triple, ir, oracle.String(), runner)

	// No preceding valid AVX512 instruction is executed. EVEX.z=1 with a
	// memory destination is always #UD, irrespective of mask/address values.
	var mainGo strings.Builder
	mainGo.WriteString("package main\nimport \"os\"\n")
	for _, name := range names {
		fmt.Fprintf(&mainGo, "func %s()\n", name)
	}
	mainGo.WriteString("func main() { switch os.Args[1] {\n")
	for _, name := range names {
		fmt.Fprintf(&mainGo, "case %q: %s()\n", name, name)
	}
	mainGo.WriteString("} }\n")
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":        "module example.com/packed-zero-store\n\ngo 1.20\n",
		"main.go":       mainGo.String(),
		"fault_amd64.s": strings.ReplaceAll(source, "TEXT fault", "TEXT ·fault"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-packed-zero-store")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", executable, ".")
	build.Dir, build.Env = dir, append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=amd64")
	build.WaitDelay = 2 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("original Go packed-store build: %v\n%s", err, output)
	}
	for _, name := range names {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		args := append(append([]string(nil), runner...), executable, name)
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Env = append(os.Environ(), "GOTRACEBACK=single")
		command.WaitDelay = 2 * time.Second
		output, err := command.CombinedOutput()
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || !x86GoPackedStoreFaultDiagnostic(runtime.GOOS, name, string(output)) {
			t.Fatalf("original Go %s did not deliver SIGILL: %v\n%s", name, err, output)
		}
	}
}

var x86GoPackedStoreFatalFault = regexp.MustCompile(`^fatal error: fault\n\n?\[signal 0xc000001d code=0x[0-9a-f]+ addr=0x[0-9a-f]+ pc=0x[0-9a-f]+\]\n`)

func x86GoPackedStoreFaultDiagnostic(goos, name, output string) bool {
	output = strings.ReplaceAll(output, "\r\n", "\n")
	if strings.Contains(output, "\r") {
		return false
	}
	matched := strings.HasPrefix(output, "SIGILL: illegal instruction\n")
	if goos == "windows" {
		// Current Go converts the native exception to sigpanic; older SDKs
		// print the unhandled exception directly. Both must identify #UD,
		// not an ordinary panic, access violation or just an exit status 2.
		// Go's fatal header can have either one newline or a separating
		// blank line before the complete native signal record.
		matched = strings.HasPrefix(output, "Exception 0xc000001d ") || x86GoPackedStoreFatalFault.MatchString(output)
	}
	if !matched {
		return false
	}
	lines := strings.Split(output, "\n")
	for index, line := range lines {
		if line == "main."+name+"()" && index+1 < len(lines) {
			location := strings.ReplaceAll(lines[index+1], "\\", "/")
			_, position, found := strings.Cut(location, "/fault_amd64.s:")
			fields := strings.Fields(position)
			if !found || len(fields) == 0 {
				continue
			}
			lineNumber, err := strconv.ParseUint(fields[0], 10, 31)
			if err == nil && lineNumber > 0 {
				return true
			}
		}
	}
	return false
}

func TestX86GoPackedStoreFaultDiagnostic(t *testing.T) {
	const stack = "\nmain.faultVMOVAPDX()\n\tC:/fixture/fault_amd64.s:2 fp=0x123 pc=0x456\n"
	const modern = "fatal error: fault\n\n[signal 0xc000001d code=0x0 addr=0x0 pc=0x456]\n"
	for _, test := range []struct {
		name, goos, output string
		valid              bool
	}{
		{"Unix", "linux", "SIGILL: illegal instruction\nPC=0x456\n" + stack, true},
		{"Windows exception", "windows", "Exception 0xc000001d 0x0 0x0 0x456\n" + stack, true},
		{"Windows sigpanic", "windows", modern + stack, true},
		{"Windows native sigpanic", "windows", strings.Replace(modern, "fault\n\n", "fault\n", 1) + stack, true},
		{"Windows native newlines", "windows", strings.ReplaceAll(modern+stack, "\n", "\r\n"), true},
		{"Windows native sigpanic CRLF", "windows", strings.ReplaceAll(strings.Replace(modern, "fault\n\n", "fault\n", 1)+stack, "\n", "\r\n"), true},
		{"extra fatal blank line", "windows", strings.Replace(modern, "fault\n\n", "fault\n\n\n", 1) + stack, false},
		{"malformed signal record", "windows", strings.Replace(modern, " pc=0x456]", " pc=unobserved]", 1) + stack, false},
		{"unterminated signal record", "windows", strings.Replace(modern, "0x456]", "0x456", 1) + stack, false},
		{"missing fault address", "windows", strings.Replace(modern, " addr=0x0", "", 1) + stack, false},
		{"ordinary panic", "windows", "panic: Exception 0xc000001d\n" + stack, false},
		{"different signal", "windows", strings.ReplaceAll(modern+stack, "0xc000001d", "0xc0000005"), false},
		{"partial exception code", "windows", "Exception 0xc000001d0\n" + stack, false},
		{"missing tested frame", "windows", modern, false},
		{"wrong tested frame", "windows", modern + strings.ReplaceAll(stack, "faultVMOVAPDX", "faultOther"), false},
		{"wrong source", "windows", modern + strings.ReplaceAll(stack, "fault_amd64.s", "main.go"), false},
		{"malformed source position", "windows", modern + strings.ReplaceAll(stack, ".s:2 ", ".s:2invalid "), false},
		{"zero source position", "windows", modern + strings.ReplaceAll(stack, ".s:2 ", ".s:0 "), false},
		{"bare native carriage return", "windows", modern + strings.ReplaceAll(stack, "fp=", "\rfp="), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := x86GoPackedStoreFaultDiagnostic(test.goos, "faultVMOVAPDX", test.output); got != test.valid {
				t.Fatalf("actual Go illegal-instruction diagnostic: got %t, want %t", got, test.valid)
			}
		})
	}
}
