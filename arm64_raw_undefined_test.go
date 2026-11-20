package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var arm64UndefinedImmediateCases = []uint16{0, 1, 16, 0x1234, 0x7fff, 0xffff}

func arm64UndefinedSource() (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, immediate := range arm64UndefinedImmediateCases {
		name := fmt.Sprintf("rawUDF%d", immediate)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nWORD $%#08x\n", name, immediate)
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	return source.String(), sigs
}

func TestARM64RawUndefinedEncodingsPreserveImmediate(t *testing.T) {
	source, sigs := arm64UndefinedSource()
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, immediate := range arm64UndefinedImmediateCases {
				want := fmt.Sprintf("asm sideeffect \"udf #%d\", \"~{memory}\"()\n  unreachable", immediate)
				if !strings.Contains(ir, want) {
					t.Fatalf("missing exact terminating exception %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			requireARM64UndefinedObjectEncodings(t, llc, triple, ir)
		})
	}
}

func requireARM64UndefinedObjectEncodings(t *testing.T, llc, triple, ir string) {
	t.Helper()
	objdump := findLLVM22Tool("llvm-objdump")
	if objdump == "" {
		t.Fatal("LLVM 22 llvm-objdump not found")
	}
	nm := findLLVM22Tool("llvm-nm")
	if nm == "" {
		t.Fatal("LLVM 22 llvm-nm not found")
	}
	dir := t.TempDir()
	source, object := filepath.Join(dir, "udf.ll"), filepath.Join(dir, "udf.o")
	if err := os.WriteFile(source, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(llc, "-O0", "-mtriple="+triple, "-filetype=obj", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("LLVM 22 UDF object: %v\n%s", err, output)
	}
	listing, err := exec.Command(objdump, "-d", object).CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM 22 UDF disassembly: %v\n%s", err, listing)
	}
	names, err := exec.Command(nm, "-n", "--defined-only", object).CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM 22 UDF symbol table: %v\n%s", err, names)
	}
	addresses := make(map[uint64]string)
	for _, match := range regexp.MustCompile(`(?m)^([0-9a-f]+)\s+[Tt]\s+_?(rawUDF[0-9]+)$`).FindAllSubmatch(names, -1) {
		address, err := strconv.ParseUint(string(match[1]), 16, 64)
		if err != nil || addresses[address] != "" {
			t.Fatalf("invalid/duplicate UDF function address:\n%s", names)
		}
		addresses[address] = string(match[2])
	}
	// Mach-O can print ltmp0 instead of the external symbol at the first
	// function's address. Bind that region through the actual symbol table;
	// never guess that a coincidental UDF elsewhere belongs to this function.
	symbols := regexp.MustCompile(`(?m)^([0-9a-f]+) <[^>]+>:\n`).FindAllSubmatchIndex(listing, -1)
	if len(symbols) != len(arm64UndefinedImmediateCases) {
		t.Fatalf("incomplete UDF symbol inventory:\n%s", listing)
	}
	seen := make(map[string]bool)
	for index, symbol := range symbols {
		address, err := strconv.ParseUint(string(listing[symbol[2]:symbol[3]]), 16, 64)
		if err != nil || addresses[address] == "" {
			t.Fatalf("disassembly region has no exact UDF function binding:\n%s", listing)
		}
		name := addresses[address]
		end := len(listing)
		if index+1 < len(symbols) {
			end = symbols[index+1][0]
		}
		matched := false
		for _, immediate := range arm64UndefinedImmediateCases {
			if name != fmt.Sprintf("rawUDF%d", immediate) {
				continue
			}
			pattern := fmt.Sprintf(`(?m)^\s*[0-9a-f]+:\s+%08x\s+udf\s+#`, immediate)
			if !regexp.MustCompile(pattern).Match(listing[symbol[1]:end]) {
				t.Fatalf("%s lacks exact UDF imm16 machine bytes:\n%s", name, listing[symbol[1]:end])
			}
			matched = true
		}
		if !matched || seen[name] {
			t.Fatalf("unexpected/duplicate UDF symbol %s", name)
		}
		seen[name] = true
	}
}

func TestCrossLinuxRuntimeMatrixARM64RawUndefinedFaultOracles(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, sigs := arm64UndefinedSource()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64-raw-udf-fault", triple, ir,
		arm64UndefinedFaultOracleC(), runner)

	// Link and call the original Go WORD bodies independently. Go's signal
	// handler reports SIGILL and terminates the child with exit code 2.
	dir := t.TempDir()
	var mainGo strings.Builder
	mainGo.WriteString("package main\nimport \"os\"\n")
	for _, immediate := range arm64UndefinedImmediateCases {
		fmt.Fprintf(&mainGo, "func rawUDF%d()\n", immediate)
	}
	mainGo.WriteString("func main() { switch os.Args[1] {\n")
	for _, immediate := range arm64UndefinedImmediateCases {
		fmt.Fprintf(&mainGo, "case \"%d\": rawUDF%d()\n", immediate, immediate)
	}
	mainGo.WriteString("} }\n")
	for name, content := range map[string]string{
		"go.mod":      "module example.com/udf-native\n\ngo 1.20\n",
		"main.go":     mainGo.String(),
		"udf_arm64.s": strings.ReplaceAll(source, "TEXT rawUDF", "TEXT ·rawUDF"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-udf")
	ctx, cancel := runtimeOracleStageContext(t)
	build := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", executable, ".")
	build.Dir, build.Env = dir, append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=arm64")
	if len(runner) != 0 {
		build.Env = append(build.Env, "GOOS=linux")
	}
	output, err := runtimeOracleCombinedOutput(ctx, build)
	cancel()
	if err != nil {
		t.Fatalf("original Go UDF build: %v\n%s", err, output)
	}
	for _, immediate := range arm64UndefinedImmediateCases {
		args := runtimeOracleGuestArguments(t, runner, executable, fmt.Sprint(immediate))
		ctx, cancel = runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Env = append(os.Environ(), "GOTRACEBACK=single")
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || !strings.Contains(string(output), "SIGILL: illegal instruction") {
			t.Fatalf("original Go UDF #%d did not deliver the expected SIGILL: %v\n%s", immediate, err, output)
		}
	}
}

func arm64UndefinedFaultOracleC() string {
	var main strings.Builder
	main.WriteString(`#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

`)
	for _, immediate := range arm64UndefinedImmediateCases {
		fmt.Fprintf(&main, "extern void rawUDF%d(void);\n", immediate)
	}
	main.WriteString("\nstatic void (*fault_functions[])(void) = {\n")
	for _, immediate := range arm64UndefinedImmediateCases {
		fmt.Fprintf(&main, "    rawUDF%d,\n", immediate)
	}
	main.WriteString(`};

int main(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 1;

    for (unsigned i = 0; i < sizeof(fault_functions) / sizeof(fault_functions[0]); i++) {
        pid_t child = fork();
        if (child < 0) return 2;
        if (!child) {
            fault_functions[i]();
            _exit(90);
        }

        int status;
        if (waitpid(child, &status, 0) != child ||
            !WIFSIGNALED(status) || WTERMSIG(status) != SIGILL) return 3;
    }
    return 0;
}
`)
	return main.String()
}

func TestARM64RawUndefinedDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x00010000, 0x0001ffff, 0x01000000, 0xffffffff} {
		ins := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		decoded, err := decodeARM64RawWordInstruction(ins)
		if err == nil && decoded.Op == "UNDEF" {
			t.Fatalf("unrelated word %#08x became an undefined-exception witness", word)
		}
	}
}

func TestARM64RawReachableUndefinedWordDoesNotBecomeData(t *testing.T) {
	const source = `TEXT rawReachableUndefined(SB),4,$0-0
	WORD $0xd503201f // NOP falls through into the trap.
reachable:
	WORD $0x00000002 // Allocated UDF #2, not a trailing constant pool.
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawReachableUndefined": {Name: "rawReachableUndefined", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, `asm sideeffect "udf #2"`) || strings.Contains(ir, ".raw_data") {
		t.Fatalf("reachable UDF became data or lost its immediate:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "reachable-udf.ll", "reachable-udf.o", ir)
}

func TestARM64RawUndefinedDecoderCompleteImmediateField(t *testing.T) {
	for word := uint32(0); word <= 0xffff; word++ {
		ins := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		decoded, err := decodeARM64RawWordInstruction(ins)
		if err != nil || decoded.Op != "UNDEF" || len(decoded.Args) != 0 || decoded.arm64RawUndefinedImmediate != uint16(word) {
			t.Fatalf("UDF %#08x decoded as %+v, %v", word, decoded, err)
		}
		if features := inferFuncTargetFeaturesForGOARCH(ArchARM64, "arm64", Func{Instrs: []Instr{ins}}); features != "" {
			t.Fatalf("baseline UDF %#08x acquired unrelated target features %q", word, features)
		}
	}
}

func TestARM64RawUndefinedRequiresActualIntegerEncoding(t *testing.T) {
	for _, value := range []string{"0.0", "-0.0", "1.25"} {
		source := "TEXT badRawUndefined(SB),4,$0-0\nWORD $(" + value + ")\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"badRawUndefined": {Name: "badRawUndefined", Ret: Void}}}); err == nil {
			t.Fatalf("floating constant %s acquired an integer machine-code witness", value)
		}
	}
}

func TestARM64ExceptionImmediateRejectsFloatingConstantsLikeGo(t *testing.T) {
	for _, op := range []string{"BRK", "HLT", "HVC", "SMC", "DCPS1", "DCPS2", "DCPS3"} {
		for _, value := range []string{"0.0", "-0.0", "1.25"} {
			t.Run(op+"/"+value, func(t *testing.T) {
				source := "TEXT badException(SB),4,$0-0\n" + op + " $(" + value + ")\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"badException": {Name: "badException", Ret: Void}}}); err == nil {
					t.Fatalf("%s accepted Go's floating operand class %s as an imm16", op, value)
				}
			})
		}
	}
}
