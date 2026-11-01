package plan9asm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

type arm64ImmediateFaultCase struct {
	text string
	move uint32
	op   uint32
}

func arm64ImmediateFaultCases() []arm64ImmediateFaultCase {
	var cases []arm64ImmediateFaultCase
	for _, tc := range []struct {
		constant string
		move     uint32
	}{
		{"1", 0xd280003b}, {"4096", 0xd282001b},
		{"0x1234", 0xd282469b}, {"0xffff0000", 0xd2bffffb}, {"-4096", 0x9281fffb},
	} {
		cases = append(cases,
			arm64ImmediateFaultCase{"CMP $" + tc.constant + ",ZR", tc.move, 0xeb1b03ff},
			arm64ImmediateFaultCase{"CMN $" + tc.constant + ",ZR", tc.move, 0xab1b03ff})
	}
	for _, tc := range []struct {
		op   string
		word uint32
	}{
		{"AND", 0x8a1b001f}, {"ORR", 0xaa1b001f}, {"EOR", 0xca1b001f},
		{"BIC", 0x8a3b001f}, {"ORN", 0xaa3b001f}, {"EON", 0xca3b001f},
	} {
		cases = append(cases, arm64ImmediateFaultCase{tc.op + " $4096,R0,ZR", 0xd282001b, tc.word})
	}
	return cases
}

func arm64ImmediateFaultSource() (source, declarations string, sigs map[string]FuncSig) {
	var asm, goDecl strings.Builder
	sigs = make(map[string]FuncSig)
	for index, tc := range arm64ImmediateFaultCases() {
		name := fmt.Sprintf("Fault%d", index)
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, tc.text)
		fmt.Fprintf(&goDecl, "func %s()\n", name)
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	return asm.String(), goDecl.String(), sigs
}

func arm64ImmediateOriginalGoBytes(t *testing.T, source, goos string) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "original.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", filepath.Join(dir, "original.o"), path)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64")
	listing, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("original Go %s object: %v\n%s", goos, err, listing)
	}
	var output []byte
	for _, row := range regexp.MustCompile(`(?m)^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`).FindAllSubmatch(listing, -1) {
		data, err := hex.DecodeString(strings.ReplaceAll(string(row[1]), " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, data...)
	}
	return output
}

func TestARM64GPImmediateOriginalGoFaultExpansion(t *testing.T) {
	// Fixed 12-byte Go rows really contain MOV, operation, UDF, followed
	// by the independent source RET. Do not mistake their zero word for
	// unreachable alignment or treat Go assembler acceptance as runtime P.
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range arm64ImmediateFaultCases() {
			source := "TEXT fault(SB),4,$0-0\n" + tc.text + "\nRET\n"
			var expected bytes.Buffer
			for _, word := range []uint32{tc.move, tc.op, 0, 0xd65f03c0} {
				if err := binary.Write(&expected, binary.LittleEndian, word); err != nil {
					t.Fatal(err)
				}
			}
			actual := arm64ImmediateOriginalGoBytes(t, source, goos)
			if !bytes.Equal(actual, expected.Bytes()) {
				t.Fatalf("%s %s original Go words: got %x want %x", goos, tc.text, actual, expected.Bytes())
			}
			ins := arm64ImmediateTestInstruction(t, tc.text)
			form, handled, err := parseARM64GPImmediateForm(ins.Op, ins)
			if !handled || err != nil || !form.trailingUDF {
				t.Fatalf("exact Go tail-zero emission missing: %s: %+v %v", tc.text, form, err)
			}
		}
	}
}

func arm64ImmediateFaultIRs(t *testing.T, target string) []string {
	t.Helper()
	source, declarations, sigs := arm64ImmediateFaultSource()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	pkg := mustGoPackage(t, "test/fault", "package fault\n"+declarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs, ResolveSym: resolve}
	text, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	module, err := TranslateModuleInContext(ctx, file, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Module.Dispose()
	return []string{text, module.String(), bound.Module.String()}
}

func TestARM64GPImmediateFaultObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		for api, ir := range arm64ImmediateFaultIRs(t, target) {
			if strings.Count(ir, `asm sideeffect "udf #0"`) != len(arm64ImmediateFaultCases()) ||
				strings.Count(ir, "unreachable") < len(arm64ImmediateFaultCases()) {
				t.Fatalf("%s API %d missing exact terminating UDF family", target, api)
			}
			compileLLVMToObject(t, llc, target, fmt.Sprintf("immediate-fault-%d.ll", api), fmt.Sprintf("immediate-fault-%d.o", api), ir)
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64GPImmediateFault(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	source, declarations, _ := arm64ImmediateFaultSource()
	var calls, cDeclarations, cPointers strings.Builder
	for index := range arm64ImmediateFaultCases() {
		fmt.Fprintf(&calls, "case \"%d\": Fault%d()\n", index, index)
		fmt.Fprintf(&cDeclarations, "extern void Fault%d(void);\n", index)
		fmt.Fprintf(&cPointers, "Fault%d,\n", index)
	}
	dir := t.TempDir()
	goSource := "package main\nimport \"os\"\n" + declarations + "func main() { switch os.Args[1] {\n" + calls.String() + "} }\n"
	for name, content := range map[string]string{"go.mod": "module example.com/immediate-fault\n\ngo 1.20\n", "main.go": goSource, "fault_arm64.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	ctx, cancel := runtimeOracleStageContext(t)
	build := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", executable, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=arm64")
	if len(runner) != 0 {
		build.Env = append(build.Env, "GOOS=linux")
	}
	output, err := runtimeOracleCombinedOutput(ctx, build)
	cancel()
	if err != nil {
		t.Fatalf("original Go fault build: %v\n%s", err, output)
	}
	for index := range arm64ImmediateFaultCases() {
		args := runtimeOracleGuestArguments(t, runner, executable, fmt.Sprint(index))
		ctx, cancel = runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Env = append(os.Environ(), "GOTRACEBACK=single")
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || !strings.Contains(string(output), "SIGILL: illegal instruction") {
			t.Fatalf("original Go %s did not deliver SIGILL: %v\n%s", arm64ImmediateFaultCases()[index].text, err, output)
		}
	}
	cSource := fmt.Sprintf(`#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
%s
static void (*functions[])(void) = {%s};
int main(void) {
    struct rlimit no_core = {0,0};
    if (setrlimit(RLIMIT_CORE,&no_core)) return 1;
    for (unsigned i=0;i<sizeof(functions)/sizeof(functions[0]);i++) {
        pid_t child=fork();
        if (child<0) return 2;
        if (!child) { functions[i](); _exit(90); }
        int status;
        if (waitpid(child,&status,0)!=child || !WIFSIGNALED(status) || WTERMSIG(status)!=SIGILL) return 3;
    }
    return 0;
}
`, cDeclarations.String(), cPointers.String())
	for api, ir := range arm64ImmediateFaultIRs(t, target) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("immediate-fault-%d", api), target, ir, cSource, runner)
	}
}

func TestARM64GPImmediateOriginalEncoderVariant(t *testing.T) {
	primary, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	// This is an original-tool oracle, not a production encoder selector.
	// Both source versions have the same fixed 12-byte fallback. Only the
	// authenticated original Go primary source identifies its MOV expansion.
	modern := strings.Contains(string(primary), "bits.RotateLeft64")
	words := []uint32{0xd2801ffb, 0xf2a01ffb, 0xf2c01ffb, 0xd65f03c0}
	scratch, flags := uint64(0x000000ff00ff00ff), 4
	if modern {
		words = []uint32{0xb2009ffb, 0xf2801ffb, 0xeb1b03ff, 0xd65f03c0}
		scratch, flags = 0x00ff00ff00ff00ff, 1
	}
	var expected bytes.Buffer
	for _, word := range words {
		if err := binary.Write(&expected, binary.LittleEndian, word); err != nil {
			t.Fatal(err)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		actual := arm64ImmediateOriginalGoBytes(t, "TEXT variant(SB),4,$0-0\nCMP $0x00ff00ff00ff00ff,ZR\nRET\n", goos)
		if !bytes.Equal(actual, expected.Bytes()) {
			t.Fatalf("%s original encoder variant: got %x want %x", goos, actual, expected.Bytes())
		}
	}
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	source := `TEXT ·DivideRem(SB),4,$0-16
MOVD input+0(FP),R10
MOVD output+8(FP),R11
MOVD 0(R10),R0
CMP $5,R0
CMP $0x00ff00ff00ff00ff,ZR
MOVD R27,0(R11)
CSET MI,R2
CSET HS,R3
LSL $2,R3
ORR R3,R2
MOVD R2,8(R11)
CMP $5,R0
AND $0x00ff00ff00ff00ff,R0,ZR
MOVD R27,16(R11)
CSET MI,R2
CSET HS,R3
LSL $2,R3
ORR R3,R2
MOVD R2,24(R11)
RET
`
	goSource := fmt.Sprintf(`package main
import "fmt"
func DivideRem(input *[4]uint64, output *[4]uint64)
func main() {
    input := [4]uint64{17,0,0,0}
    initial := input
    output := struct { left uint64; values [4]uint64; right uint64 }{left:0x1234,right:0x5678}
    DivideRem(&input,&output.values)
    want := [4]uint64{%d,%d,%d,4}
    if input != initial || output.left != 0x1234 || output.right != 0x5678 || output.values != want {
        panic(fmt.Sprintf("original encoder state/canary got %%x want %%x",output.values,want))
    }
}
`, scratch, flags, scratch)
	runARM64LocalRegisterGoOracle(t, source, goSource, len(runner) != 0, "1.20")
	t.Logf("actual original Go modern=%v: exact fallback bytes, R27=%#x, CMP flags=%d; LLVM source without encoder identity remains Context", modern, scratch, flags)
}

func TestARM64GPImmediateCompleteGoOptabs(t *testing.T) {
	primary, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(primary)
	names := make(map[string]bool)
	for _, tc := range arm64ImmediateOracleCases() {
		names[tc.op] = true
	}
	for _, family := range []struct {
		name string
		rows int
	}{
		{"AADD", 14}, {"ACMP", 6}, {"AAND", 12}, {"AANDS", 12}, {"ATST", 6},
	} {
		pattern := `(?m)^\s*\{` + family.name + `, C_(?:ADDCON2?|MOVCON[23]?|BITCON|MBCON|VCON),[^\n]+`
		rows := regexp.MustCompile(pattern).FindAllString(source, -1)
		if len(rows) != family.rows {
			t.Fatalf("Go %s immediate rows changed: got %d want %d", family.name, len(rows), family.rows)
		}
		start := strings.Index(source, "case "+family.name+":")
		if start < 0 {
			t.Fatalf("Go alias registration missing: %s", family.name)
		}
		block := source[start+len("case "+family.name+":"):]
		if end := strings.Index(block, "\n\t\tcase "); end >= 0 {
			block = block[:end]
		}
		aliases := []string{strings.TrimPrefix(family.name, "A")}
		for _, match := range regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block, -1) {
			aliases = append(aliases, match[1])
		}
		for _, name := range aliases {
			if !names[name] {
				t.Fatalf("original Go alias lacks the actual numeric family: %s", name)
			}
			delete(names, name)
		}
	}
	if len(names) != 0 {
		t.Fatalf("numeric family names lack original Go registrations: %v", names)
	}
	for _, witness := range []string{"case 13:", "case 28:", "case 62:", "case 48:", "case 53:", "cannot use REGTMP as source", "C_ADDCON2"} {
		if !strings.Contains(source, witness) {
			t.Fatalf("Go immediate materialization contract changed: missing %q", witness)
		}
	}
}
