//go:build linux && (amd64 || arm64)

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86PackedShiftLinuxExecution(t *testing.T) []string {
	t.Helper()
	if runtime.GOARCH == "amd64" {
		return nil // Required native Linux/amd64 counterpart, not Darwin Rosetta.
	}
	qemu, err := exec.LookPath("qemu-x86_64")
	if err != nil {
		t.Fatal("required explicit QEMU x86 execution:", err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, qemu, "--version"))
	cancel()
	if err != nil || !strings.HasPrefix(string(output), "qemu-x86_64 version 10.2.3 ") {
		t.Fatalf("required QEMU10.2.3: %v\n%s", err, output)
	}
	t.Logf("explicit executable transport: %s -L /usr/x86_64-linux-gnu", qemu)
	return []string{qemu, "-L", "/usr/x86_64-linux-gnu"}
}

const x86PackedShiftLegacyMemoryGoDriver = `package main
import (
 "fmt"
 "os"
 "strconv"
 "unsafe"
)
func numeric(functions []func(unsafe.Pointer,unsafe.Pointer,unsafe.Pointer,uint64)) {
 limits:=[]uint64{0,1,7,15,16,17,31,32,33,63,64,65,255,256,1<<32,^uint64(0)}
 flags:=[3][5]byte{{1,0,1,0,1},{0,1,0,1,1},{0,0,0,0,0}}
 for kernel,fn:=range functions {
  for round,count:=range limits {
   for seed:=0;seed<3;seed++ {
    var data [18]byte
    var storage [96]byte
    var out [23]byte
    for i:=range data { data[i]=byte(i*71+round*97+13) }
    for i:=range storage { storage[i]=byte(i*31+7) }
    for i:=range out { out[i]=0xc3 }
    start:=uintptr(unsafe.Pointer(&storage[0]))
    offset:=int((16-start%16)%16)
    for i:=0;i<8;i++ { storage[offset+i]=byte(count>>(8*i)) }
    beforeData,beforeStorage:=data,storage
    fn(unsafe.Pointer(&out[1]),unsafe.Pointer(&data[1]),unsafe.Pointer(&storage[offset]),uint64(seed))
    if out[0]!=0xc3 || out[22]!=0xc3 || data!=beforeData || storage!=beforeStorage {
     panic("canary/input mutation")
    }
    for i:=0;i<5;i++ {
     if out[17+i]!=flags[seed][i] { panic("flags") }
    }
    bytes:=[]int{2,4,8,2,4,8}[kernel]
    for i:=0;i<16;i+=bytes {
     var value,want uint64
     for b:=0;b<bytes;b++ { value|=uint64(data[i+b+1])<<(8*b) }
     if count<uint64(bytes*8) {
      if kernel<3 { want=value<<count } else { want=value>>count }
     }
     for b:=0;b<bytes;b++ {
      if out[i+b+1]!=byte(want>>(8*b)) { panic("numeric") }
     }
    }
   }
  }
 }
}
func main() {
 functions:=[]func(unsafe.Pointer,unsafe.Pointer,unsafe.Pointer,uint64){legacycount0,legacycount1,legacycount2,legacycount3,legacycount4,legacycount5}
 if os.Args[1]=="numeric" { numeric(functions); return }
 index,err:=strconv.Atoi(os.Args[1])
 if err!=nil { panic(err) }
 var data,count [64]byte
 var out [23]byte
 for i:=range data {
  data[i]=byte(i*71+13)
  count[i]=byte(i*31+7)
 }
 for i:=range out { out[i]=0xc3 }
 start:=uintptr(unsafe.Pointer(&count[0]))
 offset:=(16-start%16)%16+1
 beforeData,beforeCount:=data,count
 fmt.Printf("original Go count mod16=%d\n",uintptr(unsafe.Pointer(&count[offset]))%16)
 functions[index](unsafe.Pointer(&out[1]),unsafe.Pointer(&data[1]),unsafe.Pointer(&count[offset]),0)
 if out[0]!=0xc3 || out[22]!=0xc3 || data!=beforeData || count!=beforeCount { panic("canary/input mutation") }
 flags:=[5]byte{1,0,1,0,1}
 for i:=0;i<5;i++ { if out[17+i]!=flags[i] { panic("flags") } }
 /* The initialized low count qword exceeds every lane width. */
 for i:=1;i<=16;i++ { if out[i]!=0 { panic("numeric") } }
 os.Exit(90)
}
`

func TestCrossLinuxRuntimeMatrixX86PackedShiftOriginalLegacyMemory(t *testing.T) {
	prefix := x86PackedShiftLinuxExecution(t)
	x86PackedShiftVerifyGuestArguments(t, prefix)
	_, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	observer := x86PackedShiftBuildOriginalCountObserver(t, x86PackedShiftLinuxCCompiler(t, clang))
	assembly, _ := x86PackedShiftLegacyMemoryAssembly()
	var declarations strings.Builder
	for i := range x86LegacyShiftMemoryOpcodes {
		fmt.Fprintf(&declarations, "func legacycount%d(out,data,count unsafe.Pointer,seed uint64)\n", i)
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":           "module originalcount\n\ngo 1.20\n",
		"main.go":          x86PackedShiftLegacyMemoryGoDriver + declarations.String(),
		"original_amd64.s": strings.ReplaceAll(assembly, "TEXT legacycount", "TEXT ·legacycount"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	executable := filepath.Join(dir, "original")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", executable, ".")
	command.Dir, command.Env = dir, env
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go body/link: %v\n%s", err, output)
	}
	ctx, cancel = runtimeOracleStageContext(t)
	argv := x86PackedShiftGuestExecution(prefix, executable, "numeric")
	command = exec.CommandContext(ctx, argv[0], argv[1:]...)
	output, err = runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go aligned numeric/flags: %v\n%s", err, output)
	}
	for i := range x86LegacyShiftMemoryOpcodes {
		ctx, cancel = runtimeOracleStageContext(t)
		argv = x86PackedShiftGuestExecution(prefix, observer, strconv.Itoa(i))
		command = exec.CommandContext(ctx, argv[0], argv[1:]...)
		reference, referenceErr := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		status, observationErr := x86PackedShiftCountObservation(i, reference, referenceErr)
		if observationErr != nil {
			t.Fatalf("original native opcode observer %d: %v\n%s", i, observationErr, reference)
		}
		ctx, cancel = runtimeOracleStageContext(t)
		argv := x86PackedShiftGuestExecution(prefix, executable, strconv.Itoa(i))
		command = exec.CommandContext(ctx, argv[0], argv[1:]...)
		output, err = runtimeOracleCombinedOutput(ctx, command)
		cancel()
		exit, pureExit := err.(*exec.ExitError)
		text := string(output)
		if !strings.Contains(text, "original Go count mod16=1") || !pureExit {
			t.Fatalf("original Go unaligned m128 count identity %d: %v\n%s", i, err, output)
		}
		if status == "normal" {
			if exit.ExitCode() != 90 {
				t.Fatalf("original Go differs from normal native opcode %d: %v\n%s", i, err, output)
			}
		} else if exit.ExitCode() != 2 || !strings.Contains(text, "main.legacycount") ||
			(!strings.Contains(text, "unexpected fault address") && !strings.Contains(text, "invalid memory address")) {
			t.Fatalf("original Go differs from native opcode memory fault %d: %v\n%s", i, err, output)
		}
		t.Logf("original Go/native opcode %s mod16=1 status=%s", x86LegacyShiftMemoryOpcodes[i].name, status)
	}
	t.Log("6 original Go m128 kernels ×48 numeric/flags/canary inputs and 6 independent native opcode unaligned status comparisons")
}

func x86PackedShiftVerifyGuestArguments(t *testing.T, prefix []string) {
	t.Helper()
	dir := t.TempDir()
	const source = `package main
import (
 "fmt"
 "os"
)
func main() { fmt.Printf("%q\n", os.Args) }
`
	for name, contents := range map[string]string{
		"go.mod": "module argumenttransport\n\ngo 1.20\n", "main.go": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "argument-transport")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go argument witness body/link: %v\n%s", err, output)
	}
	ctx, cancel = runtimeOracleStageContext(t)
	argv := append(append([]string(nil), prefix...), executable)
	command = exec.CommandContext(ctx, argv[0], argv[1:]...)
	output, err = runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil || string(output) != fmt.Sprintf("%q\n", []string{executable}) {
		t.Fatalf("guest no-argument witness: %v\n%s", err, output)
	}
	t.Logf("guest no-argument witness: %s", strings.TrimSpace(string(output)))
	arguments := []string{"first", "with space"}
	for _, repaired := range []bool{false, true} {
		argv := append(append([]string(nil), prefix...), executable)
		argv = append(argv, arguments...)
		want := append([]string{executable}, arguments...)
		if len(prefix) != 0 && !repaired {
			// The authenticated binfmt release treats the first argument as
			// original argv[0] even for ordinary explicit execution.
			want = arguments
		}
		if repaired {
			argv = x86PackedShiftGuestExecution(prefix, executable, arguments...)
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, argv[0], argv[1:]...)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil || string(output) != fmt.Sprintf("%q\n", want) {
			t.Fatalf("guest argument witness repaired=%t command=%q: %v\n%s; want %q",
				repaired, argv, err, output, fmt.Sprintf("%q\n", want))
		}
		t.Logf("guest argument witness repaired=%t: %s", repaired, strings.TrimSpace(string(output)))
	}
}

func TestCrossLinuxRuntimeMatrixX86PackedShiftLLVMNativeCount(t *testing.T) {
	prefix := x86PackedShiftLinuxExecution(t)
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	assembly, sigs := x86PackedShiftLegacyMemoryAssembly()
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "x86_64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	driver := x86PackedShiftLegacyCountCHeader + x86PackedShiftLegacyCountDeclarations() + x86PackedShiftOriginalCountC() +
		x86PackedShiftCountCChecks + x86PackedShiftLegacyNativeCountCMain
	compileAndRunRuntimeTestWithCompiler(t, llc, x86PackedShiftLinuxCCompiler(t, clang), "legacy_count_contract", triple, ir, driver, prefix)
	t.Log("6 original opcode/LLVM m128 kernels ×48 numeric/flags/canary inputs, 90 unaligned status comparisons and 6 original/LLVM full128 guard-page faults")
}

func x86PackedShiftLinuxCCompiler(t *testing.T, clang string) []string {
	t.Helper()
	if runtime.GOARCH == "amd64" {
		return []string{clang}
	}
	gcc, err := exec.LookPath("x86_64-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required AMD64 C/link driver:", err)
	}
	return []string{gcc, "-no-pie"}
}

func TestCrossLinuxRuntimeMatrixX86PackedShiftCompleteNumerical(t *testing.T) {
	prefix := x86PackedShiftLinuxExecution(t)
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	cases := x86PackedShiftNumericalCases()
	assembly, sigs := x86PackedShiftNumericalAssembly(cases)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "x86_64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	var driver strings.Builder
	driver.WriteString(x86PackedShiftIndependentC)
	for _, c := range cases {
		fmt.Fprintf(&driver, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint64_t);\n", c.name)
	}
	driver.WriteString("static const struct shift_case cases[]={\n")
	for _, c := range cases {
		fmt.Fprintf(&driver, "{%s,%q,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", c.name, c.row,
			c.width, c.bits, c.countMode, c.immediate, c.memory, c.maskMode, c.destination,
			x86ShiftBoolean(c.left), x86ShiftBoolean(c.legacy), x86ShiftBoolean(c.broadcast))
	}
	driver.WriteString(`};
int main(void) {
 for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
  if(check_case(&cases[i],(int)i)) return 1;
 }
 return 0;
}
`)
	compileAndRunRuntimeTestWithCompiler(t, llc, x86PackedShiftLinuxCCompiler(t, clang),
		"complete_packed_shift", triple, ir, driver.String(), prefix)
	t.Logf("%d exact LLVM programs ×192 independent whole-byte/flags/canary inputs", len(cases))
}
