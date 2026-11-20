//go:build linux && amd64

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This required owner executes the complete original ABI0 bool-byte target
// through genuine Go callers and separate raw callers. LLVM crosses C only
// through explicit i1-to-i32 shims. It supplies no SDK/native-entry authority;
// local emulation cannot replace native Linux AMD64's kernel i386 counterpart.
func TestCrossLinuxRuntimeMatrixX86ABI0Mode32CanonicalBoolOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required LLVM22/i386 bool counterpart tools: llc=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu", compiler: []string{compiler, "-static", "-no-pie"}}
	rows := x86ABI0Mode32BoolRuntimeRows()
	assembly, invalid, declarations, observers, observerDecl := x86ABI0Mode32BoolRuntimeSource(rows)
	var calls, rawChecks, wrappers, prototypes, checks strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&calls, "if Bool%d()!=(%d!=0){panic(\"original Go bool caller row %d\")}; if Observe%d()!=(0x112233445a5a5a00|%d){panic(\"original raw bool byte/seven adjacent canaries row %d\")}; calls+=2\n", index, row.want, index, index, row.want, index)
		fmt.Fprintf(&wrappers, "\ndefine i32 @Probe%d() {\n %%v=call i1 @Bool%d()\n %%r=zext i1 %%v to i32\n ret i32 %%r\n}\n", index, index)
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(void);\n", index)
		fmt.Fprintf(&checks, "if(Probe%d()!=%d){fprintf(stderr,\"LLVM bool byte row %d\\n\");return 1;} calls++;\n", index, row.want, index)
	}
	for index, raw := range []int{2, 3, 255} {
		fmt.Fprintf(&rawChecks, "if Observe%d()!=(0x112233445a5a5a00|%d){panic(\"raw invalid bool representation normalized\")}; calls++\n", len(rows)+index, raw)
	}
	goDriver := "package main\nimport \"fmt\"\n" + declarations + observerDecl + "\nfunc main(){calls:=0\n" + calls.String() + rawChecks.String() + "fmt.Printf(\"original386 bool bytes/canaries: %d checks\\n\",calls)\n}\n"
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module boolbyte386\n\ngo 1.20\n", "main.go": goDriver,
		"bool_386.s": assembly, "invalid_386.s": invalid, "observer_386.s": observers} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	command := exec.Command("go", "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	originalProgram, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	wantOriginal := fmt.Sprintf("original386 bool bytes/canaries: %d checks\n", 2*len(rows)+3)
	if output := x87IA32RunDirect(t, originalProgram, nil, os.Environ()); string(output) != wantOriginal {
		t.Fatalf("incomplete original Go bool/raw representation axis: %s", output)
	}
	// Each original target member remains complete: the valid member and the
	// three invalid bool TEXTs are separate exact source fixtures. The observer
	// is an independent native Go caller driver, not a translated helper ABI.
	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewAPI(t, invalid, declarations, "386", execution.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Fatal("raw 2/3/255 byte controls acquired a logical bool transport", api, len(ir), err)
		}
	}
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + "\nint main(void){volatile uint32_t canary[2]={0x12345678,0x87654321};unsigned calls=0;\n" + checks.String() +
		"if(canary[0]!=0x12345678||canary[1]!=0x87654321)return 2;printf(\"LLVM386 canonical bool shims: %u checks\\n\",calls);return 0;}\n"
	wantLLVM := fmt.Sprintf("LLVM386 canonical bool shims: %d checks\n", len(rows))
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "386", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			executable := execution.compileLLVM(t, "canonical-abi0-bool-386", ir+wrappers.String(), driver, level)
			translatedProgram, err := x87IA32StaticExecutable(executable)
			if err != nil {
				t.Fatal(err)
			}
			output := x87IA32RunDirect(t, translatedProgram, nil, os.Environ())
			if string(output) != wantLLVM {
				t.Fatalf("incomplete %s/%s logical bool counterpart: %s", api, level, output)
			}
		}
	}
	t.Log("whole original Go target, actual ABI0 bool callers/raw bytes/seven adjacent canaries; 96 SETcc rows plus raw2/3/255 restoration; three APIs/O0/O2 integer-only LLVM shims. Not C _Bool or SDK-native-entry certification.")
	x87IA32RequireNativeHost(t)
}
