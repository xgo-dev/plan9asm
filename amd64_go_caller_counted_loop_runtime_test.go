package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86GoCallerCountedLoopOriginalInitializedValues(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 caller runtime counterpart")
	}
	runX86CallerCountedLoopOriginalValues(t, []string{"MOVQ"})
}

func runX86CallerCountedLoopOriginalValues(t *testing.T, aliases []string) {
	t.Helper()
	var source, assembly, calls strings.Builder
	source.WriteString("package caller\nimport \"unsafe\"\n")
	for _, alias := range aliases {
		for _, raw := range []bool{false, true} {
			for _, separateExit := range []bool{false, true} {
				name := fmt.Sprintf("counted%s%t%t", alias, raw, separateExit)
				declaration := x86CallerCountedLoopScalarSource()
				declaration = declaration[strings.Index(declaration, "//go:noescape"):]
				declaration = strings.ReplaceAll(declaration, "kernel", name)
				declaration = strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1)
				source.WriteString(declaration)
				machine := x86CallerCountedLoopScalarAssembly(raw)
				if separateExit {
					machine = x86CallerCountedLoopSeparateExitAssembly(raw)
				}
				machine = x86SourceAliasCountedAssembly(machine, alias)
				assembly.WriteString(strings.ReplaceAll(machine, "·kernel", "·"+name))
				fmt.Fprintf(&calls, `
 if got:=Call%s(x.data[:length],y.data[:]); got!=want ||
  snapshot(&x)!=originalX || snapshot(&y)!=originalY {
  t.Fatalf("%s length=%%d got=%%#x want=%%#x",length,got,want)
 }
`, name, name)
			}
		}
	}
	goTest := `package caller
import "testing"

type guardedInput struct {
 before [4]uint32
 data [16]uint32
 after [4]uint32
}

//go:noinline
func snapshot(input *guardedInput) guardedInput { return *input }

func TestOriginalInitializedCountedValues(t *testing.T) {
 for repeat:=0; repeat<4; repeat++ {
  for _, value:=range []uint32{0,1,7,0x80000000,0xffffffff,0x12345678} {
   for length:=0; length<16; length++ {
    x := guardedInput{
     before: [4]uint32{11,17,29,53},
     data: [16]uint32{value,value^0xaabbccdd,19,23,29,31,37,41,43,47,53,59,61,67,71,73},
     after: [4]uint32{0xaabbccdd,0x12345678,0x87654321,0xffffffff},
    }
    y := guardedInput{
     before: x.after,
     data: [16]uint32{31,37,value,43,47,53,59,61,67,71,73,79,83,89,97,101},
     after: x.before,
    }
    originalX,originalY:=snapshot(&x),snapshot(&y)
    var want uint32
    for index:=0;index<length&3;index++ { want+=x.data[index]+y.data[index] }
` + calls.String() + `
   }
  }
 }
}
`
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": source.String(),
		"value_amd64.s": assembly.String(), "value_test.go": goTest,
	} {
		bytes := []byte(content)
		if strings.HasSuffix(name, ".go") {
			var err error
			bytes, err = format.Source(bytes)
			if err != nil {
				t.Fatalf("format generated %s: %v", name, err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("first-party original Go counted integer/canary oracle: %v\n%s", err, output)
	}
	t.Logf("original Go scalar oracle: %d initialized calls; bound zero/one/two/three, u32 wrap, both shared/separate exits; noinline full-memory snapshots compare both data buffers and adjacent canaries, not a physical source-stack witness; Darwin/Rosetta is diagnostic, not Intel hardware evidence", 1536*len(aliases))
	t.Run("serial SCC composition", func(t *testing.T) { runX86CallerCountedSCCOriginalValues(t, aliases...) })
}

func TestCrossLinuxRuntimeMatrixX86GoCallerCountedLoopValuesAndMemoryCanaries(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 caller runtime counterpart")
	}
	runX86CallerCountedLoopLLVMValues(t, []string{"MOVQ"})
}

func runX86CallerCountedLoopLLVMValues(t *testing.T, aliases []string) {
	t.Helper()
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, assembly, oracle strings.Builder
	source.WriteString("package caller\nimport \"unsafe\"\n")
	oracle.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	var calls strings.Builder
	for _, alias := range aliases {
		for _, raw := range []bool{false, true} {
			for _, separateExit := range []bool{false, true} {
				name := fmt.Sprintf("counted%s%t%t", alias, raw, separateExit)
				declaration := x86CallerCountedLoopScalarSource()
				declaration = declaration[strings.Index(declaration, "//go:noescape"):]
				declaration = strings.ReplaceAll(declaration, "kernel", name)
				source.WriteString(strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1))
				machine := x86CallerCountedLoopScalarAssembly(raw)
				if separateExit {
					machine = x86CallerCountedLoopSeparateExitAssembly(raw)
				}
				machine = x86SourceAliasCountedAssembly(machine, alias)
				assembly.WriteString(strings.ReplaceAll(machine, "·kernel", "·"+name))
				fmt.Fprintf(&oracle, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
				fmt.Fprintf(&calls, `
    memset(output,0xc9,sizeof(output));memcpy(expected,output,sizeof(output));
    memcpy(expected+5,&want,sizeof(want));
    %s(a+1,b+3,output+5,&length);
    if (memcmp(output,expected,sizeof(output)) || memcmp(a,original_a,sizeof(a)) ||
        memcmp(b,original_b,sizeof(b)) || length!=original_length) return 1;
    calls++;
`, name)
			}
		}
	}
	oracle.WriteString(`int main(void) {
 const uint32_t values[]={0,1,7,0x80000000u,0xffffffffu,0x12345678u};
 unsigned calls=0;
 for (unsigned repeat=0;repeat<4;repeat++) {
  for (unsigned value=0;value<sizeof(values)/sizeof(values[0]);value++) {
   for (uint64_t length=0;length<16;length++) {
    uint32_t x[16]={values[value],values[value]^0xaabbccddu,19,23,29,31,37,41,43,47,53,59,61,67,71,73};
    uint32_t y[16]={31,37,values[value],43,47,53,59,61,67,71,73,79,83,89,97,101};
    uint8_t a[97],b[99],original_a[97],original_b[99],output[29],expected[29];
    memset(a,0xa3,sizeof(a));memset(b,0xb7,sizeof(b));
    memcpy(a+1,x,sizeof(x));memcpy(b+3,y,sizeof(y));
    memcpy(original_a,a,sizeof(a));memcpy(original_b,b,sizeof(b));
    const uint64_t original_length=length;
    uint32_t want=0;
    for (unsigned index=0;index<(length&3);index++) want+=x[index]+y[index];
`)
	oracle.WriteString(calls.String())
	fmt.Fprintf(&oracle, "   }\n  }\n }\n return calls==%d?0:2;\n}\n", 1536*len(aliases))
	goSource, err := format.Source([]byte(source.String()))
	if err != nil {
		t.Fatal(err)
	}
	pkg := x86CallerRuntimePackage(t, string(goSource), assembly.String())
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if translation != nil && !translation.Module.IsNil() {
		defer translation.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compiler := []string{clang}
	if triple != testTargetTriple(runtime.GOOS, runtime.GOARCH) {
		compiler = append(compiler, "-target", triple)
	}
	for _, level := range []int{0, 2} {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "caller_counted_loop", triple, translation.Module.String(), oracle.String(), runner, level)
	}
	t.Logf("%d independent unsigned mathematical results; both input buffers and all output/adjacent guard bytes unchanged, length immutable; Rosetta is diagnostic only", 1536*len(aliases))
	t.Run("serial SCC composition", func(t *testing.T) { runX86CallerCountedSCCLLVMValues(t, aliases...) })
}
