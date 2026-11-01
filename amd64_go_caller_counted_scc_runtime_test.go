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

// Both existing required counted-loop runtime roots consume these fixtures.
// Their host/runner policy is unchanged; Rosetta remains diagnostic rather
// than evidence of native Linux execution or physical source-stack identity.
func x86CallerCountedSCCRuntimeFixtures(aliases ...string) (string, string, []string) {
	if len(aliases) == 0 {
		aliases = []string{"MOVQ"}
	}
	var source, assembly strings.Builder
	source.WriteString("package caller\nimport \"unsafe\"\n")
	var names []string
	for _, alias := range aliases {
		for _, raw := range []bool{false, true} {
			for _, diamond := range []bool{false, true} {
				name := fmt.Sprintf("scc%s%t%t", alias, raw, diamond)
				declaration := x86CallerCountedLoopScalarSource()
				declaration = declaration[strings.Index(declaration, "//go:noescape"):]
				declaration = strings.ReplaceAll(declaration, "kernel", name)
				source.WriteString(strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1))
				machine := x86SourceAliasCountedAssembly(x86CallerCountedSCCAssembly(raw, diamond), alias)
				assembly.WriteString(strings.ReplaceAll(machine, "·kernel", "·"+name))
				names = append(names, name)
			}
		}
	}
	return source.String(), assembly.String(), names
}

func runX86CallerCountedSCCOriginalValues(t *testing.T, aliases ...string) {
	source, assembly, names := x86CallerCountedSCCRuntimeFixtures(aliases...)
	var calls strings.Builder
	for index, name := range names {
		fmt.Fprintf(&calls, `
   {
    want := sum
    if %t {
     if x.data[bound] == 0 { want += 5 } else { want += 3 }
    }
    if got := Call%s(x.data[:length],y.data[:]); got != want ||
     snapshot(&x) != originalX || snapshot(&y) != originalY {
     t.Fatalf("%s length=%%d got=%%#x want=%%#x",length,got,want)
    }
    calls++
   }
`, index%2 == 1, name, name)
	}
	testSource := `package caller
import "testing"
type guardedInput struct { before [4]uint32; data [16]uint32; after [4]uint32 }
//go:noinline
func snapshot(input *guardedInput) guardedInput { return *input }
func TestOriginalSCCValues(t *testing.T) {
 calls := 0
 for repeat := 0; repeat < 4; repeat++ {
  for _, value := range []uint32{0,1,7,0x80000000,0xffffffff,0x12345678} {
   for length := 0; length < 16; length++ {
    x := guardedInput{
     before: [4]uint32{11,17,29,53},
     data: [16]uint32{value,0,value^0xaabbccdd,0,29,31,37,41,43,47,53,59,61,67,71,73},
     after: [4]uint32{0xaabbccdd,0x12345678,0x87654321,0xffffffff},
    }
    y := guardedInput{before:x.after,
     data:[16]uint32{31,37,value,43,47,53,59,61,67,71,73,79,83,89,97,101},after:x.before}
    originalX,originalY := snapshot(&x),snapshot(&y)
    bound := length & 3
    var sum uint32
    for index := 0; index < 2*bound; index++ { sum += x.data[index]+y.data[index] }
` + calls.String() + `
   }
  }
 }
` + fmt.Sprintf(" if calls != %d { t.Fatalf(\"calls=%%d\", calls) }\n", 384*len(names)) + `
}
`
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": source,
		"value_amd64.s": assembly, "value_test.go": testSource,
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
		t.Fatalf("first-party original Go serial SCC integer/canary oracle: %v\n%s", err, output)
	}
	t.Logf("%d original Go calls: two serial bounded loops, raw/named controls, both diamond arms, u32 wrap and complete guarded input snapshots", 384*len(names))
}

func runX86CallerCountedSCCLLVMValues(t *testing.T, aliases ...string) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	source, assembly, names := x86CallerCountedSCCRuntimeFixtures(aliases...)
	var oracle, calls strings.Builder
	oracle.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for index, name := range names {
		fmt.Fprintf(&oracle, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
		fmt.Fprintf(&calls, `
    {
     uint32_t want = sum;
     if (%d) want += x[bound] == 0 ? 5 : 3;
     memset(output,0xc9,sizeof(output)); memcpy(expected,output,sizeof(output));
     memcpy(expected+5,&want,sizeof(want));
     %s(a+1,b+3,output+5,&length);
     if (memcmp(output,expected,sizeof(output)) || memcmp(a,original_a,sizeof(a)) ||
         memcmp(b,original_b,sizeof(b)) || length != original_length) return 1;
     calls++;
    }
`, index%2, name)
	}
	oracle.WriteString(`int main(void) {
 const uint32_t values[]={0,1,7,0x80000000u,0xffffffffu,0x12345678u};
 unsigned calls=0;
 for (unsigned repeat=0;repeat<4;repeat++) {
  for (unsigned value=0;value<sizeof(values)/sizeof(values[0]);value++) {
   for (uint64_t length=0;length<16;length++) {
    uint32_t x[16]={values[value],0,values[value]^0xaabbccddu,0,29,31,37,41,43,47,53,59,61,67,71,73};
    uint32_t y[16]={31,37,values[value],43,47,53,59,61,67,71,73,79,83,89,97,101};
    uint8_t a[97],b[99],original_a[97],original_b[99],output[29],expected[29];
    memset(a,0xa3,sizeof(a)); memset(b,0xb7,sizeof(b));
    memcpy(a+1,x,sizeof(x)); memcpy(b+3,y,sizeof(y));
    memcpy(original_a,a,sizeof(a)); memcpy(original_b,b,sizeof(b));
    const uint64_t original_length=length;
    const unsigned bound=length&3;
    uint32_t sum=0;
    for (unsigned index=0;index<2*bound;index++) sum+=x[index]+y[index];
`)
	oracle.WriteString(calls.String())
	fmt.Fprintf(&oracle, "   }\n  }\n }\n return calls==%d?0:2;\n}\n", 384*len(names))
	goSource, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	pkg := x86CallerRuntimePackage(t, string(goSource), assembly)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
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
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compiler := []string{clang}
	if triple != testTargetTriple(runtime.GOOS, runtime.GOARCH) {
		compiler = append(compiler, "-target", triple)
	}
	for _, level := range []int{0, 2} {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "caller_counted_scc", triple, translation.Module.String(), oracle.String(), runner, level)
	}
	t.Logf("%d independent integer results plus full input/output canaries and immutable length; required Linux counterpart remains independently executable, Rosetta diagnostic is not native evidence", 384*len(names))
}
