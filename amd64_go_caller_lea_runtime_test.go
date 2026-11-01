package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86CallerLEARuntimeForm struct {
	name, suffix string
	bits, scale  int
}

func x86CallerLEARuntimeForms() []x86CallerLEARuntimeForm {
	var forms []x86CallerLEARuntimeForm
	for _, width := range []struct {
		suffix string
		bits   int
	}{{"W", 16}, {"L", 32}, {"Q", 64}} {
		for _, scale := range []int{1, 2, 4, 8} {
			forms = append(forms, x86CallerLEARuntimeForm{
				name: fmt.Sprintf("kernel%s%d", width.suffix, scale), suffix: width.suffix,
				bits: width.bits, scale: scale,
			})
		}
	}
	return forms
}

func x86CallerLEARuntimeSources() (goSource, assembly, goTest, cOracle string) {
	var declarations, machine, tests, c strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	tests.WriteString(`package caller
import "testing"
func TestOriginalLEAMathematics(t *testing.T) {
 values := []uint64{0, 1, 7, 19, 65535, 1<<16, 1<<31, 1<<32-1, 1<<32, 1<<63, ^uint64(0)}
`)
	c.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for _, form := range x86CallerLEARuntimeForms() {
		fmt.Fprintf(&declarations, `
//go:noescape
func %[1]s(a, b, res, length unsafe.Pointer)
func Call%[1]s(x, y []uint64) uint64 {
 var res uint64
 length := len(x)
 %[1]s(unsafe.Pointer(unsafe.SliceData(x)), unsafe.Pointer(unsafe.SliceData(y)),
  unsafe.Pointer(&res), unsafe.Pointer(&length))
 return res
}
`, form.name)
		fmt.Fprintf(&machine, `TEXT ·%s(SB),4,$0-32
MOVQ a+0(FP),DI
MOVQ b+8(FP),SI
MOVQ res+16(FP),DX
MOVQ length+24(FP),CX
BYTE $0x55
WORD $0x8948
BYTE $0xe5
LONG $0xf8e48348
MOVQ (DI),R9
MOVQ (SI),BX
MOVQ $0x1122334455667788,AX
LEA%s -7(R9)(BX*%d),AX
MOVQ AX,(DX)
WORD $0x8948
BYTE $0xec
BYTE $0x5d
BYTE $0xc3
`, form.name, form.suffix, form.scale)
		fmt.Fprintf(&tests, `
 for _, x := range values {
  for _, y := range values {
   a, b := []uint64{x, 23}, []uint64{y, 37}
   canary := [4]uint64{11, 41, 53, 67}
   want := x + y*%[1]d - 7
`, form.scale)
		switch form.bits {
		case 16:
			tests.WriteString("   want = 0x1122334455660000 | uint64(uint16(want))\n")
		case 32:
			tests.WriteString("   want = uint64(uint32(want))\n")
		}
		fmt.Fprintf(&tests, `
   if got := Call%[1]s(a, b); got != want || a[0] != x || a[1] != 23 || b[0] != y || b[1] != 37 ||
    canary != [4]uint64{11, 41, 53, 67} {
    t.Fatalf("%[1]s x=%%#x y=%%#x got=%%#x want=%%#x", x, y, got, want)
   }
  }
 }
`, form.name)
		fmt.Fprintf(&c, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", form.name, form.name)
	}
	tests.WriteString("}\n")
	c.WriteString(`int main(void) {
 const uint64_t values[] = {0,1,7,19,65535,UINT64_C(1)<<16,UINT64_C(1)<<31,UINT32_MAX,
  UINT64_C(1)<<32,UINT64_C(1)<<63,UINT64_MAX};
`)
	for _, form := range x86CallerLEARuntimeForms() {
		fmt.Fprintf(&c, `
 for (unsigned i=0; i<sizeof(values)/sizeof(values[0]); i++) {
  for (unsigned j=0; j<sizeof(values)/sizeof(values[0]); j++) {
   uint8_t a[17], b[19], output[33], before[33];
   uint64_t x=values[i], y=values[j], length=1, got=0;
   memset(a,0xa3,sizeof(a)); memset(b,0xb7,sizeof(b));
   memcpy(a+1,&x,8); memcpy(b+3,&y,8);
   memset(output,0xc9,sizeof(output)); memcpy(before,output,sizeof(output));
   uint64_t want = x + y*%d - 7;
`, form.scale)
		switch form.bits {
		case 16:
			c.WriteString("   want = UINT64_C(0x1122334455660000) | (uint16_t)want;\n")
		case 32:
			c.WriteString("   want = (uint32_t)want;\n")
		}
		fmt.Fprintf(&c, `
   %s(a+1,b+3,output+5,&length);
   memcpy(&got,output+5,8); memcpy(before+5,&want,8);
   if (got!=want || memcmp(output,before,sizeof(output)) || length!=1) return 1;
   uint64_t after_x=0,after_y=0;
   memcpy(&after_x,a+1,8); memcpy(&after_y,b+3,8);
   if (after_x!=x || after_y!=y || a[0]!=0xa3 || a[9]!=0xa3 || b[2]!=0xb7 || b[11]!=0xb7) return 2;
  }
 }
`, form.name)
	}
	c.WriteString(" return 0;\n}\n")
	return declarations.String(), machine.String(), tests.String(), c.String()
}

func TestCrossLinuxRuntimeMatrixX86GoCallerLEAModuloAndCanaries(t *testing.T) {
	testX86CallerLEAModuloAndCanaries(t, false)
}

func TestCrossLinuxRuntimeMatrixX86RawLEADisplacementModuloAndCanaries(t *testing.T) {
	testX86CallerLEAModuloAndCanaries(t, true)
}

func testX86CallerLEAModuloAndCanaries(t *testing.T, raw bool) {
	t.Helper()
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("LEA execution requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	goSource, assembly, goTest, cOracle := x86CallerLEARuntimeSources()
	if raw {
		for _, form := range x86CallerLEARuntimeForms() {
			rex := byte(0x41) // numerical R9 base; destination AX, index BX.
			var encoding []byte
			if form.bits == 16 {
				encoding = append(encoding, 0x66)
			} else if form.bits == 64 {
				rex |= 8
			}
			scale := map[int]byte{1: 0, 2: 1, 4: 2, 8: 3}[form.scale]
			encoding = append(encoding, rex, 0x8d, 0x84, scale<<6|3<<3|1)
			encoding = binary.LittleEndian.AppendUint32(encoding, 0xfffffff9)
			named := fmt.Sprintf("LEA%s -7(R9)(BX*%d),AX", form.suffix, form.scale)
			if strings.Count(assembly, named) != 1 {
				t.Fatalf("raw LEA fixture lost its independent named form: %s", named)
			}
			assembly = strings.Replace(assembly, named, x86RawDisplacementDirectives(encoding), 1)
		}
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": goSource,
		"value_amd64.s": assembly, "value_test.go": goTest,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go LEA modulo/canary oracle: %v\n%s", err, output)
	}
	pkg := x86CallerRuntimePackage(t, goSource, assembly)
	llvmContext := llvm.NewContext()
	defer llvmContext.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(llvmContext, pkg, []byte(assembly), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "caller_lea", triple, translation.Module.String(), cOracle, runner)
}
