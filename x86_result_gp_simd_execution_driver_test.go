package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86GPSIMDSparseOriginalDriver(fixture x86GPSIMDSparseExecutionFixture) string {
	var rows, seeds strings.Builder
	for _, row := range fixture.rows {
		fmt.Fprintf(&rows, "{%q,Seed%s,%d},\n", row.name, row.name, row.kind)
	}
	for _, seed := range x86GPSIMDSparseRuntimeSeeds {
		fmt.Fprintf(&seeds, "0x%x,", seed)
	}
	return `package main
import "fmt"
` + fixture.declarations + fixture.wrapperDeclarations + `
//go:noinline
func snapshot(p *[4]uint64) [4]uint64 {return *p}
func main() {
 rows:=[]struct{name string;call func(byte,uint64)(uint32,uint32);kind int}{
` + rows.String() + `}
 seeds:=[]uint64{` + seeds.String() + `}
 canaries:=[4]uint64{0x1122334455667788,0x8877665544332211,0xfedcba9876543210,0x123456789abcdef0}
 before:=snapshot(&canaries)
 hash:=uint64(1469598103934665603)
 positive,unknown,guards:=0,0,0
 for value:=0;value<256;value++ {for _,seed:=range seeds {for _,row:=range rows {
  c:=byte(value)
  got,guard:=row.call(c,seed)
  want,wantGuard:=uint32(c),uint32(0xa7a7a7a7)
  if row.kind==0 {want*=0x01010101}
  if row.kind==1 {wantGuard=0xa7a7a700|uint32(c)}
  if row.kind==3 {want=uint32(seed)&0xffffff00|uint32(c);unknown++}else{
   hash^=uint64(got);hash*=1099511628211;positive++
  }
  if got!=want||guard!=wantGuard||snapshot(&canaries)!=before {
   panic(fmt.Sprintf("%s c=%d seed=%x got=%x want=%x guard=%x wantGuard=%x",row.name,c,seed,got,want,guard,wantGuard))
  }
  guards++
 }}}
 fmt.Printf("GP/X positive checks=%d hash=%016x\n",positive,hash)
 fmt.Printf("original unknown overwrite=%d outgoing/caller guards=%d\n",unknown,guards)
}
`
}

func x86GPSIMDSparseLLVMDriver(fixture x86GPSIMDSparseExecutionFixture) string {
	var rows, declarations, seeds strings.Builder
	for _, row := range fixture.rows {
		if row.kind == 3 {
			continue // No LLVM exists for the independent original unknown file.
		}
		typ := "uint32_t"
		if row.kind == 1 {
			typ = "uint8_t"
		}
		fmt.Fprintf(&declarations, "extern %s %s(uint8_t);\n", typ, row.name)
		fmt.Fprintf(&rows, `{
 uint32_t got=%s(c),want=c;
 if(%d==0) want*=UINT32_C(0x01010101);
 if(got!=want||canaries[0]!=left||canaries[1]!=right){
  fprintf(stderr,"%s c=%%u seed=%%llx got=%%x want=%%x canary failure\n",c,(unsigned long long)seeds[s],got,want);return 1;
 }
 hash^=got;hash*=UINT64_C(1099511628211);calls++;
}
`, row.name, row.kind, row.name)
	}
	for _, seed := range x86GPSIMDSparseRuntimeSeeds {
		fmt.Fprintf(&seeds, "UINT64_C(0x%x),", seed)
	}
	return `#include <stdint.h>
#include <stdio.h>
` + declarations.String() + `
int main(void) {
 const uint64_t seeds[]={` + seeds.String() + `};
 uint64_t hash=UINT64_C(1469598103934665603);
 unsigned calls=0;
 for(unsigned value=0;value<256;value++)for(unsigned s=0;s<sizeof(seeds)/sizeof(seeds[0]);s++){
  uint8_t c=(uint8_t)value;
  uint64_t left=seeds[s]^UINT64_C(0x1122334455667788),right=seeds[s]^UINT64_C(0x8877665544332211);
  volatile uint64_t canaries[]={left,right};
` + rows.String() + `
 }
 printf("GP/X positive checks=%u hash=%016llx\n",calls,(unsigned long long)hash);
 printf("LLVM caller guards=%u\n",calls);
 return 0;
}
`
}

// Both native owners and an explicitly named execution-prefix diagnostic can
// share this oracle. The caller alone establishes which execution role it owns.
func x86GPSIMDSparseExecuteOriginalAndLLVM(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	op := "MOVD"
	if arch == "386" {
		op = "MOVL"
	}
	fixture := x86GPSIMDSparseExecutionFixtureFor(t, arch, []string{op})
	dir := t.TempDir()
	sources := map[string]string{
		"go.mod":                  "module sparsegpsimd\n\ngo 1.20\n",
		"main.go":                 x86GPSIMDSparseOriginalDriver(fixture),
		"positive_" + arch + ".s": fixture.positive,
		"negative_" + arch + ".s": fixture.negative,
		"callers_" + arch + ".s":  fixture.wrappers,
	}
	for name, source := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	goDriver, driverHash := x86LEAActualSDKDriver(t)
	command := exec.Command(goDriver, "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	verifyOriginal := func() {
		for name, source := range sources {
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(actual) != source {
				t.Fatal("complete original source changed", name, err)
			}
		}
		if actualDriver, actualHash := x86LEAActualSDKDriver(t); actualDriver != goDriver || actualHash != driverHash {
			t.Fatal("original source driver changed")
		}
	}
	verifyOriginal()
	t.Logf("original driver SHA256=%x positive=%x negative=%x callers=%x", driverHash,
		sha256.Sum256([]byte(fixture.positive)), sha256.Sum256([]byte(fixture.negative)), sha256.Sum256([]byte(fixture.wrappers)))
	want := x86GPSIMDSparseExecutionExpected(fixture)
	run := func(executable string) []byte {
		if arch != "386" {
			return execution.run(t, executable)
		}
		sealed, err := x87IA32StaticExecutable(executable)
		if err != nil {
			t.Fatal("actual i386 source needs its complete static ELF", err)
		}
		if len(execution.prefix) == 0 {
			return x87IA32RunDirect(t, sealed, nil, os.Environ())
		}
		// An explicitly separate prefix diagnostic may execute the same
		// sealed ELF, but it is not the required native owner above.
		if err := sealed.verify(); err != nil {
			t.Fatal(err)
		}
		output := execution.run(t, executable)
		if err := sealed.verify(); err != nil {
			t.Fatal(err)
		}
		return output
	}
	originalOutput := run(original)
	originalWant := want + "original unknown overwrite=1280 outgoing/caller guards=5120\n"
	if string(originalOutput) != originalWant {
		t.Fatalf("complete original Go high-byte/slot observation: got=%q want=%q", originalOutput, originalWant)
	}
	t.Logf("arch=%s original Go: %s", arch, strings.TrimSpace(string(originalOutput)))
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			badIR, err := x86ScalarFPBitViewAPI(t, fixture.negative, fixture.declarations, arch, execution.triple, api)
			if !errors.Is(err, ErrProbeNeedsContext) || badIR != "" {
				t.Fatal("actual original unknown-overwrite source gained a translated return", err)
			}
			ir, err := x86ScalarFPBitViewAPI(t, fixture.positive, fixture.declarations, arch, execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete sparse source failed to translate", err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, input)
					}
					executable := execution.compileLLVM(t, "sparse-gp-x", input, x86GPSIMDSparseLLVMDriver(fixture), level)
					output := run(executable)
					if string(output) != want+"LLVM caller guards=3840\n" {
						t.Fatal("LLVM byte/result/canary oracle differs from original Go:", string(output))
					}
					t.Logf("arch=%s original/LLVM common: %s", arch, strings.TrimSpace(want))
				})
			}
		})
	}
	verifyOriginal()
}
