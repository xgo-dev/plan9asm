package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86BitScanOriginalExecutionDriver(t *testing.T, fixture x86BitScanExecutionFixture) string {
	t.Helper()
	typ := "uint64"
	if fixture.arch == "386" {
		typ = "uint32"
	}
	var registrations, inputs, priors strings.Builder
	for _, row := range fixture.rows {
		public, observe := "Guard"+row.name, "nil"
		if row.role >= 3 {
			public, observe = "nil", row.name
		}
		fmt.Fprintf(&registrations, "{%s,%s,%d},\n", public, observe, row.role)
	}
	for _, value := range x86BitScanExecutionValues {
		fmt.Fprintf(&inputs, "0x%x,", value)
	}
	for _, prior := range x86BitScanExecutionPriors {
		fmt.Fprintf(&priors, "0x%x,", prior)
	}
	source := `package main
	import "fmt"
` + fixture.declarations + fixture.observerDeclarations + fixture.callerDeclarations + `
type word = ` + typ + `
//go:noinline
func snapshot(p *[4]word) [4]word { return *p }
func main() {
 rows:=[]struct{public func(*[4]word,word,word,uint32,uint32);observe func(*[4]word,word,word,word);role int}{
` + registrations.String() + `}
 inputs:=[]uint64{` + inputs.String() + `}
 priors:=[]uint64{` + priors.String() + `}
 for _,x:=range inputs {for _,prior:=range priors {for status:=0;status<64;status++ {
  seed:=uint64(0)
  for bit,position:=range []uint{0,2,4,6,7,11}{seed|=uint64(status>>bit&1)<<position}
  for _,row:=range rows {
   left,right:=word(uint64(0x1122334455667788)^seed),word(uint64(0x8877665544332211)^prior)
   guards:=[4]word{left,0,0,right}
   before:=snapshot(&guards)
   var value,flags word
   if row.role<3 {
    row.public(&guards,word(x),word(prior),uint32(seed),uint32(prior))
    if guards[2]!=1{panic("original ABI0 argument/result-adjacent outgoing guards modified")}
    value=guards[1]
   }else{
    row.observe(&guards,word(x),word(prior),word(seed))
    value,flags=guards[1],guards[2]&2261
   }
   after:=snapshot(&guards)
   if after[0]!=before[0]||after[3]!=before[3]{panic("original observer result-array boundary modified")}
   fmt.Printf("%016x %04x\n",uint64(value),uint64(flags))
  }
 }}}
}
`
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal("original driver must be complete actual Go source", err)
	}
	return string(formatted)
}

// A test-private view of the compiler's physical helper, never a Go source or
// Options capability. Public numerical functions still expose portable ZF only.
func x86BitScanExecutionStatusShim(t *testing.T, fixture x86BitScanExecutionFixture, ir string) string {
	t.Helper()
	word := 64
	if fixture.arch == "386" {
		word = 32
	}
	var output strings.Builder
	for _, row := range fixture.rows {
		if row.role < 3 {
			continue
		}
		spec := x86ScalarBitScanSpecs[Op(row.op)]
		helper := x86BitScanHelperName("__plan9asm_bitscan_0_", fixture.arch, Op(row.op))
		if !strings.Contains(ir, "@"+helper+"(") {
			t.Fatal("test status shim needs this actual module's internal helper", helper)
		}
		fmt.Fprintf(&output, "define void @%s(ptr %%out, i%d %%x, i%d %%prior, i%d %%seed) {\nentry:\n", row.name, word, word, word)
		input := "%x"
		if spec.bits != word {
			fmt.Fprintf(&output, "  %%input = trunc i%d %%x to i%d\n", word, spec.bits)
			input = "%input"
		}
		prior := "%prior"
		if row.role == 4 {
			prior = "%x"
		}
		fmt.Fprintf(&output, "  %%result = call { i%d, i%d } @%s(i%d %s, i%d %s, i%d %%seed)\n", word, word, helper, spec.bits, input, word, prior, word)
		fmt.Fprintf(&output, "  %%value = extractvalue { i%d, i%d } %%result, 0\n  %%flags = extractvalue { i%d, i%d } %%result, 1\n", word, word, word, word)
		fmt.Fprintf(&output, "  %%valuep = getelementptr i%d, ptr %%out, i32 1\n  %%flagsp = getelementptr i%d, ptr %%out, i32 2\n", word, word)
		fmt.Fprintf(&output, "  store i%d %%value, ptr %%valuep\n  store i%d %%flags, ptr %%flagsp\n  ret void\n}\n", word, word)
	}
	return ir + "\n" + output.String()
}

func x86BitScanLLVMExecutionDriver(fixture x86BitScanExecutionFixture) string {
	typ, stack := "uint64_t", "movq %%rsp,%0"
	if fixture.arch == "386" {
		typ, stack = "uint32_t", "movl %%esp,%0"
	}
	var declarations, registrations, inputs, priors strings.Builder
	for _, row := range fixture.rows {
		public, observe := row.name, "NULL"
		if row.role >= 3 {
			public, observe = "NULL", row.name
			fmt.Fprintf(&declarations, "extern void %s(word*,word,word,word);\n", row.name)
		} else {
			fmt.Fprintf(&declarations, "extern word %s(word,word,uint32_t,uint32_t);\n", row.name)
		}
		fmt.Fprintf(&registrations, "{%s,%s,%d},\n", public, observe, row.role)
	}
	for _, value := range x86BitScanExecutionValues {
		fmt.Fprintf(&inputs, "UINT64_C(0x%x),", value)
	}
	for _, prior := range x86BitScanExecutionPriors {
		fmt.Fprintf(&priors, "UINT64_C(0x%x),", prior)
	}
	return `#include <stdint.h>
#include <stdio.h>

typedef ` + typ + ` word;

static __attribute__((always_inline)) inline uintptr_t stack_pointer(void) {
    uintptr_t value;
    __asm__ volatile("` + stack + `" : "=r"(value) : : "memory");
    return value;
}

` + declarations.String() + `
static const struct {
    word (*public)(word, word, uint32_t, uint32_t);
    void (*observe)(word *, word, word, word);
    int role;
} rows[] = {
` + registrations.String() + `};

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;

    FILE *reference = fopen(argv[1], "r");
    if (!reference)
        return 2;

    const uint64_t inputs[] = {` + inputs.String() + `},
        priors[] = {` + priors.String() + `};
    unsigned checks = 0;

    for (unsigned x = 0; x < sizeof(inputs) / sizeof(inputs[0]); x++)
        for (unsigned p = 0; p < sizeof(priors) / sizeof(priors[0]); p++)
            for (unsigned status = 0; status < 64; status++) {
                uint64_t seed = 0;
                const unsigned positions[] = {0, 2, 4, 6, 7, 11};
                for (unsigned bit = 0; bit < 6; bit++)
                    seed |= ((status >> bit) & 1u) << positions[bit];

                for (unsigned r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
                    const word left = (word)(UINT64_C(0x1122334455667788) ^ seed),
                        right = (word)(UINT64_C(0x8877665544332211) ^ priors[p]);
                    volatile word guards[] = {left, 0, 0, right};
                    word value = 0, flags = 0;
                    const uintptr_t stackBefore = stack_pointer();

                    if (rows[r].role < 3)
                        value = rows[r].public((word)inputs[x], (word)priors[p],
                                              (uint32_t)seed, (uint32_t)priors[p]);
                    else {
                        rows[r].observe((word *)guards, (word)inputs[x],
                                        (word)priors[p], (word)seed);
                        value = guards[1];
                        flags = guards[2] & 2261u;
                    }

                    const uintptr_t stackAfter = stack_pointer();
                    unsigned long long expectedValue = 0, expectedFlags = 0;
                    if (fscanf(reference, "%llx %llx", &expectedValue, &expectedFlags) != 2 ||
                        (uint64_t)value != expectedValue ||
                        (uint64_t)flags != expectedFlags ||
                        guards[0] != left || guards[3] != right ||
                        stackBefore != stackAfter) {
                        fprintf(stderr,
                            "bit-scan row=%u x=%llx prior=%llx seed=%llx value=%llx flags=%llx original=%llx/%llx SP=%llx/%llx or result-array boundary mismatch\n",
                            r, (unsigned long long)inputs[x],
                            (unsigned long long)priors[p], (unsigned long long)seed,
                            (unsigned long long)value, (unsigned long long)flags,
                            expectedValue, expectedFlags,
                            (unsigned long long)stackBefore,
                            (unsigned long long)stackAfter);
                        fclose(reference);
                        return 3;
                    }
                    checks++;
                }
            }

    unsigned long long extraValue, extraFlags;
    if (fscanf(reference, "%llx %llx", &extraValue, &extraFlags) != EOF) {
        fclose(reference);
        return 4;
    }
    if (fclose(reference))
        return 5;

    printf("bit-scan original/LLVM NUM+six-status+canaries checks=%u\n", checks);
    return 0;
}
`
}

func x86BitScanExecuteOriginalAndLLVM(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	if execution.triple != triple || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("native bit-scan oracle needs exact direct Linux transport")
	}
	fixture := x86BitScanExecutionFixtureFor(t, arch)
	dir := t.TempDir()
	sources := map[string]string{
		"go.mod":                 "module bitscanexec\n\ngo 1.20\n",
		"main.go":                x86BitScanOriginalExecutionDriver(t, fixture),
		"public_" + arch + ".s":  fixture.public,
		"status_" + arch + ".s":  fixture.observers,
		"callers_" + arch + ".s": fixture.callers,
	}
	for name, source := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("original complete source=%s SHA256=%x", name, sha256.Sum256([]byte(source)))
	}
	original := filepath.Join(dir, "original")
	driver, driverHash := x86LEAActualSDKDriver(t)
	command := exec.Command(driver, "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	verifyOriginal := func() {
		for name, source := range sources {
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(actual) != source {
				t.Fatal("complete original input changed", name, err)
			}
		}
		if actualDriver, actualHash := x86LEAActualSDKDriver(t); actualDriver != driver || actualHash != driverHash {
			t.Fatal("original source driver changed")
		}
	}
	run := func(executable string, arguments ...string) []byte {
		if arch != "386" {
			return execution.run(t, executable, arguments...)
		}
		sealed, err := x87IA32StaticExecutable(executable)
		if err != nil {
			t.Fatal("native bit-scan i386 needs a complete static ELF", err)
		}
		return x87IA32RunDirect(t, sealed, arguments, os.Environ())
	}
	verifyOriginal()
	observations := run(original)
	if err := x86BitScanExecutionCheckRecords(fixture, observations); err != nil {
		t.Fatal("original hardware destination/ZF/whole observation failed", err)
	}
	reference := filepath.Join(dir, "original.records")
	if err := os.WriteFile(reference, observations, 0600); err != nil {
		t.Fatal(err)
	}
	verifyRecords := func() {
		actual, err := os.ReadFile(reference)
		if err != nil || string(actual) != string(observations) {
			t.Fatal("original records changed around LLVM observation", err)
		}
	}
	count := len(fixture.rows) * len(x86BitScanExecutionValues) * len(x86BitScanExecutionPriors) * 64
	want := fmt.Sprintf("bit-scan original/LLVM NUM+six-status+canaries checks=%d\n", count)
	t.Logf("native original Go arch=%s records=%d driver=%x output=%x", arch, count, driverHash, sha256.Sum256(observations))
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, fixture.public, fixture.declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete original numerical source failed", err)
			}
			ir = x86BitScanExecutionStatusShim(t, fixture, ir)
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, input)
					}
					executable := execution.compileLLVM(t, "bitscan", input, x86BitScanLLVMExecutionDriver(fixture), level)
					verifyRecords()
					if output := run(executable, reference); string(output) != want {
						t.Fatal("native original-Go/LLVM destination/status/canary disagreement", string(output))
					}
					verifyRecords()
					verifyOriginal()
				})
			}
		})
	}
	verifyOriginal()
	verifyRecords()
}

func TestX86ScalarBitScanExecutionPhysicalStatusShimKeepsPublicRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		fixture := x86BitScanExecutionFixtureFor(t, arch)
		// Parse the complete original Go driver without building or executing.
		x86BitScanOriginalExecutionDriver(t, fixture)
		for _, api := range []string{"text", "module", "Go"} {
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			ir, err := x86ScalarFPBitViewAPI(t, fixture.public, fixture.declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal(err)
			}
			shim := x86BitScanExecutionStatusShim(t, fixture, ir)
			ctx := llvm.NewContext()
			module, err := parseIRModuleInContext(ctx, shim)
			if !module.IsNil() {
				module.Dispose()
			}
			ctx.Dispose()
			if err != nil {
				t.Fatal("test-private complete shim IR malformed", err)
			}
			if strings.Contains(ir, "@Observe") || strings.Count(shim, "define void @Observe") != len(fixture.rows)*2/5 {
				t.Fatal("physical observer leaked into ordinary public NUM module")
			}
		}
	}
}

func TestX86ScalarBitScanExecutionStatusObservationDoesNotAuthorizePublicFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		fixture := x86BitScanExecutionFixtureFor(t, arch)
		typ, move, word, triple := "uint64", "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			typ, move, word, triple = "uint32", "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for _, row := range fixture.rows {
			if row.role != 0 {
				continue
			}
			for _, consumer := range []string{"SETCS ret+RESULT(FP)", "SETPS ret+RESULT(FP)", "SETMI ret+RESULT(FP)", "SETOS ret+RESULT(FP)", "LAHF\nMOVB AH,ret+RESULT(FP)"} {
				declaration := fmt.Sprintf("func view(x,prior %s) byte\n", typ)
				body := fmt.Sprintf("%s x+0(FP),AX\n%s prior+%d(FP),BX\n%s AX,BX\n%s", move, move, word, row.op, consumer)
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+row.op+"/"+consumer+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("test-only physical flag shim granted public nonportable flag permission", err)
						}
					})
				}
			}
		}
	}
}
