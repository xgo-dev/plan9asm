//go:build linux && amd64

package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Only quiet NaNs are included: their sign/payload must survive this exact
// FLD/FRNDINT/FSTP path. Signaling-NaN quieting is a different observation.
var x86ScopedRoundingInputs = []uint64{
	0, 0x8000000000000000, 1, 0x8000000000000001,
	0x3fe0000000000000, 0xbfe0000000000000,
	0x3ff8000000000000, 0xbff8000000000000,
	0x4004000000000000, 0xc004000000000000,
	0x400e000000000000, 0xc00e000000000000,
	0x432fffffffffffff, 0xc32fffffffffffff,
	0x4330000000000000, 0xc330000000000000,
	0x7fefffffffffffff, 0xffefffffffffffff,
	0x7ff0000000000000, 0xfff0000000000000,
	0x7ff8000000000001, 0xfff8000000004321,
}

func TestCrossLinuxRuntimeMatrixX86X87ScopedRoundingOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, _, found := findLlcAndClang(t)
	compiler, compilerErr := exec.LookPath("i686-linux-gnu-gcc")
	if !found || compilerErr != nil {
		t.Fatal("scoped rounding requires LLVM22 and the static native i386 toolchain", compilerErr)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie", "-maccumulate-outgoing-args"}}
	source, declarations := x86ScopedRoundingBundle(t)
	rows := x86ScopedRoundingCases()
	if len(rows) != 5*7*2 {
		t.Fatal("native scope inventory must retain five spellings, seven GP registers and both word layouts", len(rows))
	}
	dir := t.TempDir()
	goDriver, observers := x86ScopedRoundingOriginalDriver(t)
	sources := map[string]string{
		"go.mod": "module scopedrounding\n\ngo 1.20\n", "main.go": goDriver,
		"rounding_386.s": source, "observe_386.s": observers,
	}
	for name, contents := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("complete original input=%s sha256=%x", name, sha256.Sum256([]byte(contents)))
	}
	goTool, toolHash := x86LEAActualSDKDriver(t)
	verifySource := func() {
		for name, contents := range sources {
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(actual) != contents {
				t.Fatal("complete original scoped-rounding source changed", name, err)
			}
		}
		if actual, hash := x86LEAActualSDKDriver(t); actual != goTool || hash != toolHash {
			t.Fatal("original scoped-rounding Go tool changed")
		}
	}
	original := filepath.Join(dir, "original")
	environment := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOOS=linux", "GOARCH=386", "CGO_ENABLED=0", "GOFLAGS=", "GOEXPERIMENT=", "GOMAXPROCS=2")
	verifySource()
	output, err := x87IA32Capture(t, goTool, []string{"build", "-p=1", "-o", original, "."}, dir, environment)
	if err != nil || len(output) != 0 {
		t.Fatalf("complete original Go scoped-rounding build failed: %v\n%s", err, output)
	}
	run := func(path string, args ...string) []byte {
		sealed, err := x87IA32StaticExecutable(path)
		if err != nil {
			t.Fatal("scoped rounding requires direct static ELF32 execution", err)
		}
		return x87IA32RunDirect(t, sealed, args, os.Environ())
	}
	verifySource()
	records := run(original)
	x86ScopedRoundingCheckRecords(t, records)
	reference := filepath.Join(dir, "original.records")
	if err := os.WriteFile(reference, records, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual original scoped-rounding records sha256=%x", sha256.Sum256(records))
	verifyRecords := func() {
		actual, err := os.ReadFile(reference)
		if err != nil || string(actual) != string(records) {
			t.Fatal("original scoped-rounding records changed", err)
		}
	}
	want := fmt.Sprintf("scoped rounding original-Go/LLVM checks=%d\n", len(rows)*4*len(x86ScopedRoundingInputs))
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, "386", execution.triple, api, X87Hardware)
			if err != nil || ir == "" {
				t.Fatal("complete original scoped-rounding source cannot translate", api, err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, input)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
						executable := execution.compileLLVM(t, "scoped-rounding", input, x86ScopedRoundingNativeDriver(), level)
						verifySource()
						verifyRecords()
						if actual := run(executable, reference); string(actual) != want {
							t.Fatal("scoped rounding values, CW, SP or complete inventory differ", string(actual))
						}
						verifyRecords()
						verifySource()
					})
				}
			}
		})
	}
	x87IA32RequireNativeHost(t)
}

func x86ScopedRoundingOriginalDriver(t *testing.T) (string, string) {
	t.Helper()
	var driver, observers, calls strings.Builder
	driver.WriteString("package main\nimport \"fmt\"\n")
	observers.WriteString("#include \"funcdata.h\"\n")
	for index, row := range x86ScopedRoundingCases() {
		driver.WriteString(row.declaration)
		fmt.Fprintf(&driver, "func Observe%d(input uint64, control uint32) (bits uint64, before, after uint32)\n", index)
		fmt.Fprintf(&calls, "Observe%d,\n", index)
		// A normal small split caller, not a new backing contract for the
		// leaf: no SP rewriting, no source modification and no large reserve.
		fmt.Fprintf(&observers, `TEXT ·Observe%d(SB),0,$32-28
NO_LOCAL_POINTERS
MOVL input+0(FP),AX
MOVL input_hi+4(FP),DX
MOVL AX,0(SP)
MOVL DX,4(SP)
FSTCW saved-2(SP)
MOVL control+8(FP),CX
MOVW CX,selected-4(SP)
FLDCW selected-4(SP)
FSTCW beforeCW-6(SP)
CALL ·%s(SB)
FSTCW afterCW-8(SP)
FLDCW saved-2(SP)
MOVL 8(SP),AX
MOVL 12(SP),DX
MOVL AX,bits+12(FP)
MOVL DX,bits_hi+16(FP)
MOVWLZX beforeCW-6(SP),AX
MOVL AX,before+20(FP)
MOVWLZX afterCW-8(SP),AX
MOVL AX,after+24(FP)
RET
`, index, row.name)
	}
	driver.WriteString("func main() {\ninputs := []uint64{\n")
	for _, input := range x86ScopedRoundingInputs {
		fmt.Fprintf(&driver, "0x%016x,\n", input)
	}
	driver.WriteString("}\nfunctions := []func(uint64,uint32)(uint64,uint32,uint32){\n" + calls.String() + "}\n")
	driver.WriteString(`for row, call := range functions {
    for ambient := 0; ambient < 4; ambient++ {
        control := uint32(0x037f | ambient<<10)
        for _, input := range inputs {
            value, before, after := call(input, control)
            if before != control || after != control {
                panic(fmt.Sprintf("original CW row=%d before=%04x after=%04x want=%04x", row,before,after,control))
            }
            fmt.Printf("%d %d %016x %04x %04x %016x\n", row,ambient,input,before,after,value)
        }
    }
}
}
`)
	formatted, err := format.Source([]byte(driver.String()))
	if err != nil {
		t.Fatal("original scoped-rounding driver is malformed", err)
	}
	return string(formatted), observers.String()
}

func x86ScopedRoundingCheckRecords(t *testing.T, records []byte) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(records), "\n"), "\n")
	want := len(x86ScopedRoundingCases()) * 4 * len(x86ScopedRoundingInputs)
	if !strings.HasSuffix(string(records), "\n") || len(lines) != want {
		t.Fatal("original scoped-rounding inventory is incomplete", len(lines), want)
	}
	index := 0
	for row := range x86ScopedRoundingCases() {
		for ambient := 0; ambient < 4; ambient++ {
			for _, input := range x86ScopedRoundingInputs {
				var actualRow, actualAmbient int
				var actualInput, before, after, value uint64
				count, err := fmt.Sscanf(lines[index], "%d %d %x %x %x %x", &actualRow, &actualAmbient, &actualInput, &before, &after, &value)
				control := uint64(0x037f | ambient<<10)
				canonical := fmt.Sprintf("%d %d %016x %04x %04x %016x", row, ambient, input, control, control, value)
				if err != nil || count != 6 || actualRow != row || actualAmbient != ambient || actualInput != input ||
					before != control || after != control || lines[index] != canonical {
					t.Fatal("original record lost its exact input/control/order", index, lines[index], err)
				}
				index++
			}
		}
	}
}

func x86ScopedRoundingNativeDriver() string {
	var driver, functions, modes, inputs strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	for _, row := range x86ScopedRoundingCases() {
		fmt.Fprintf(&driver, "extern double %s(double);\n", row.name)
		fmt.Fprintf(&functions, "%s,\n", row.name)
		fmt.Fprintf(&modes, "%d,", row.mode)
	}
	for _, input := range x86ScopedRoundingInputs {
		fmt.Fprintf(&inputs, "UINT64_C(0x%016x),\n", input)
	}
	driver.WriteString("static double (*const functions[])(double)={\n" + functions.String() + "};\n")
	driver.WriteString("static const unsigned modes[]={" + modes.String() + "};\n")
	driver.WriteString("static const uint64_t inputs[]={\n" + inputs.String() + "};\n")
	driver.WriteString(`
/* An integer IEEE-754 oracle: ambient x87 RC cannot change its arithmetic. */
static uint64_t expected_bits(uint64_t bits, unsigned mode) {
    const uint64_t sign=bits&UINT64_C(0x8000000000000000);
    const uint64_t magnitude=bits&UINT64_C(0x7fffffffffffffff);
    const unsigned exponent=(unsigned)(magnitude>>52);
    if (!magnitude || exponent>=1075)
        return bits; /* Also retain both infinities and quiet-NaN payloads. */
    if (exponent<1023) {
        const int increment=mode==0 ? magnitude>UINT64_C(0x3fe0000000000000) :
            mode==1 ? sign!=0 : mode==2 ? sign==0 : 0;
        return sign|(increment?UINT64_C(0x3ff0000000000000):0);
    }
    const unsigned shift=1075-exponent;
    const uint64_t unit=UINT64_C(1)<<shift, fraction=magnitude&(unit-1);
    uint64_t integer=magnitude&~(unit-1);
    const int increment=mode==0 ? fraction>unit/2 ||
        (fraction==unit/2 && ((integer>>shift)&1)) :
        mode==1 ? fraction && sign : mode==2 ? fraction && !sign : 0;
    if (increment)
        integer+=unit;
    return sign|integer;
}

static __attribute__((always_inline)) inline uintptr_t stack_pointer(void) {
    uintptr_t value;
    __asm__ volatile("movl %%esp,%0" : "=r"(value) : : "memory");
    return value;
}

int main(int argc,char **argv) {
    if (argc!=2) return 1;
    FILE *reference=fopen(argv[1],"r");
    if (!reference) return 2;
    unsigned checks=0;
    for (unsigned row=0;row<sizeof(functions)/sizeof(functions[0]);row++) {
        for (unsigned ambient=0;ambient<4;ambient++) {
            const uint16_t control=(uint16_t)(0x037f|(ambient<<10));
            for (unsigned sample=0;sample<sizeof(inputs)/sizeof(inputs[0]);sample++) {
                unsigned recorded_row,recorded_ambient,recorded_before,recorded_after;
                unsigned long long recorded_input,recorded_value;
                if (fscanf(reference,"%u %u %llx %x %x %llx",
                    &recorded_row,&recorded_ambient,&recorded_input,
                    &recorded_before,&recorded_after,&recorded_value)!=6) return 3;
                const uint64_t want=expected_bits(inputs[sample],modes[row]);
                if (recorded_row!=row || recorded_ambient!=ambient || recorded_input!=inputs[sample] ||
                    recorded_before!=control || recorded_after!=control || recorded_value!=want) {
                    fprintf(stderr,"original numerical/control mismatch row=%u ambient=%u sample=%u got=%016llx want=%016llx\n",
                        row,ambient,sample,recorded_value,(unsigned long long)want);
                    return 4;
                }
                double input;
                memcpy(&input,&inputs[sample],sizeof(input));
                uint16_t saved,before,after;
                __asm__ volatile("fnstcw %0" : "=m"(saved) : : "memory");
                __asm__ volatile("fldcw %0" : : "m"(control) : "memory");
                __asm__ volatile("fnstcw %0" : "=m"(before) : : "memory");
                const uintptr_t sp_before=stack_pointer();
                volatile double value=functions[row](input);
                const uintptr_t sp_after=stack_pointer();
                __asm__ volatile("fnstcw %0" : "=m"(after) : : "memory");
                __asm__ volatile("fldcw %0" : : "m"(saved) : "memory");
                uint64_t bits;
                memcpy(&bits,(const void *)&value,sizeof(bits));
                if (bits!=want || before!=control || after!=control || sp_before!=sp_after) {
                    fprintf(stderr,"LLVM numerical/CW/SP mismatch row=%u ambient=%u sample=%u got=%016llx want=%016llx CW=%04x/%04x\n",
                        row,ambient,sample,(unsigned long long)bits,(unsigned long long)want,before,after);
                    return 5;
                }
                checks++;
            }
        }
    }
    int trailing;
    do { trailing=fgetc(reference); } while (trailing=='\n' || trailing==' ' || trailing=='\t');
    const int complete=trailing==EOF && !ferror(reference);
    if (fclose(reference) || !complete) return 6;
    printf("scoped rounding original-Go/LLVM checks=%u\n",checks);
    return 0;
}
`)
	return driver.String()
}
