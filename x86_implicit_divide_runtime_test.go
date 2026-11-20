package plan9asm

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type x86DivideNativeRow struct {
	name, source string
	bits         int
	signed       bool
	memory       bool
	assembly     string
}

type x86DivideNativeCase struct {
	row                    int
	low, high, divisor     uint64
	operand, quotient, rem uint64
	fault                  string
}

func x86DivideNativeRows(arch string) []x86DivideNativeRow {
	return x86DivideNativeSourceRows(arch, false)
}

func x86DivideLogicalFPNativeRows(arch string) []x86DivideNativeRow {
	return x86DivideNativeSourceRows(arch, true)
}

func x86DivideNativeSourceRows(arch string, logicalFP bool) []x86DivideNativeRow {
	word, move, push, pop := 8, "MOVQ", "PUSHFQ", "POPQ"
	if arch == "386" {
		word, move, push, pop = 4, "MOVL", "PUSHFL", "POPL"
	}
	var rows []x86DivideNativeRow
	for _, member := range x86ImplicitDivideOracle {
		if arch == "386" && member.bits == 64 {
			continue
		}
		sources := []string{"CX", "memory", "AX", "DX"}
		if member.bits == 8 {
			sources = append(sources, "AH", "BH")
		}
		if arch == "386" {
			sources = append(sources, "BP", "SI", "DI")
		}
		if logicalFP {
			sources = []string{"FP"}
		}
		for _, source := range sources {
			row := x86DivideNativeRow{name: fmt.Sprint("Value", len(rows)), source: source,
				bits: member.bits, signed: member.signed, memory: source == "memory"}
			pointer, divisor := "DI", source
			if source == "DI" {
				pointer = "SI"
			}
			if row.memory {
				divisor = "(" + pointer + ")"
			} else if source == "FP" {
				divisor = fmt.Sprintf("divisor+%d(FP)", word+16)
			}
			setup := fmt.Sprintf("%s out+0(FP),%s\n%s low+%d(FP),AX\n%s high+%d(FP),DX\n%s divisor+%d(FP),CX\n",
				move, pointer, move, word, move, word+8, move, word+16)
			if source == "BH" {
				setup += fmt.Sprintf("%s divisor+%d(FP),BX\n", move, word+16)
			} else if source == "BP" || source == "SI" || source == "DI" {
				setup += fmt.Sprintf("%s divisor+%d(FP),%s\n", move, word+16, source)
			}
			instruction := "STD\n" + member.name + " " + divisor + "\n"
			var stores strings.Builder
			for index, register := range []string{"AX", "DX", "BX"} {
				fmt.Fprintf(&stores, "%s %s,%d(%s)\n", move, register, index*8, pointer)
				if arch == "386" {
					fmt.Fprintf(&stores, "MOVL $0,%d(%s)\n", index*8+4, pointer)
				}
			}
			row.assembly = fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s%s%s\n%s BX\n%s $0x400,BX\nCLD\n%sRET\n",
				row.name, word+24, setup, instruction, push, pop, "AND"+move[3:], stores.String())
			row.assembly += fmt.Sprintf("TEXT ·Dead%d(SB),4,$0-%d\n%s%sCLD\nRET\n", len(rows), word+24, setup, instruction)
			rows = append(rows, row)
		}
	}
	return rows
}

func x86DivideNativeEvaluate(row x86DivideNativeRow, index int, low, high, divisor uint64, arch string) x86DivideNativeCase {
	result := x86DivideNativeCase{row: index, low: low, high: high, divisor: divisor}
	mask := ^uint64(0)
	if row.bits != 64 {
		mask = uint64(1)<<uint(row.bits) - 1
	}
	operand := divisor
	switch row.source {
	case "AX":
		operand = low
	case "DX":
		operand = high
	case "AH":
		operand = low >> 8
	case "BH":
		operand = divisor >> 8
	}
	result.operand = operand & mask
	if result.operand == 0 {
		result.fault = "zero"
		return result
	}
	bits := row.bits * 2
	numerator := new(big.Int).SetUint64(low & mask)
	if row.bits == 8 {
		numerator.SetUint64(low & 0xffff)
	} else {
		upper := new(big.Int).Lsh(new(big.Int).SetUint64(high&mask), uint(row.bits))
		numerator.Or(numerator, upper)
	}
	denominator := new(big.Int).SetUint64(result.operand)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(row.bits))
	if row.signed {
		if numerator.Bit(bits-1) != 0 {
			numerator.Sub(numerator, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		}
		if denominator.Bit(row.bits-1) != 0 {
			denominator.Sub(denominator, modulus)
		}
	}
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	minimum, maximum := new(big.Int), new(big.Int).Sub(new(big.Int).Set(modulus), big.NewInt(1))
	if row.signed {
		limit := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
		minimum.Neg(limit)
		maximum.Sub(limit, big.NewInt(1))
	}
	if quotient.Cmp(minimum) < 0 || quotient.Cmp(maximum) > 0 {
		result.fault = "overflow"
		return result
	}
	quotient.Mod(quotient, modulus)
	remainder.Mod(remainder, modulus)
	result.quotient, result.rem = quotient.Uint64(), remainder.Uint64()
	if row.bits == 8 {
		result.quotient = low&^uint64(0xffff) | result.quotient | result.rem<<8
		result.rem = high
	} else if row.bits == 16 {
		result.quotient |= low &^ mask
		result.rem |= high &^ mask
	}
	if arch == "386" {
		result.quotient, result.rem = uint64(uint32(result.quotient)), uint64(uint32(result.rem))
	}
	return result
}

func x86DivideNativeCases(rows []x86DivideNativeRow, arch string) (values, faults []x86DivideNativeCase) {
	seeds := []uint64{0, ^uint64(0), 1, ^uint64(0) - 1, 7, ^uint64(0) - 6,
		127, ^uint64(0) - 126, 128, ^uint64(0) - 127, 255, ^uint64(0) - 254,
		256, ^uint64(0) - 255, 257, ^uint64(0) - 256, 0x1122334455667788, 0x8877665544332211}
	for value := uint64(2); value < 34; value++ {
		seeds = append(seeds, value, ^uint64(0)-(value-1))
	}
	for index, row := range rows {
		widthMask := ^uint64(0)
		if row.bits != 64 {
			widthMask = uint64(1)<<uint(row.bits) - 1
		}
		seenFaults, selected := make(map[string]bool), 0
		seenValues := make(map[[3]uint64]bool)
		wordMask := ^uint64(0)
		if arch == "386" {
			wordMask = 0xffffffff
		}
		for _, low := range seeds {
			chosen := false
			preferredHigh := uint64(0)
			if row.signed && low&(uint64(1)<<uint(row.bits-1)) != 0 {
				preferredHigh = widthMask
			}
			for _, high := range []uint64{preferredHigh, 0, widthMask, 1, uint64(1) << uint(row.bits-1)} {
				for _, divisor := range []uint64{3, ^uint64(0) - 2, 1, ^uint64(0), 7, 0, 0x100, 0x300} {
					current := x86DivideNativeEvaluate(row, index, low, high, divisor, arch)
					if current.fault != "" {
						if !seenFaults[current.fault] {
							seenFaults[current.fault] = true
							faults = append(faults, current)
						}
					} else if !chosen && selected < 16 {
						key := [3]uint64{low & wordMask, high & wordMask, current.operand}
						if !seenValues[key] {
							seenValues[key] = true
							values = append(values, current)
							selected++
							chosen = true
						}
					}
				}
			}
		}
		if row.signed && (row.source == "CX" || row.source == "FP" || row.memory) {
			for _, boundary := range []string{"wide-min/-1", "narrow-min/-1"} {
				low, high := uint64(0), uint64(1)<<uint(row.bits-1)
				if boundary == "narrow-min/-1" {
					low, high = uint64(1)<<uint(row.bits-1), widthMask
				}
				if row.bits == 8 {
					low, high = low|high<<8, 0
				}
				current := x86DivideNativeEvaluate(row, index, low, high, ^uint64(0), arch)
				if current.fault != "overflow" {
					panic("independent signed division overflow boundary is not #DE")
				}
				current.fault = boundary
				faults = append(faults, current)
			}
		}
	}
	return values, faults
}

func TestX86ImplicitDivideIndependentNativeVectorDirectory(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86DivideNativeRows(arch)
		values, faults := x86DivideNativeCases(rows, arch)
		wantRows, wantValues, wantFaults := 36, 512, 88
		if arch == "386" {
			wantRows, wantValues, wantFaults = 46, 688, 104
		}
		if len(rows) != wantRows || len(rows)*2 > 96 || len(values) != wantValues || len(faults) != wantFaults {
			t.Fatal("independent complete source/alias/defined-value/#DE directory changed", arch, len(rows), len(values), len(faults))
		}
		for index, row := range rows {
			count := 0
			for _, value := range values {
				if value.row == index {
					count++
				}
			}
			alwaysFaults := !row.signed && (row.source == "DX" && row.bits != 8 || row.source == "AH")
			if alwaysFaults && count != 0 || !alwaysFaults && count != 16 {
				t.Fatal("a source alias disappeared behind an empty value vector", arch, row, count)
			}
		}
	}
}

func x86DivideNativeDeclarationSources(rows []x86DivideNativeRow) (apiDeclarations, originalFile string) {
	var declarations strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&declarations, "func %s(out *[4]uint64,low,high,divisor uint64)\nfunc Dead%d(out *[4]uint64,low,high,divisor uint64)\n", row.name, index)
	}
	return declarations.String(), "package oracle\n" + declarations.String()
}

func x86RunImplicitDivideNative(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	x86RunImplicitDivideNativeRows(t, execution, arch, x86DivideNativeRows(arch))
}

func x86RunImplicitDivideNativeRows(t *testing.T, execution x86FloatCompareExecution, arch string, rows []x86DivideNativeRow) {
	t.Helper()
	values, faults := x86DivideNativeCases(rows, arch)
	var assembly, cRows, cCases, goRows, goCases, faultRows, faultCases strings.Builder
	declarations, originalDeclarations := x86DivideNativeDeclarationSources(rows)
	for index, row := range rows {
		assembly.WriteString(row.assembly)
		fmt.Fprintf(&cRows, "{ %s },\n", row.name)
		fmt.Fprintf(&goRows, "%s,\n", row.name)
		signed, memory := 0, 0
		if row.signed {
			signed = 1
		}
		if row.memory {
			memory = 1
		}
		fmt.Fprintf(&faultRows, "{ Dead%d,%d,%d,%d },\n", index, row.bits, signed, memory)
	}
	for _, value := range values {
		fmt.Fprintf(&cCases, "{%d,UINT64_C(%d),UINT64_C(%d),UINT64_C(%d),UINT64_C(%d),UINT64_C(%d)},\n", value.row, value.low, value.high, value.divisor, value.quotient, value.rem)
		fmt.Fprintf(&goCases, "{%d,%d,%d,%d,%d,%d},\n", value.row, value.low, value.high, value.divisor, value.quotient, value.rem)
	}
	for _, fault := range faults {
		fmt.Fprintf(&faultCases, "{%d,UINT64_C(%d),UINT64_C(%d),UINT64_C(%d),UINT64_C(%d)},\n", fault.row, fault.low, fault.high, fault.divisor, fault.operand)
	}
	var prototypes strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&prototypes, "extern void %s(uint64_t *,uint64_t,uint64_t,uint64_t);\nextern void Dead%d(uint64_t *,uint64_t,uint64_t,uint64_t);\n", row.name, index)
	}
	goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
	ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations, arch, execution.triple, "Go")
	if err != nil {
		t.Fatal("complete original division runtime source rejected", arch, err)
	}
	valueDriver := fmt.Sprintf(x86DivideNativeValuesC, prototypes.String(), cRows.String(), cCases.String())
	faultDriver := x86DivideNativeFaultsC(prototypes.String(), faultRows.String(), faultCases.String())
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			calls := strings.Count(pipeline.ir, `asm sideeffect "div`) + strings.Count(pipeline.ir, `asm sideeffect "idiv`)
			if calls != len(rows)*2 {
				t.Fatal("an observable or dead division lost its mandatory native opcode")
			}
			valueExecutable := execution.compileLLVM(t, "division-values", pipeline.ir, valueDriver, pipeline.level)
			var output []byte
			if arch == "386" {
				program := x86NativeOracleIA32Executable(t, execution, valueExecutable)
				output = x87IA32RunDirect(t, program, nil, os.Environ())
			} else {
				output = execution.run(t, valueExecutable)
			}
			want := fmt.Sprintf("native division whole-register/DF/canary outcomes %d failures 0\n", len(values))
			if string(output) != want {
				t.Fatal("independent mathematical whole-register results", string(output), want)
			}
			executable := execution.compileLLVM(t, "division-faults", pipeline.ir, faultDriver, pipeline.level)
			var ia32 *x87IA32Executable
			if arch == "386" {
				program := x86NativeOracleIA32Executable(t, execution, executable)
				ia32 = &program
			}
			observe := func(index, probe, original int) string {
				// A genuine native signal still has to come from the exact
				// static IA32 file inspected before this direct invocation.
				if ia32 != nil {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				result := x86ObserveMemoryFault(t, execution, executable, index, probe, original)
				if ia32 != nil {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				return result
			}
			for index, fault := range faults {
				probes := 1
				if rows[fault.row].memory {
					probes = 5
				}
				for probe := 0; probe < probes; probe++ {
					want := observe(index, probe, 1)
					if probe == 1 || probe == 2 {
						if want != "segv" && want != "bus" {
							t.Fatal("original memory access did not precede #DE", arch, index, probe, want)
						}
					} else if want != "fpe" {
						t.Fatal("original zero/overflow division did not raise native #DE", arch, index, probe, want)
					}
					if got := observe(index, probe, 0); got != want {
						t.Fatal("dead native division exception class/priority mismatch", arch, index, probe, got, want)
					}
				}
			}
			if rows[0].source == "FP" {
				t.Logf("logical FP native arch=%s rows=%d values=%d dead-division-faults=%d; whole AX/DX, DF and canaries; zero/overflow and signed-min/-1 SIGFPE", arch, len(rows), len(values), len(faults))
			}
		})
	}
	x86RunOriginalGoNativeSource(t, execution, arch, originalDeclarations, assembly.String(),
		fmt.Sprintf(x86DivideNativeOriginalGo, goRows.String(), goCases.String()))
	if rows[0].source == "FP" {
		t.Logf("logical FP actual original Go arch=%s rows=%d values=%d; complete original FP divisor source and whole AX/DX/DF/canary observations", arch, len(rows), len(values))
	}
}

func x86NativeOracleIA32Executable(t *testing.T, execution x86FloatCompareExecution, path string) x87IA32Executable {
	t.Helper()
	if execution.triple != "i386-unknown-linux-gnu" || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("native IA32 oracle forbids an emulator or guest argv transport")
	}
	program, err := x87IA32StaticExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native oracle static IA32 ELF bytes=%d sha256=%x", program.size, program.hash)
	return program
}

func x86OriginalGoNativeEnvironment(arch string, inherited []string) []string {
	env := append([]string(nil), inherited...)
	return append(env, "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOROOT="+runtime.GOROOT(), "GOFLAGS=", "GOEXPERIMENT=", "GOOS=linux",
		"GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
}

func TestX86ImplicitDivideOriginalGoEnvironmentIsBoundToSDK(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		inherited := []string{"PATH=sentinel", "GOROOT=untrusted", "GOENV=untrusted", "GOWORK=untrusted",
			"GOTOOLCHAIN=auto", "GOFLAGS=-race", "GOEXPERIMENT=untrusted", "GOOS=untrusted",
			"GOARCH=untrusted", "CGO_ENABLED=1", "GOMAXPROCS=64"}
		actual := make(map[string]string)
		for _, entry := range x86OriginalGoNativeEnvironment(arch, inherited) {
			name, value, _ := strings.Cut(entry, "=")
			actual[name] = value
		}
		for name, want := range map[string]string{
			"PATH": "sentinel", "GOROOT": runtime.GOROOT(), "GOENV": "off", "GOWORK": "off",
			"GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "", "GOOS": "linux",
			"GOARCH": arch, "CGO_ENABLED": "0", "GOMAXPROCS": "2",
		} {
			if actual[name] != want {
				t.Fatalf("%s %s=%q, want %q", arch, name, actual[name], want)
			}
		}
		if inherited[1] != "GOROOT=untrusted" {
			t.Fatal("oracle environment mutated its caller's inherited environment")
		}
	}
}

// Shared exact-SDK execution is only a test-driver lifecycle. Neither family
// obtains source, numerical, ABI or native-storage permissions from it.
func x86RunOriginalGoNativeSource(t *testing.T, execution x86FloatCompareExecution, arch, declarations, assembly, testSource string) {
	t.Helper()
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations,
		"value_" + arch + ".s": assembly, "value_test.go": testSource,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(directory, "original.test")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	env := x86OriginalGoNativeEnvironment(arch, os.Environ())
	version, err := x87IA32Capture(t, goBinary, []string{"version"}, directory, env)
	if err != nil || !strings.HasPrefix(string(version), "go version "+runtime.Version()+" ") {
		t.Fatalf("native oracle SDK identity mismatch: %v\n%s", err, version)
	}
	output, err := x87IA32Capture(t, goBinary,
		[]string{"test", "-p=1", "-vet=off", "-c", "-o", binary, "."}, directory, env)
	if err != nil || len(output) != 0 {
		t.Fatalf("original Go native oracle compile failed: %v\n%s", err, output)
	}
	arguments := []string{"-test.run=^TestOriginal$", "-test.count=1", "-test.v"}
	if arch == "386" {
		program := x86NativeOracleIA32Executable(t, execution, binary)
		output = x87IA32RunDirect(t, program, arguments, os.Environ())
	} else {
		output = execution.run(t, binary, arguments...)
	}
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatal("original Go has no successful complete mathematical terminal", string(output))
	}
}

const x86DivideNativeValuesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
struct kernel {void (*run)(uint64_t *,uint64_t,uint64_t,uint64_t);};
static const struct kernel kernels[]={%s};
struct sample {unsigned row; uint64_t low,high,divisor,quotient,remainder;};
static const struct sample samples[]={%s};
int main(void) {
    unsigned count=0;
    for (unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);i++) {
        struct sample s=samples[i];
        if (s.row>=sizeof(kernels)/sizeof(kernels[0])) return 1;
        uint64_t actual[]={s.divisor,UINT64_C(0x123456789abcdef0),UINT64_C(0x1122334455667788),UINT64_C(0x9abcdef012345678)};
        const uint64_t expected[]={s.quotient,s.remainder,0x400,UINT64_C(0x9abcdef012345678)};
        kernels[s.row].run(actual,s.low,s.high,s.divisor);
        if (memcmp(actual,expected,sizeof(actual))) {
            fprintf(stderr,"division row=%%u sample=%%u got=%%llx/%%llx/%%llx expected=%%llx/%%llx\n",s.row,i,
                (unsigned long long)actual[0],(unsigned long long)actual[1],(unsigned long long)actual[2],
                (unsigned long long)s.quotient,(unsigned long long)s.remainder);
            return 1;
        }
        count++;
    }
    printf("native division whole-register/DF/canary outcomes %%u failures 0\n",count);
    return 0;
}
`

const x86DivideNativeOriginalGo = `package oracle
import "testing"
var kernels=[]func(*[4]uint64,uint64,uint64,uint64){%s}
var samples=[]struct{row int;low,high,divisor,quotient,remainder uint64}{%s}
func TestOriginal(t *testing.T) {
    if len(samples)==0 {t.Fatal("empty independent mathematical vector")}
    for i,s:=range samples {
        actual:=[4]uint64{s.divisor,0x123456789abcdef0,0x1122334455667788,0x9abcdef012345678}
        expected:=[4]uint64{s.quotient,s.remainder,0x400,0x9abcdef012345678}
        kernels[s.row](&actual,s.low,s.high,s.divisor)
        if actual!=expected {t.Fatalf("division row=%%d sample=%%d got=%%x want=%%x",s.row,i,actual,expected)}
    }
    t.Logf("actual Go whole-register/DF/canary outcomes %%d failures 0",len(samples))
}
`
