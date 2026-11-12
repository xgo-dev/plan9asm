//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This portable counterpart executes original legacy Go bytes and translated
// forms. Only the separately required Linux owner executes original VEX bytes.
func TestX86PackedStringOriginalLegacyAndLLVMReadFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution = x86PackedStringFaultCompiler(t, execution)
	x86PackedStringRunMemoryFaults(t, execution, false)
}

func x86PackedStringFaultCompiler(t *testing.T, execution x86FloatCompareExecution) x86FloatCompareExecution {
	t.Helper()
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		// Reuse the actual selected SDK/no-default-config helper. This only
		// configures the test's native C driver, never the Go source profile.
		command := runtimeOracleNativeCCommand(t, ctx, execution.compiler[0], execution.compiler[1:]...)
		execution.compiler = append([]string(nil), command.Args...)
	}
	return execution
}

func TestX86PackedStringFaultOriginalByteDriverObjects(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("original PCMP byte/driver objects require LLVM22")
	}
	triple := "x86_64-unknown-linux-gnu"
	if runtime.GOOS == "darwin" {
		triple = "x86_64-apple-darwin"
	}
	execution := x86FloatCompareExecution{llc: llc, triple: triple,
		compiler: []string{clang, "-target", triple, "-mno-red-zone"}}
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" {
		// The already authenticated matching cross compiler supplies its SDK;
		// this object-only owner does not execute its emulator transport.
		execution = x86FloatCompareExecutionTools(t)
	}
	execution = x86PackedStringFaultCompiler(t, execution)
	cases := x86PackedStringFaultCases()
	source, declarations := x86PackedStringFaultFixture(cases, "amd64")
	x86LEAActualTargetGoObject(t, "amd64", triple, source)
	driver := x86PackedStringFaultDriver(t, triple, cases, true)
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		input := ir
		if level == "-O2" {
			input = x86UndefinedTrapOptimizedIR(t, ir)
		}
		execution.compileLLVM(t, "original-pcmp-fault-driver", input, driver, level)
	}
	t.Log("complete original eight-name Go-byte/LLVM/C driver compiled; no faulting executable was launched")
}

func x86PackedStringRunMemoryFaults(t *testing.T, execution x86FloatCompareExecution, native bool) {
	t.Helper()
	if native {
		if len(execution.prefix) != 0 || execution.preserveArgv0 || execution.triple != "x86_64-unknown-linux-gnu" {
			t.Fatal("native PCMP fault owner cannot use a guest transport or another target")
		}
		execution.requireAVX(t)
	}
	cases := x86PackedStringFaultCases()
	source, declarations := x86PackedStringFaultFixture(cases, "amd64")
	// This independently checks the complete original Go ABI0 source, not only
	// the physical-register byte shim consumed by the C fault observer below.
	x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
	driver := x86PackedStringFaultDriver(t, execution.triple, cases, native)
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			executable := execution.compileLLVM(t, "packed-string-read-faults", input, driver, level)
			probes := []int{0, 1, 2, 4} // NULL, 15-byte tail, full tail, readable mod16=1.
			if native {
				probes = nil
				for probe := 0; probe < 34; probe++ {
					probes = append(probes, probe)
				}
			}
			for row := range cases {
				for _, probe := range probes {
					original := x86ObserveMemoryFault(t, execution, executable, row, probe, 1)
					translated := x86ObserveMemoryFault(t, execution, executable, row, probe, 0)
					fault := probe == 0 || probe == 1 || probe >= 19
					if original != translated || fault && original != "segv" && original != "bus" || !fault && original != "return" {
						t.Fatalf("PCMP row=%d/%s zero=%t dead=%t probe=%d original=%s LLVM=%s",
							row, cases[row].op, cases[row].zero, cases[row].dead, probe, original, translated)
					}
				}
			}
			t.Logf("complete32-case PCMP read/fault matrix: original native VEX=%t, probes=%d, LLVM%s; readable values and full input-page canaries checked", native, len(probes), level)
		})
	}
}

func x86PackedStringFaultDriver(t *testing.T, triple string, cases []x86PackedStringFaultCase, native bool) string {
	t.Helper()
	var declarations, records strings.Builder
	declarations.WriteString(x86OriginalSysVPointer("uint32_t", "original_program", "const uint8_t*"))
	for index, row := range cases {
		originalRow := row
		if !native {
			// A legacy opcode is only the portable memory-fault counterpart.
			// It cannot certify the named original VEX opcode's execution.
			originalRow.op = strings.TrimPrefix(originalRow.op, "V")
		}
		original := fmt.Sprintf("original_stringfault%d", index)
		code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+x86PackedStringFaultBody(originalRow)+"RET\n")
		if len(code) < 8 || code[len(code)-1] != 0xc3 {
			t.Fatal("original Go PCMP byte program lost its complete ordinary RET", originalRow, code)
		}
		var bytes []string
		for _, value := range code {
			bytes = append(bytes, fmt.Sprintf("0x%02x", value))
		}
		symbol := original
		if strings.Contains(triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&declarations, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		declarations.WriteString(x86OriginalSysVDeclaration("uint32_t", original, "const uint8_t*"))
		fmt.Fprintf(&declarations, "extern uint32_t stringfault%d(const uint8_t*);\n", index)
		fmt.Fprintf(&records, "    {%s,stringfault%d,%d,%d},\n", original, index,
			x86FloatAddSubBoolInt(row.zero), x86FloatAddSubBoolInt(row.dead))
	}
	return x86MemoryFaultSupportC + declarations.String() + `
struct string_fault_case {
    original_program original;
    uint32_t (*translated)(const uint8_t*);
    int zero,dead;
};

static const struct string_fault_case cases[] = {
` + records.String() + "};\n" + x86PackedStringFaultMainC
}

const x86PackedStringFaultMainC = `
int main(int argc, char **argv) {
    if (argc != 4) return 80;
    unsigned row,probe,original;
    char tail;
    if (sscanf(argv[1],"%u%c",&row,&tail) != 1 ||
        sscanf(argv[2],"%u%c",&probe,&tail) != 1 ||
        sscanf(argv[3],"%u%c",&original,&tail) != 1 ||
        row >= sizeof(cases)/sizeof(cases[0]) || probe >= 34 || original > 1) return 80;

    __builtin_cpu_init();
    if (!__builtin_cpu_supports("sse4.2")) return 86;
    int setup = memory_fault_setup(0);
    if (setup) return setup;
    const struct string_fault_case *kernel = &cases[row];
    uint8_t fill = kernel->zero ? 0 : 255;
    memset(guard,fill,page);
    if (mprotect(guard,page,PROT_READ)) return 87;

    const uint8_t *input;
    if (probe == 0) {
        input = NULL;
    } else if (probe == 1) {
        input = guard+page-15;
    } else if (probe == 2) {
        input = guard+page-16;
    } else if (probe < 19) {
        input = guard+32+(probe-3);
    } else {
        input = guard+page-(probe-19);
    }

    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 83;
    uint32_t value = original ? kernel->original(input) : kernel->translated(input);

    // A missing primary read must fail immediately. Calling the reference
    // here could otherwise supply the fault that the translated code lost.
    if (probe == 0 || probe == 1 || probe >= 19) return 93;

    // Values are compared only after the primary instruction returned. The
    // original opcode, not a C string scan or a guessed length, is the oracle.
    if (value != kernel->original(input) || (kernel->dead && value != 7)) return 91;
    for (size_t i = 0; i < page; ++i) {
        if (guard[i] != fill) return 92;
    }
    if (free_guard()) return 84;
    puts("memory complete");
    return fflush(stdout) ? 85 : 0;
}
`
