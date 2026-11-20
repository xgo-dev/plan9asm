//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

type fixedLocalPackedRuntimeCase struct {
	width, bits, word, mode int
}

func fixedLocalPackedRuntimeProgram(all bool) (string, string, []fixedLocalPackedRuntimeCase) {
	var assembly, declarations strings.Builder
	var cases []fixedLocalPackedRuntimeCase
	add := func(opcode, bank string, width, bits, mode int) {
		for word := -1; word <= width/8; word++ {
			index := len(cases)
			cases = append(cases, fixedLocalPackedRuntimeCase{width, bits, word, mode})
			fmt.Fprintf(&declarations, "func Value%d(a, mask uint64) uint64\n", index)
			fmt.Fprintf(&assembly, "TEXT ·Value%d(SB),4,$512-24\nMOVQ a+0(FP),AX\nMOVQ mask+8(FP),CX\n", index)
			assembly.WriteString("MOVQ SP,BP\nADDQ $64,BP\nANDQ $-64,BP\n")
			assembly.WriteString("MOVQ $0x5a5a5a5a5a5a5a5a,DX\nMOVQ DX,248(BP)\n")
			fmt.Fprintf(&assembly, "MOVQ DX,%d(BP)\n", 256+width)
			for offset := 0; offset < width; offset += 8 {
				fmt.Fprintf(&assembly, "MOVQ DX,%d(BP)\n", 256+offset)
			}
			for offset := 0; offset < width; offset += 8 {
				fmt.Fprintf(&assembly, "MOVQ $%d,DX\nMOVQ DX,%d(BP)\n", int64(0x102030405060708)+int64(offset), 128+offset)
			}
			if word >= 0 && word < width/8 {
				fmt.Fprintf(&assembly, "MOVQ AX,%d(BP)\n", 128+word*8)
			}
			first, last := bank+"0", bank+"1"
			fmt.Fprintf(&assembly, "%s 256(BP),%s\n%s 256(BP),%s\n", opcode, first, opcode, last)
			mask, effective := "", opcode
			if mode != 0 {
				assembly.WriteString("KMOVQ CX,K7\n")
				mask = "K7,"
			}
			if mode == 2 {
				effective += ".Z"
			}
			fmt.Fprintf(&assembly, "%s 128(BP),%s%s\n%s %s,%s%s\n", effective, mask, first, effective, first, mask, last)
			if mode == 2 {
				mask = "" // Observe inactive zeroed bytes, not retained memory.
			}
			fmt.Fprintf(&assembly, "%s %s,%s256(BP)\nMOVQ %d(BP),AX\nMOVQ AX,ret+16(FP)\nRET\n", opcode, last, mask, 256+word*8)
		}
	}
	for _, opcode := range []string{"MOVO", "MOVOA", "MOVOU", "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD"} {
		add(opcode, "X", 16, 8, 0)
	}
	if all {
		for _, row := range fixedLocalPackedMoveOracle {
			width, bank, bits := 32, "Y", 8
			if row.evex {
				width, bank = 64, "Z"
			}
			switch row.name {
			case "VMOVAPD", "VMOVUPD", "VMOVDQA64", "VMOVDQU64":
				bits = 64
			case "VMOVAPS", "VMOVUPS", "VMOVDQA32", "VMOVDQU32":
				bits = 32
			case "VMOVDQU16":
				bits = 16
			}
			add(row.name, bank, width, bits, 0)
			if row.evex {
				add(row.name, bank, width, bits, 1)
				add(row.name, bank, width, bits, 2)
			}
		}
	}
	return assembly.String(), declarations.String(), cases
}

func fixedLocalPackedRuntimeOracles(cases []fixedLocalPackedRuntimeCase, triple string) (string, string) {
	var goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, row := range cases {
		fmt.Fprintf(&goRows, "{Value%d,%d,%d,%d,%d},\n", index, row.width, row.bits, row.word, row.mode)
		fmt.Fprintf(&cRows, "{value%d,%d,%d,%d,%d},\n", index, row.width, row.bits, row.word, row.mode)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t,uint64_t) __asm__(\"%sexample.invalid/framefixture.Value%d\");\n", index, prefix, index)
	}
	goOracle := `package framefixture
import "testing"
func TestOriginal(t *testing.T) {
    cases := []struct {
        call func(uint64,uint64) uint64
        width, bits, word, mode int
    }{
` + goRows.String() + `
    }
    values := []uint64{0,1,^uint64(0),0x8000000000000000,0x123456789abcdef0,0x7ff81234567890ab}
    masks := []uint64{0,1,^uint64(0),0x5555555555555555,0xaaaaaaaaaaaaaaaa,0x8000000000000000}
    for index, row := range cases {
        for _, value := range values {
            for _, mask := range masks {
                want := uint64(0x5a5a5a5a5a5a5a5a)
                if row.word >= 0 && row.word < row.width/8 {
                    want = 0
                    for bit := 0; bit < 64; bit++ {
                        input := uint64(0x5a5a5a5a5a5a5a5a)
                        if row.mode == 0 || mask >> uint((row.word*64+bit)/row.bits)&1 != 0 {
                            input = value
                        } else if row.mode == 2 {
                            input = 0
                        }
                        want |= input & (uint64(1) << uint(bit))
                    }
                }
                if got := row.call(value,mask); got != want {
                    t.Fatalf("case=%d input=%x mask=%x got=%x want=%x",index,value,mask,got,want)
                }
            }
        }
    }
}
`
	cOracle := `#include <stdint.h>
#include <stdio.h>
` + cDeclarations.String() + `
struct entry {
    uint64_t (*call)(uint64_t,uint64_t);
    int width,bits,word,mode;
};
static const struct entry cases[]={
` + cRows.String() + `
};
int main(void) {
    const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x123456789abcdef0),UINT64_C(0x7ff81234567890ab)};
    const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x5555555555555555),UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0x8000000000000000)};
    for(unsigned n=0;n<sizeof(cases)/sizeof(cases[0]);n++) {
        struct entry row=cases[n];
        for(unsigned v=0;v<6;v++) for(unsigned m=0;m<6;m++) {
            uint64_t want=UINT64_C(0x5a5a5a5a5a5a5a5a);
            if(row.word>=0 && row.word<row.width/8) {
                want=0;
                for(unsigned bit=0;bit<64;bit++) {
                    uint64_t source=UINT64_C(0x5a5a5a5a5a5a5a5a);
                    unsigned lane=((unsigned)row.word*64+bit)/(unsigned)row.bits;
                    if(row.mode==0 || (masks[m]>>lane)&1) source=values[v];
                    else if(row.mode==2) source=0;
                    want|=source&(UINT64_C(1)<<bit);
                }
            }
            uint64_t got=row.call(values[v],masks[m]);
            if(got!=want) {
                fprintf(stderr,"case=%u value=%llx mask=%llx got=%llx want=%llx\n",n,(unsigned long long)values[v],(unsigned long long)masks[m],(unsigned long long)got,(unsigned long long)want);
                return 1;
            }
        }
    }
    return 0;
}
`
	return goOracle, cOracle
}

func fixedLocalPackedRuntime(t *testing.T, execution x86FloatCompareExecution, all, execute bool) {
	t.Helper()
	fixedLocalPackedRuntimeAPIs(t, execution, all, execute, []string{"Translate", "Module", "GoModule"})
}

func fixedLocalPackedBatchSelection(total int, selected ...int) ([]int, error) {
	if total <= 0 || len(selected) > 1 {
		return nil, fmt.Errorf("packed source owner needs a nonempty inventory and at most one batch: total=%d selected=%v",
			total, selected)
	}
	if len(selected) == 1 {
		if selected[0] < 0 || selected[0] >= total {
			return nil, fmt.Errorf("packed source batch outside complete inventory: total=%d selected=%v", total, selected)
		}
		return []int{selected[0]}, nil
	}
	var indices []int
	for index := 0; index < total; index++ {
		indices = append(indices, index)
	}
	return indices, nil
}

func fixedLocalPackedRuntimeAPIs(t *testing.T, execution x86FloatCompareExecution, all, execute bool, apis []string, selected ...int) {
	t.Helper()
	batches := fixedLocalPackedLeaseBatches(t, all, execution.triple)
	indices, err := fixedLocalPackedBatchSelection(len(batches), selected...)
	if err != nil {
		t.Fatal(err)
	}
	// Share only disposable compiler artifacts, never a source observation.
	t.Setenv("GOCACHE", t.TempDir())
	assembly, declarations, cases := fixedLocalPackedRuntimeProgram(all)
	goOracle, cOracle := fixedLocalPackedRuntimeOracles(cases, execution.triple)
	// Compile/execute the unchanged whole original before starting any API
	// lease. The following batches are complete independent source packages.
	fixedLocalPackedRunOriginal(t, execution, assembly, declarations, goOracle, execute)
	if !execute {
		dir := t.TempDir()
		input, output := filepath.Join(dir, "oracle.c"), filepath.Join(dir, "oracle.o")
		if err := os.WriteFile(input, []byte(cOracle), 0600); err != nil {
			t.Fatal(err)
		}
		command := append([]string(nil), execution.compiler...)
		command = append(command, "-O2", "-c", input, "-o", output)
		x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
	}
	for _, index := range indices {
		batch := batches[index]
		t.Run(fmt.Sprintf("batch%d", index), func(t *testing.T) {
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, batch.assembly, batch.declarations,
				runtime.GOOS+"/amd64", execution.triple)
			fixedLocalConversionPrepareToolCache(t, request)
			fixedLocalFreshAPIs(t, pkg, request, options, apis, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				for member := batch.start; member < batch.end; member++ {
					names = append(names, fmt.Sprintf("example.invalid/framefixture.Value%d", member))
				}
				for _, pipeline := range []struct {
					name, level string
					optimize    bool
				}{
					{"backend_O0", "-O0", false},
					{"backend_O2", "-O2", false},
					{"IR_O2/backend_O2", "-O2", true},
				} {
					t.Run(pipeline.name, func(t *testing.T) {
						input := ir
						if pipeline.optimize {
							input = x86MulDivRoundOptimize(t, ir)
						}
						x86CompactExpandRequireAllDefinitions(t, input, names)
						if execute {
							execution.compileAndRunLLVM(t, "packed-native-frame", input, batch.oracle, pipeline.level)
						} else {
							x86PackedStringCompileObject(t, execution.llc, execution.triple, input, pipeline.level)
						}
						t.Logf("complete packed oracle [%d,%d): %d kernels x 6 values x 6 masks x 64 result bits; execute=%v",
							batch.start, batch.end, batch.end-batch.start, execute)
					})
				}
			})
		})
	}
	t.Logf("cases=%d original Go + APIs=%v; complete source batches=%d selected=%v execute=%v native-wide=%v",
		len(cases), apis, len(batches), indices, execute, all)
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedSSE(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	fixedLocalPackedRuntime(t, execution, false, true)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("Rosetta SSE diagnostic, not native AVX/AVX512 execution")
	}
}

func TestGoAMD64FixedLocalPackedWideRuntimeOracleCompileOnly(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	fixedLocalPackedRuntimeAPIs(t, execution, true, false, []string{"Translate"})
	t.Log("full wide oracle compiled, not executed; required Linux/amd64 root owns native coverage")
}

func TestGoAMD64FixedLocalPackedWideRuntimeOracleModuleCompileOnly(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	fixedLocalPackedRuntimeAPIs(t, execution, true, false, []string{"Module"})
	t.Log("full wide oracle compiled, not executed; required Linux/amd64 root owns native coverage")
}

func TestGoAMD64FixedLocalPackedWideRuntimeOracleGoModuleCompileOnly(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	fixedLocalPackedRuntimeAPIs(t, execution, true, false, []string{"GoModule"})
	t.Log("full wide oracle compiled, not executed; required Linux/amd64 root owns native coverage")
}

// Object compilation needs a real compiler and target headers, not an x86 CPU
// or executable transport. This value must never be used to claim execution.
func fixedLocalPackedCompileOnlyTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required for complete packed object compilation")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	compiler := []string{clang, "-target", triple}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	if runtime.GOOS == "linux" && runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		const root = "/usr/x86_64-linux-gnu"
		include := filepath.Join(root, "include")
		if info, err := os.Stat(include); err != nil || !info.IsDir() {
			t.Fatalf("required AMD64 C target sysroot headers %s: %v", include, err)
		}
		compiler = append(compiler, "--sysroot="+root, "-isystem", include)
	}
	return x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
}

func TestGoAMD64FixedLocalPackedRuntimeOwnership(t *testing.T) {
	for _, row := range []struct {
		all   bool
		count int
	}{{false, 28}, {true, 340}} {
		_, declarations, cases := fixedLocalPackedRuntimeProgram(row.all)
		if len(cases) != row.count || strings.Count(declarations, "func Value") != row.count {
			t.Fatalf("runtime row ownership all=%v: got %d want %d", row.all, len(cases), row.count)
		}
	}
	source, err := os.ReadFile("amd64_fixed_local_packed_native_linux_amd64_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fixedLocalPackedRequireNativeBatchOwners(t)
	if strings.Contains(string(source), "t.Skip") {
		t.Fatal("native wide runtime coverage must not silently skip")
	}
}
