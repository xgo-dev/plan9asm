package plan9asm

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

type arm64UnsignedReciprocalCase struct {
	operation   string
	lanes       int
	destination int
}

func (f arm64UnsignedReciprocalCase) assembly() string {
	return fmt.Sprintf("%s v%d.%ds, v30.%ds", f.operation, f.destination, f.lanes, f.lanes)
}

func arm64UnsignedReciprocalFixture(t *testing.T) (string, []arm64UnsignedReciprocalCase) {
	t.Helper()
	var cases []arm64UnsignedReciprocalCase
	var lines []string
	for _, operation := range []string{"urecpe", "ursqrte"} {
		for _, lanes := range []int{2, 4} {
			for _, destination := range []int{31, 30} {
				test := arm64UnsignedReciprocalCase{operation, lanes, destination}
				cases = append(cases, test)
				lines = append(lines, test.assembly())
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT EstimateRows(SB),516,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n")
	for i, word := range assembleARM64LLVMWords(t, lines, "") {
		test := cases[i]
		fmt.Fprintf(&source, "VLD1 (R0), [V30.S4]\nWORD $%#08x\nVST1.P [V%d.S4], 16(R1)\n", word, test.destination)
		if effects, ok := arm64RawContinuationEffectsForWord(word); !ok || effects != (arm64RawContinuationEffects{}) {
			t.Errorf("%s: effects %+v, recognized %t", test.assembly(), effects, ok)
		}
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	return source.String(), cases
}

func translateARM64UnsignedReciprocalFixture(t *testing.T, source, triple string) string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	signature := FuncSig{
		Name: "EstimateRows", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}},
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"EstimateRows": signature}})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64UnsignedReciprocalObjects(t *testing.T) {
	source, cases := arm64UnsignedReciprocalFixture(t)
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump are required")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := translateARM64UnsignedReciprocalFixture(t, source, triple)
			object := compileLLVMToObject(t, llc, triple, "unsigned-estimate.ll", "unsigned-estimate.o", ir)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			code, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", object))
			if err != nil {
				t.Fatalf("inspect translated estimate instructions: %v\n%s", err, code)
			}
			for _, test := range cases {
				pattern := fmt.Sprintf(`\b%s(?:\s+v[0-9]+\.%ds, v[0-9]+\.%ds|\.%ds\s+v[0-9]+, v[0-9]+)`,
					test.operation, test.lanes, test.lanes, test.lanes)
				if !regexp.MustCompile(pattern).Match(code) {
					t.Fatalf("object missing %s with %d lanes:\n%s", test.operation, test.lanes, code)
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64UnsignedReciprocal(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, cases := arm64UnsignedReciprocalFixture(t)
	ir := translateARM64UnsignedReciprocalFixture(t, source, triple)
	var main strings.Builder
	main.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void EstimateRows(const uint32_t *, uint32_t (*)[4]);
static void original(const uint32_t *in, uint32_t (*out)[4]) {
`)
	for i, test := range cases {
		fmt.Fprintf(&main, `  __asm__ volatile("ld1 {v30.4s}, [%%1]\n\t%s\n\tst1 {v%d.4s}, [%%0]"
    :: "r"(out[%d]), "r"(in) : "v30", "v31", "memory");
`, test.assembly(), test.destination, i)
	}
	fmt.Fprintf(&main, `}
enum { rows = %d };
int main(void) {
  const uint32_t inputs[][4] = {
    {0, 1, 0x3fffffff, 0x40000000},
    {0x40000001, 0x7fffffff, 0x80000000, 0x80000001},
    {0x81234567, 0xbbaabbcc, 0xffffffff, 0xfffffffe},
    {0x80004000, 0x81100000, 0xc0000000, 0xe0000000},
  };
  for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); ++i) {
    uint32_t got[rows][4], want[rows][4];
    original(inputs[i], want);
    EstimateRows(inputs[i], got);
    for (int j = 0; j < rows; ++j) {
      if (memcmp(got[j], want[j], sizeof(got[j])) != 0) {
        fprintf(stderr, "input %%u row %%d: reciprocal estimate mismatch\n", i, j);
        return 1;
      }
    }
  }
  return 0;
}
`, len(cases))
	for _, optimization := range []int{0, 2} {
		name := fmt.Sprintf("unsigned_estimate_O%d", optimization)
		t.Run(name, func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, name, triple, ir, main.String(), runner, optimization)
		})
	}
}
