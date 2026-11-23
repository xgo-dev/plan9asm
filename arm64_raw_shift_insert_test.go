package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64ShiftInsertOracle(t *testing.T) (assembly []string, words []uint32) {
	t.Helper()
	for _, arrangement := range []struct {
		registers string
		width     int
	}{
		{"v31.8b, v30.8b", 8}, {"v31.16b, v30.16b", 8},
		{"v31.4h, v30.4h", 16}, {"v31.8h, v30.8h", 16},
		{"v31.2s, v30.2s", 32}, {"v31.4s, v30.4s", 32},
		{"v31.2d, v30.2d", 64}, {"d31, d30", 64},
	} {
		for shift := 0; shift < arrangement.width; shift++ {
			assembly = append(assembly, fmt.Sprintf("sli %s, #%d", arrangement.registers, shift))
			assembly = append(assembly, fmt.Sprintf("sri %s, #%d", arrangement.registers, shift+1))
		}
	}
	return assembly, assembleARM64LLVMWords(t, assembly, "")
}

func TestARM64RawShiftInsertRejectsAdjacentEncodings(t *testing.T) {
	for word, description := range map[uint32]string{
		0x2f005400: "immh=0",
		0x2f405400: "vector 1D",
		0x3f405400: "scalar with Q=0",
		0x7f205400: "32-bit scalar",
		0x6f405c00: "adjacent immediate operation",
	} {
		if form, ok := decodeARM64RawShiftInsert(word); ok {
			t.Errorf("%s (%#08x) decoded as %+v", description, word, form)
		}
	}
}

func TestARM64ShiftInsertUsesDeclaredScalarWidth(t *testing.T) {
	word := assembleARM64LLVMWords(t, []string{"sli d0, d1, #1"}, "")[0]
	source := fmt.Sprintf("TEXT ·Insert<ABIInternal>(SB),4,$0-24\nWORD $%#08x\nRET\n", word)
	requireARM64GoABIInternalObject(t, source)
	for _, test := range []struct {
		name, secondParam string
		wantContext       bool
	}{
		{"64-bit input", "float64", false},
		{"32-bit input", "float32", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			decl := fmt.Sprintf("package shiftinsert\nfunc Insert(dst float64, src %s) float64\n", test.secondParam)
			pkg := mustGoPackage(t, "test/shiftinsert", decl)
			result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: arm64LinuxGNUTriple,
			})
			if result != nil {
				defer result.Module.Dispose()
			}
			if test.wantContext {
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "V1 read (64 bits)") {
					t.Fatalf("32-bit input must require 64 bits of V1 state: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64ShiftInsert(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	assembly, words := arm64ShiftInsertOracle(t)
	var source strings.Builder
	source.WriteString(`TEXT ShiftInsertRows(SB),516,$0-24
MOVD src+0(FP), R0
MOVD dst+8(FP), R1
MOVD out+16(FP), R2
VLD1 (R0), [V30.D2]
`)
	for i, word := range words {
		if effects, ok := arm64RawContinuationEffectsForWord(word); !ok || effects != (arm64RawContinuationEffects{}) {
			t.Errorf("%s: effects %+v, recognized %t", assembly[i], effects, ok)
		}
		fmt.Fprintf(&source, "VLD1 (R1), [V31.D2]\nWORD $%#08x\nVST1.P [V31.D2], 16(R2)\n", word)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	signature := FuncSig{Name: "ShiftInsertRows", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}},
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"ShiftInsertRows": signature}})
	if err != nil {
		t.Fatal(err)
	}

	var main strings.Builder
	main.WriteString(`#include <stdint.h>
#include <stdio.h>
extern void ShiftInsertRows(const uint64_t *, const uint64_t *, uint64_t (*)[2]);
static void original(const uint64_t *src, const uint64_t *dst, uint64_t (*out)[2]) {
`)
	for index, instruction := range assembly {
		fmt.Fprintf(&main, `  __asm__ volatile("ld1 {v30.2d}, [%%1]\n\tld1 {v31.2d}, [%%2]\n\t%s\n\tst1 {v31.2d}, [%%0]"
    :: "r"(out[%d]), "r"(src), "r"(dst) : "v30", "v31", "memory");
`, instruction, index)
	}
	fmt.Fprintf(&main, `}
enum { rows = %d };
int main(void) {
  const uint64_t inputs[][2] = {
    {UINT64_C(0xf9a46a5362c5318e), UINT64_C(0x198e87f51f7a33b9)},
    {UINT64_C(0x8000010000000032), UINT64_C(0xffffffffffc0ffff)},
    {0, 0}, {UINT64_MAX, UINT64_MAX},
  };
  for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); ++i) {
    const uint64_t *src = inputs[i], *dst = inputs[(i + 1) %% 4];
    uint64_t want[rows][2], got[rows][2];
    original(src, dst, want);
    ShiftInsertRows(src, dst, got);
    for (int j = 0; j < rows; ++j) {
      if (got[j][0] != want[j][0] || got[j][1] != want[j][1]) {
        fprintf(stderr, "input %%u row %%d: %%016llx:%%016llx, want %%016llx:%%016llx\n", i, j,
          (unsigned long long)got[j][1], (unsigned long long)got[j][0],
          (unsigned long long)want[j][1], (unsigned long long)want[j][0]);
        return 1;
      }
    }
  }
  return 0;
}
`, len(words))
	for _, optimization := range []int{0, 2} {
		name := fmt.Sprintf("shift_insert_O%d", optimization)
		t.Run(name, func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, name, triple, ir, main.String(), runner, optimization)
		})
	}
}
