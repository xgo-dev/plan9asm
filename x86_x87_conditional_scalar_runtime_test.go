package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x87ConditionalScalarLanes = 3

func x86X87ConditionalScalarCounterpart() (assembly, declaration string) {
	var source, types strings.Builder
	for lane := 1; lane <= x87ConditionalScalarLanes; lane++ {
		for _, op := range x87ConditionalMoveGo127Ops {
			name := fmt.Sprintf("conditional%sF%d", op, lane)
			fmt.Fprintf(&types, "func %s(a, b float64, predicate uint32) float64\n", name)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nFINIT\nFMOVD a+0(FP),F0\n", name)
			source.WriteString(strings.Repeat("FLD1\n", lane-1))
			fmt.Fprintf(&source, "FMOVD b+8(FP),F0\nMOVL predicate+16(FP),AX\nCMPL AX,$1\n"+
				"%s F%d,F0\nFMOVDP F0,ret+24(FP)\nFINIT\nRET\n", op, lane)
		}
	}
	return source.String(), types.String()
}

func x86X87ConditionalScalarC(main string) string {
	var source strings.Builder
	source.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef double (*conditional_fn)(double, double, uint32_t);
`)
	for lane := 1; lane <= x87ConditionalScalarLanes; lane++ {
		for _, op := range x87ConditionalMoveGo127Ops {
			fmt.Fprintf(&source, "extern double conditional%sF%d(double, double, uint32_t);\n", op, lane)
		}
	}
	source.WriteString("static const conditional_fn functions[][14] = {\n")
	for lane := 1; lane <= x87ConditionalScalarLanes; lane++ {
		source.WriteString("  {\n")
		for _, op := range x87ConditionalMoveGo127Ops {
			fmt.Fprintf(&source, "    conditional%sF%d,\n", op, lane)
		}
		source.WriteString("  },\n")
	}
	// Independent Intel condition names, not the lowerer's predicate table.
	source.WriteString(`};
static int selected(unsigned op, uint32_t input) {
  uint32_t difference = input - UINT32_C(1);
  unsigned parity = 0;
  for (unsigned bit = 0; bit < 8; ++bit) parity ^= (difference >> bit) & 1u;
  int cf = input < 1, zf = input == 1, pf = parity == 0;
  switch (op) {
  case 0: case 7: return !cf;          /* CC, NB */
  case 1: case 5: return cf;           /* CS, B */
  case 2: case 9: return zf;           /* EQ, E */
  case 3: case 8: return !cf && !zf;   /* HI, NBE */
  case 4: case 6: return cf || zf;     /* LS, BE */
  case 10: return !zf;                /* NE */
  case 11: return !pf;                /* NU */
  case 12: case 13: return pf;        /* U, UN */
  default: abort();
  }
}
void x87conditionalmovesemantics(uint8_t *raw) {
  double *data = (double *)raw;
  data[0] = conditionalFCMOVBF1(data[8], data[9], 0);
  data[1] = conditionalFCMOVNBF1(data[8], data[9], 0);
  data[2] = conditionalFCMOVEF1(data[8], data[9], 1);
  data[3] = conditionalFCMOVNEF1(data[8], data[9], 1);
  data[4] = conditionalFCMOVBEF1(data[8], data[9], 1);
  data[5] = conditionalFCMOVNBEF1(data[8], data[9], 1);
  data[6] = conditionalFCMOVUF1(data[8], data[9], 1);
  data[7] = conditionalFCMOVNUF1(data[8], data[9], 1);
  volatile uint32_t predicates[] = {0, 1, 2, 3, 255};
  volatile uint64_t bits[][2] = {
    {UINT64_C(0x3ff4000000000000), UINT64_C(0x4023000000000000)},
    {UINT64_C(0x8000000000000000), UINT64_C(0)},
    {UINT64_C(0x7ff8000000000042), UINT64_C(0x7ff0000000000000)},
    {UINT64_C(1), UINT64_C(0xc000000000000000)}
  };
  for (unsigned op = 0; op < 14; ++op) {
    for (unsigned p = 0; p < 5; ++p) {
      for (unsigned pair = 0; pair < 4; ++pair) {
        uint32_t predicate = predicates[p];
        uint64_t a_bits = bits[pair][0], b_bits = bits[pair][1], got_bits;
        double a, b, got;
        memcpy(&a, &a_bits, sizeof(a));
        memcpy(&b, &b_bits, sizeof(b));
        uint64_t expected = selected(op, predicate) ? a_bits : b_bits;
        for (unsigned lane = 0; lane < sizeof(functions)/sizeof(functions[0]); ++lane) {
          got = functions[lane][op](a, b, predicate);
          memcpy(&got_bits, &got, sizeof(got_bits));
          if (got_bits != expected) {
            fprintf(stderr, "conditional op=%u lane=%u predicate=%u pair=%u got=%llx expected=%llx\n",
              op, lane+1, predicate, pair, (unsigned long long)got_bits, (unsigned long long)expected);
            exit(1);
          }
        }
      }
    }
  }
}
`)
	source.WriteString(main)
	return source.String()
}

func TestX86X87ConditionalScalarCounterpartCompleteGoObject(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	assembly, declaration := x86X87ConditionalScalarCounterpart()
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil || len(file.Funcs) != 42 {
		t.Fatal("typed runtime counterpart lost a complete Go conditional family", err)
	}
	var names, locations []string
	for index, function := range file.Funcs {
		lane := index/len(x87ConditionalMoveGo127Ops) + 1
		op := x87ConditionalMoveGo127Ops[index%len(x87ConditionalMoveGo127Ops)]
		if function.Sym != fmt.Sprintf("conditional%sF%d", op, lane) ||
			function.ArgSize != 32 || function.FrameSize != 0 {
			t.Fatal("typed scalar function changed its identity or ABI0 layout", function.Sym)
		}
		names = append(names, function.Sym)
		locations = append(locations, fmt.Sprintf("%s F%d,F0", op, lane))
	}
	const triple = "x86_64-unknown-linux-gnu"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, assembly, declaration, "amd64", triple, api, X87Hardware)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				object := x86PackedStringCompileObject(t, llc, triple, ir, level)
				requireX86ELFTestFunctions(t, "amd64", object, names, locations)
			}
		})
	}
}

func TestX86X87ConditionalMoveHostSoftwareThreeAPIs(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang are required")
	}
	main := x86X87FunctionLiteral(t, "amd64_lower_x87_conditional_move_test.go",
		"TestAMD64X87ConditionalMoveRuntimeConditions", "mainC")
	assembly, declaration := x86X87ConditionalScalarCounterpart()
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/IR-O2-%t", api, optimized), func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, assembly, declaration, "amd64", triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("complete typed conditional source did not reach Software execution", err)
				}
				if optimized {
					ir = x86DwordProductIROptimize(t, ir)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "x87-conditional-scalar", triple, ir,
					x86X87ConditionalScalarC(main), nil)
			})
		}
	}
}
