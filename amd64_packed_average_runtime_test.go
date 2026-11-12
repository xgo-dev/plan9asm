package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86AverageNumericCase struct {
	op                   string
	width, bits          int
	masking, destination int
	memory, mmx          bool
}

func x86AverageNumericCases() []x86AverageNumericCase {
	var cases []x86AverageNumericCase
	for index, op := range x86AverageNames {
		widths := []int{8, 16}
		if strings.HasPrefix(op, "V") {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			for _, memory := range []bool{false, true} {
				modes, destinations := 1, 1
				if strings.HasPrefix(op, "V") {
					modes, destinations = 3, 3
				}
				for mode := 0; mode < modes; mode++ {
					for destination := 0; destination < destinations; destination++ {
						cases = append(cases, x86AverageNumericCase{op, width, 8 << uint(index%2), mode, destination, memory, width == 8})
					}
				}
			}
		}
	}
	return cases
}

func (row x86AverageNumericCase) instruction() string {
	bank := map[int]string{8: "M", 16: "X", 32: "Y", 64: "Z"}[row.width]
	first := bank + "1"
	if row.memory {
		first = "(BX)"
	}
	if !strings.HasPrefix(row.op, "V") {
		return row.op + " " + first + "," + bank + "0"
	}
	op := row.op
	if row.masking == 2 {
		op += ".Z"
	}
	args := first + "," + bank + "0"
	if row.masking != 0 {
		args += ",K1"
	}
	return fmt.Sprintf("%s %s,%s%d", op, args, bank, row.destination)
}

func x86AverageNumericFixture(t *testing.T, cases []x86AverageNumericCase) (string, map[string]FuncSig, string) {
	t.Helper()
	var source, declarations, table strings.Builder
	sigs := make(map[string]FuncSig)
	for index, row := range cases {
		name := fmt.Sprintf("average%d", index)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-40
MOVQ out+0(FP),AX
MOVQ a+8(FP),BX
MOVQ b+16(FP),CX
MOVQ mask+24(FP),DX
VMOVUPS (CX),Z0
VMOVUPS (CX),Z2
KMOVQ DX,K1
`, name)
		if !row.memory || row.destination == 1 {
			source.WriteString("VMOVUPS (BX),Z1\n")
		}
		source.WriteString("PUSHQ flags+32(FP)\nPOPFQ\n")
		if row.mmx {
			source.WriteString("VMOVUPS Z0,(AX)\nMOVQ (CX),M0\nMOVQ (BX),M1\n")
		}
		source.WriteString(row.instruction() + "\n")
		if row.mmx {
			source.WriteString("MOVQ M0,(AX)\nEMMS\n")
		} else {
			fmt.Fprintf(&source, "VMOVUPS Z%d,(AX)\n", row.destination)
		}
		source.WriteString("PUSHFQ\nPOPQ R10\nMOVQ R10,64(AX)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*,uint64_t,uint64_t);\n", name)
		fmt.Fprintf(&table, "{%s,%d,%d,%d,%d,%d},\n", name, row.width, row.bits/8,
			row.masking, row.destination, x86FloatAddSubBoolInt(!strings.HasPrefix(row.op, "V")))
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	driver := declarations.String() + "static const struct {Kernel run;int width,bytes,masking,destination,legacy;} cases[]={\n" + table.String() + "};\n"
	return source.String(), sigs, driver
}

func x86AverageNumericProgram(t *testing.T, triple string, cases []x86AverageNumericCase) (string, string) {
	t.Helper()
	source, sigs, driver := x86AverageNumericFixture(t, cases)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "amd64", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir, driver
}

// Byte arithmetic is independent of the lowering specification. W lanes use
// explicit little-endian assembly and a 17-bit sum, including 65535+65535.
const x86AverageIndependentC = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
typedef void (*Kernel)(void *, const void *, const void *, uint64_t, uint64_t);
static unsigned lane(const uint8_t *p, int bytes) {
  unsigned value = p[0];
  if (bytes == 2) {
    value |= (unsigned)p[1] << 8;
  }
  return value;
}
static const uint64_t masks[] = {0, 1, UINT64_C(0xaaaaaaaa55555555), UINT64_MAX};
`

const x86AverageCheckC = `int main(void) {
  for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); row++) {
    for (int sample = 0; sample < 257; sample++) {
      for (int status = 0; status < 2; status++) {
        for (int m = 0; m < 4; m++) {
          _Alignas(64) uint8_t a[192], b[192], out[192];
          memset(a, 0xa7, sizeof(a));
          memset(b, 0xb9, sizeof(b));
          memset(out, 0xc3, sizeof(out));

          for (int i = 0; i < 64; i++) {
            a[64 + i] = (uint8_t)(sample * 71 + i * 37);
            b[64 + i] = (uint8_t)(sample * 19 - i * 13);
            if (sample < 4) {
              a[64 + i] = (uint8_t[]){255, 0, 128, 255}[sample];
              b[64 + i] = (uint8_t[]){255, 1, 128, 0}[sample];
            }
          }
          uint8_t beforeA[192], beforeB[192];
          memcpy(beforeA, a, sizeof(a));
          memcpy(beforeB, b, sizeof(b));

          uint32_t saved = _mm_getcsr(),
                   profile = (uint32_t)(0x1f80 | ((sample % 4) << 13) | (sample % 64));
          _mm_setcsr(profile);
          uint64_t seed = status ? UINT64_C(0x8d5) : 0;
          cases[row].run(out + 64, a + 64, b + 64, masks[m], seed);
          uint32_t after = _mm_getcsr();
          _mm_setcsr(saved);
          uint64_t flags;
          memcpy(&flags, out + 128, 8);
          if (after != profile || (flags & UINT64_C(0x8d5)) != seed ||
              memcmp(a, beforeA, sizeof(a)) || memcmp(b, beforeB, sizeof(b))) {
            fprintf(stderr, "row%u sample%d CSR/flags/input\n", row, sample);
            return 1;
          }

          for (int i = 0; i < 64; i++) {
            int start = i / cases[row].bytes * cases[row].bytes;
            unsigned value = (lane(a + 64 + start, cases[row].bytes) +
                              lane(b + 64 + start, cases[row].bytes) + 1) /
                             2;
            int active =
                !cases[row].masking || ((masks[m] >> (i / cases[row].bytes)) & 1);
            uint8_t old = cases[row].destination == 1 ? a[64 + i] : b[64 + i];
            uint8_t want =
                i < cases[row].width
                    ? (active ? (uint8_t)(value >> (8 * (i % cases[row].bytes)))
                       : cases[row].masking == 2 ? 0
                                                 : old)
                : cases[row].legacy ? b[64 + i]
                                    : 0;
            if (out[64 + i] != want) {
              fprintf(stderr, "row%u sample%d mask%llx byte%d got%x want%x\n", row,
                      sample, (unsigned long long)masks[m], i, out[64 + i], want);
              return 2;
            }
          }
          for (int i = 0; i < 192; i++) {
            if ((i < 64 || i >= 136) && out[i] != 0xc3) {
              return 3;
            }
          }
        }
      }
    }
  }
  puts("complete average bytes/flags/MXCSR/input/output canaries");
  return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86PackedAverageIndependentBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	cases := x86AverageNumericCases()
	ir, table := x86AverageNumericProgram(t, execution.triple, cases)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "average-independent", ir,
				x86AverageIndependentC+table+x86AverageCheckC, level)
			if !strings.Contains(string(output), "complete average bytes") {
				t.Fatal("missing full numerical receipt", string(output))
			}
		})
	}
	t.Logf("%d programs × 257 patterns × 2 flags × 4 masks, full 64-byte views, O0/O2; translated wide shadow views, not original EVEX runtime", len(cases))
}

func TestCrossLinuxRuntimeMatrixX86PackedAverageInactiveMemory(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var cases []x86AverageNumericCase
	for _, op := range x86AverageNames[2:] {
		bits := 8
		if strings.HasSuffix(op, "W") {
			bits = 16
		}
		for _, width := range []int{16, 32, 64} {
			for _, mode := range []int{1, 2} {
				cases = append(cases, x86AverageNumericCase{op, width, bits, mode, 0, true, false})
			}
		}
	}
	ir, table := x86AverageNumericProgram(t, execution.triple, cases)
	// Unlike a post-load select, an E4.nb masked read cannot touch the guard
	// page. With mask 1 only the first byte/word is accessible; mask 0 has no
	// accessible source bytes. Full virtual FP spans are tested separately.
	const main = x86TestGuardPagesC + `
#ifndef _WIN32
#include <sys/resource.h>
#endif
int main(void) {
#ifndef _WIN32
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core)) {
    return 9;
  }
#endif
  if (setup_guard()) {
    return 11;
  }

  _Alignas(64) uint8_t b[64], out[80];
  memset(b, 0x91, 64);
  for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); row++) {
    for (int active = 0; active < 2; active++) {
      memset(out, 0xc3, 80);
      uint8_t *a = guard + page - (active ? cases[row].bytes : 0);
      if (active) {
        memset(a, 0xff, (size_t)cases[row].bytes);
      }
      cases[row].run(out + 1, a, b, (uint64_t)active, 0);
      for (int i = 0; i < 64; i++) {
        unsigned value = (cases[row].bytes == 1 ? 255 : 65535) +
                         (cases[row].bytes == 1 ? 0x91 : 0x9191) + 1;
        value /= 2;
        uint8_t want = i < cases[row].width
                           ? (active && i < cases[row].bytes
                                  ? (uint8_t)(value >> (8 * (i % cases[row].bytes)))
                              : cases[row].masking == 2 ? 0
                                                        : b[i])
                           : 0;
        if (out[i + 1] != want) {
          return 12;
        }
      }
      for (int i = 0; i < 80; i++) {
        if ((i == 0 || i >= 73) && out[i] != 0xc3) {
          return 13;
        }
      }
    }
  }
  if (free_guard()) {
    return 14;
  }
  puts("inactive guard-page reads suppressed");
  return 0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "average-inactive", ir, x86AverageIndependentC+table+main, level)
			if !strings.Contains(string(output), "inactive guard-page reads suppressed") {
				t.Fatal("missing masked memory receipt", string(output))
			}
		})
	}
}
