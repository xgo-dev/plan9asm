package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Include narrow conversion results as well as whole X/Y/Z carriers. This
// independent helper domain is a superset of the current typed callers, not an
// inventory or execution certificate for the instructions which call it.
func x86IntegerLaneMaskShapes() []struct{ lanes, bits int } {
	var shapes []struct{ lanes, bits int }
	for _, bits := range []int{8, 16, 32, 64} {
		for lanes := 1; lanes <= 64 && lanes*bits <= 512; lanes *= 2 {
			shapes = append(shapes, struct{ lanes, bits int }{lanes, bits})
		}
	}
	return shapes
}

func TestX86IntegerLaneMaskBoundedVectorIR(t *testing.T) {
	for _, shape := range x86IntegerLaneMaskShapes() {
		for _, zeroing := range []bool{false, true} {
			name := fmt.Sprintf("%dxi%d/zeroing=%t", shape.lanes, shape.bits, zeroing)
			t.Run(name, func(t *testing.T) {
				var body strings.Builder
				ctx := &amd64Ctx{b: &body}
				result := amd64ApplyIntegerLaneMask(ctx, shape.lanes, shape.bits,
					"%computed", "%unavailableOld", "%mask", zeroing)
				ir := body.String()
				if got := strings.Count(ir, " = "); got != 5 {
					t.Fatalf("mask helper emitted %d instructions; want five independent of lane count:\n%s", got, ir)
				}
				for _, forbidden := range []string{"extractelement", "select i1 ", "bitcast i64", "lshr i64"} {
					if strings.Contains(ir, forbidden) {
						t.Fatalf("lane mask expanded scalar operations or used endian-dependent packing %q:\n%s", forbidden, ir)
					}
				}
				for _, want := range []string{
					fmt.Sprintf("lshr <%d x i64>", shape.lanes),
					fmt.Sprintf("trunc <%d x i64>", shape.lanes),
					fmt.Sprintf("select <%d x i1>", shape.lanes),
				} {
					if !strings.Contains(ir, want) {
						t.Fatalf("mask predicate lacks %q:\n%s", want, ir)
					}
				}
				if zeroing && strings.Contains(ir, "%unavailableOld") {
					t.Fatal("zeroing read the unavailable old destination")
				}
				if !zeroing && strings.Count(ir, "%unavailableOld") != 1 {
					t.Fatal("merge must select the old vector exactly once")
				}
				if !strings.Contains(ir, result+" = select ") {
					t.Fatal("helper did not return the selected vector")
				}
			})
		}
	}
}

func TestX86IntegerLaneMaskEmptyShape(t *testing.T) {
	for _, lanes := range []int{-1, 0} {
		for _, zeroing := range []bool{false, true} {
			var body strings.Builder
			ctx := &amd64Ctx{b: &body}
			want := "%old"
			if zeroing {
				want = "zeroinitializer"
			}
			got := amd64ApplyIntegerLaneMask(ctx, lanes, 8, "%computed", "%old", "%mask", zeroing)
			if got != want || body.Len() != 0 {
				t.Fatalf("empty shape lanes=%d zeroing=%t emitted %q, %q", lanes, zeroing, got, body.String())
			}
		}
	}
}

// Exercise the helper's emitted LLVM with an independent byte-selection C
// oracle. No native ISA attributes or scalar-mask bitcasts are needed. Physical
// x86 instruction behavior and active-lane memory faults retain separate owners.
func TestX86IntegerLaneMaskPortableSemantics(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	var module, prototypes, checks strings.Builder
	count := 0
	for _, shape := range x86IntegerLaneMaskShapes() {
		for _, zeroing := range []bool{false, true} {
			name := fmt.Sprintf("laneMask%d", count)
			count++
			vec := fmt.Sprintf("<%d x i%d>", shape.lanes, shape.bits)
			fmt.Fprintf(&module, "define void @%s(ptr %%out, ptr %%input, ptr %%prior, i64 %%mask) {\n", name)
			fmt.Fprintf(&module, "  %%computed = load %s, ptr %%input, align 1\n", vec)
			if !zeroing {
				fmt.Fprintf(&module, "  %%old = load %s, ptr %%prior, align 1\n", vec)
			}
			ctx := &amd64Ctx{b: &module}
			result := amd64ApplyIntegerLaneMask(ctx, shape.lanes, shape.bits, "%computed", "%old", "%mask", zeroing)
			fmt.Fprintf(&module, "  store %s %s, ptr %%out, align 1\n  ret void\n}\n", vec, result)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&checks, "    if (check(%s, %q, %d, %d, %t)) return 1;\n",
				name, name, shape.lanes, shape.bits/8, zeroing)
		}
	}
	if count != 44 {
		t.Fatal("incomplete independent lane-mask shape/mode union", count)
	}
	driver := strings.NewReplacer("PROTOTYPES", prototypes.String(), "CHECKS", checks.String()).Replace(x86IntegerLaneMaskDriver)
	ir := module.String()
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "i386-unknown-linux-gnu"} {
		t.Run("baseline-object/"+triple, func(t *testing.T) {
			x86ResultInitializationObject(t, execution.llc, triple, ir, "lane-mask-baseline")
		})
	}
	for _, optimized := range []bool{false, true} {
		text := ir
		if optimized {
			text = x86MulDivRoundOptimize(t, ir)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(fmt.Sprintf("IR-O2=%t/%s", optimized, level), func(t *testing.T) {
				execution.compileAndRunLLVM(t, "integer-lane-mask", text, driver, level)
			})
		}
	}
}

const x86IntegerLaneMaskDriver = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES

static int check(void (*fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t),
                 const char *name, unsigned lanes, unsigned bytes, bool zeroing) {
    uint64_t masks[69] = {0, UINT64_MAX, UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)};
    for (unsigned bit = 0; bit < 64; ++bit) {
        masks[4+bit] = UINT64_C(1) << bit;
    }
    masks[68] = lanes == 64 ? 0 : UINT64_MAX << lanes;
    for (unsigned sample = 0; sample < 8; ++sample) {
        uint8_t input[66], prior[66], originalInput[66], originalPrior[66], output[66];
        for (unsigned i = 0; i < 66; ++i) {
            input[i] = (uint8_t)(sample*71 + i*29 + 1);
            prior[i] = (uint8_t)(sample*13 - i*47 + 128);
        }
        memcpy(originalInput, input, sizeof(input));
        memcpy(originalPrior, prior, sizeof(prior));
        for (unsigned m = 0; m < 69; ++m) {
            memset(output, 0xa7, sizeof(output));
            fn(output+1, input+1, zeroing ? NULL : prior+1, masks[m]);
            for (unsigned offset = 0; offset < 64; ++offset) {
                uint8_t want = 0xa7;
                if (offset < lanes*bytes) {
                    unsigned active = (unsigned)((masks[m] >> (offset/bytes)) & 1);
                    if (active) {
                        want = input[offset+1];
                    } else if (zeroing) {
                        want = 0;
                    } else {
                        want = prior[offset+1];
                    }
                }
                if (output[offset+1] != want) {
                    fprintf(stderr, "%s sample=%u mask=%llx byte=%u got=%x want=%x\n",
                            name, sample, (unsigned long long)masks[m], offset, output[offset+1], want);
                    return 1;
                }
            }
            if (output[0] != 0xa7 || output[65] != 0xa7 ||
                memcmp(input, originalInput, sizeof(input)) || memcmp(prior, originalPrior, sizeof(prior))) {
                fprintf(stderr, "%s changed inputs or output canaries\n", name);
                return 1;
            }
        }
    }
    return 0;
}

int main(void) {
CHECKS
    return 0;
}
`
