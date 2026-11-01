package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// Every function initializes only one complete lane in each numerical input.
// The other lanes remain unknown even though the translated operation covers
// the original complete X/Y view. Memory operands still read their full tuple.
func x86CompareLaneValueFixture(memoryForms bool) (string, string, string) {
	var declarations, source, checks strings.Builder
	for index, row := range x86CompareLaneCases() {
		for _, memory := range []bool{false, true} {
			if memory && !memoryForms {
				continue
			}
			name := fmt.Sprintf("laneCompare%d_%t", index, memory)
			fmt.Fprintf(&declarations, "func %s(a,b *[32]byte) uint32\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-20\nMOVQ a+0(FP),SI\nMOVQ b+8(FP),DI\n", name)
			start := 16 - row.bytes
			for offset := start; offset < 16; offset++ {
				if !memory {
					fmt.Fprintf(&source, "PINSRB $%d,%d(SI),X0\n", offset, offset)
				}
				fmt.Fprintf(&source, "PINSRB $%d,%d(DI),X%d\n", offset, offset, row.second())
			}
			first := row.bank + "0"
			if memory {
				first = "(SI)"
			}
			source.WriteString(row.instruction(first) + "\n")
			fmt.Fprintf(&source, "PEXTRB $%d,X2,AX\nMOVL AX,ret+16(FP)\nRET\n", start)
			fmt.Fprintf(&checks, "    if (checkLane(%s,\"%s\",%d,%d)) return 1;\n",
				name, name, row.bytes, x86FloatAddSubBoolInt(strings.Contains(row.op, "GT")))
		}
	}
	return declarations.String(), source.String(), checks.String()
}

func TestX86PackedCompareLaneCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("partial-lane comparison objects require LLVM22 llc")
	}
	declarations, source, _ := x86CompareLaneValueFixture(true)
	if strings.Count(source, "TEXT ") != 48 {
		t.Fatal("incomplete independent register/full-memory comparison family")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86PackedIntegerCompareAPI(t, source, declarations, "amd64", triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete partial-lane objects", err)
				}
				for _, optimized := range []bool{false, true} {
					input := ir
					if optimized {
						input = x86UndefinedTrapOptimizedIR(t, input)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, input, level)
					}
				}
			})
		}
	}
}

// This independent oracle compares unsigned bit patterns with sign-bit bias,
// avoiding signed C overflow and implementation-defined signed conversion.
// Plan9 GT compares its second operand against its first operand.
const x86ComparePartialLaneOracle = `
static uint64_t laneValue(const uint8_t *p, int bytes) {
    uint64_t value = 0;
    for (int i = 0; i < bytes; ++i) value |= (uint64_t)p[i] << (8*i);
    return value;
}

static int checkLane(uint32_t (*fn)(const uint8_t *, const uint8_t *),
                     const char *name, int bytes, int greater) {
    const uint64_t sign = UINT64_C(1) << (8*bytes-1);
    const uint64_t limit = bytes == 8 ? UINT64_MAX : (UINT64_C(1) << (8*bytes))-1;
    const uint64_t values[] = {
        0, 1, sign-1, sign, limit, UINT64_C(0x5555555555555555) & limit,
        UINT64_C(0xaaaaaaaaaaaaaaaa) & limit
    };
    for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]) + 8*bytes; ++i) {
        uint64_t first = i < sizeof(values)/sizeof(values[0]) ? values[i] :
            UINT64_C(1) << (i-sizeof(values)/sizeof(values[0]));
        for (unsigned j = 0; j < sizeof(values)/sizeof(values[0]); ++j) {
            uint64_t second = values[j];
            for (int alignment = 0; alignment < 3; ++alignment) {
                uint8_t aStorage[40], bStorage[40], savedA[40], savedB[40];
                memset(aStorage,0xa7,sizeof(aStorage));
                memset(bStorage,0xb9,sizeof(bStorage));
                uint8_t *a = aStorage+alignment, *b = bStorage+alignment;
                int start = 16-bytes;
                for (int k = 0; k < bytes; ++k) {
                    a[start+k] = (uint8_t)(first >> (8*k));
                    b[start+k] = (uint8_t)(second >> (8*k));
                }
                memcpy(savedA,aStorage,sizeof(savedA));
                memcpy(savedB,bStorage,sizeof(savedB));
                uint64_t av = laneValue(a+start,bytes), bv = laneValue(b+start,bytes);
                uint32_t want = (greater ? (bv ^ sign) > (av ^ sign) : av == bv) ? 255 : 0;
                uint32_t got = fn(a,b);
                if (got != want || memcmp(savedA,aStorage,sizeof(savedA)) ||
                    memcmp(savedB,bStorage,sizeof(savedB))) {
                    fprintf(stderr,"%s bytewidth%d first%llx second%llx got%u want%u\n",
                            name,bytes,(unsigned long long)av,(unsigned long long)bv,got,want);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`

func TestX86PackedCompareLanePortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("portable partial-lane comparisons require LLVM22 llc/clang")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler := []string{clang}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	declarations, source, checks := x86CompareLaneValueFixture(false)
	if strings.Count(source, "TEXT ") != 24 {
		t.Fatal("incomplete independent portable comparison family")
	}
	var prototypes strings.Builder
	for index := range x86CompareLaneCases() {
		fmt.Fprintf(&prototypes, "extern uint32_t laneCompare%d_false(const uint8_t *,const uint8_t *);\n", index)
	}
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() +
		x86ComparePartialLaneOracle + "\nint main(void) {\n" + checks + "    return 0;\n}\n"
	// Register EQ/GT lowering is portable LLVM. This is actual numerical
	// execution on the host, not original-Go native x86/AVX execution credit.
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86PackedIntegerCompareAPI(t, source, declarations, "amd64", triple, api)
		if err != nil || ir == "" {
			t.Fatal("complete portable partial-lane source", api, err)
		}
		for _, optimized := range []bool{false, true} {
			input := ir
			if optimized {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/IR_O2=%t/backendO%d", api, optimized, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler,
						"partial-compare-lanes", triple, input, driver, nil, level)
				})
			}
		}
	}
}
