//go:build unix

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Reuse the complete original row fixture and its initialized producer. The
// object owner alone does not establish execution of these exact witnesses.
func explicitSIMDRuntimeProgram(t *testing.T) (assembly, declarations, goDriver, cDriver string) {
	t.Helper()
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	cases := explicitSIMD27OriginalCases(t, catalog)
	var source, decl, names, prototypes strings.Builder
	rows := make(map[string]bool)
	lines := 0
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprintf("OfficialSIMD%d", index)
		body, declaration := explicitSIMD27InitializedFunction(fixture.symbol, fixture.witness.Instruction, "amd64")
		position := strings.Index(body, "\n"+fixture.witness.Instruction+"\n")
		if position < 0 || strings.Count(body, "\n"+fixture.witness.Instruction+"\n") != 1 {
			t.Fatal("runtime producer lost the exact original instruction", fixture.row)
		}
		fixture.line = lines + strings.Count(body[:position+1], "\n") + 1
		lines += strings.Count(body, "\n")
		rows[fixture.row] = true
		source.WriteString(body)
		decl.WriteString(declaration)
		fmt.Fprintf(&names, "%s,\n", fixture.symbol)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *, uint8_t *, uint8_t *, uintptr_t);\n", fixture.symbol)
	}
	if len(rows) != 28 || len(cases) != 48 {
		t.Fatal("complete original SIMD runtime inventory changed", len(rows), len(cases))
	}
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("runtime source differs from original row encodings", err)
	}
	goDriver = strings.ReplaceAll(explicitSIMDOriginalGoDriver, "KERNEL_NAMES", names.String())
	cDriver = strings.NewReplacer("KERNEL_NAMES", names.String(), "KERNEL_PROTOTYPES", prototypes.String()).Replace(explicitSIMDTranslatedCDriver)
	return source.String(), decl.String(), goDriver, cDriver
}

func explicitSIMDRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	assembly, declarations, goDriver, cDriver := explicitSIMDRuntimeProgram(t)
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, assembly, goDriver)
	var reference []byte
	if execute {
		// SHA and SSE4.1 are real requirements of the original, unmodified
		// witnesses. An unavailable native instruction is never a passing skip.
		t.Logf("%s", execution.run(t, fixedLocalSHARuntimePreflight(t, execution)))
		reference = execution.run(t, original)
		if bytes.Count(reference, []byte{'\n'}) != 48*64 {
			t.Fatal("original Go did not execute every row/input", len(reference))
		}
		t.Logf("original Go: 28 rows, 48 exact witnesses, 3072 inputs; output SHA256 %x", sha256.Sum256(reference))
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete initialized runtime source", err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					if !execute {
						execution.compileLLVM(t, "official-explicit-simd", ir, cDriver, level)
						return
					}
					actual := execution.compileAndRunLLVM(t, "official-explicit-simd", ir, cDriver, level)
					if !bytes.Equal(actual, reference) {
						t.Fatalf("complete outputs differ from original Go: actual SHA256 %x, want %x", sha256.Sum256(actual), sha256.Sum256(reference))
					}
					t.Log("3072 original-Go comparisons PASS: vector, scalar, FLAGS, source bytes and output canaries")
				})
			}
		})
	}
}

func TestX86OfficialExplicitSIMDRuntimeObjects(t *testing.T) {
	explicitSIMDRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
	t.Log("complete original-Go and translated runtime programs compiled, not executed")
}

const explicitSIMDOriginalGoDriver = `package main

import (
    "fmt"
    "unsafe"
)

var kernels = []func(*[64]byte, *[16]byte, *[16]byte, uintptr){
KERNEL_NAMES
}

func main() {
    for row, kernel := range kernels {
        for sample := 0; sample < 64; sample++ {
            var first, second [32]byte
            align := func(storage *[32]byte) *[16]byte {
                base := unsafe.Pointer(&storage[0])
                offset := -uintptr(base) & 15
                return (*[16]byte)(unsafe.Add(base, offset))
            }
            a, b := align(&first), align(&second)
            state := uint64(row+1)*0x9e3779b97f4a7c15 ^ uint64(sample+1)*0xd1b54a32d192ed03
            next := func() byte {
                state ^= state << 13
                state ^= state >> 7
                state ^= state << 17
                return byte(state)
            }
            for lane := 0; lane < 16; lane++ {
                a[lane], b[lane] = next(), next()
            }
            var out [64]byte
            for lane := range out {
                out[lane] = byte(0xa5 ^ lane)
            }
            kernel(&out, a, b, uintptr(state))
            fmt.Printf("%d %d %x %x %x\n", row, sample, out[:], a[:], b[:])
        }
    }
}
`

const explicitSIMDTranslatedCDriver = `
#include <stdint.h>
#include <stdio.h>

KERNEL_PROTOTYPES

typedef void (*kernel)(uint8_t *, uint8_t *, uint8_t *, uintptr_t);
static kernel kernels[] = { KERNEL_NAMES };

static uint8_t next(uint64_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return (uint8_t)*state;
}

static void print_bytes(const uint8_t *data, unsigned length) {
    for (unsigned index = 0; index < length; index++) printf("%02x", data[index]);
}

int main(void) {
    for (unsigned row = 0; row < sizeof(kernels) / sizeof(kernels[0]); row++) {
        for (unsigned sample = 0; sample < 64; sample++) {
            uint8_t a[16] __attribute__((aligned(16)));
            uint8_t b[16] __attribute__((aligned(16)));
            uint8_t out[64];
            uint64_t state = (uint64_t)(row+1)*UINT64_C(0x9e3779b97f4a7c15) ^
                             (uint64_t)(sample+1)*UINT64_C(0xd1b54a32d192ed03);
            for (unsigned lane = 0; lane < 16; lane++) {
                a[lane] = next(&state);
                b[lane] = next(&state);
            }
            for (unsigned lane = 0; lane < sizeof(out); lane++) out[lane] = (uint8_t)(0xa5 ^ lane);
            kernels[row](out, a, b, (uintptr_t)state);
            printf("%u %u ", row, sample);
            print_bytes(out, sizeof(out));
            putchar(' ');
            print_bytes(a, sizeof(a));
            putchar(' ');
            print_bytes(b, sizeof(b));
            putchar('\n');
        }
    }
    return 0;
}
`
