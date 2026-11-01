package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Unmasked block extraction is a portable bit copy. Masked E6NF stores retain
// their independent required native original-Go/LLVM runtime owner.
func TestX86BlockExtractUnmaskedStorePortableBytes(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, originalTriple, move, word := "amd64", "x86_64-unknown-linux-gnu", "MOVQ", 8
	if strconv.IntSize == 32 {
		arch, originalTriple, move, word = "386", "i386-unknown-linux-gnu", "MOVL", 4
	}
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, row := range x86BlockNativeStoreRows(arch) {
		if strings.Contains(row, "K1") {
			continue
		}
		chunk, width, _ := x86InsertExtractMaskedMemoryShape(row)
		for _, selector := range []int{0, 1, 2, 3, 255} {
			name := fmt.Sprint("Store", count)
			instruction := strings.Replace(row, "$255", fmt.Sprint("$", selector), 1)
			fmt.Fprintf(&declarations, "func %s(out, input *byte)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),BX\n%s input+%d(FP),DX\nVMOVUPS (DX),Z1\n%s\nRET\n",
				name, 2*word, move, move, word, instruction)
			fmt.Fprintf(&prototypes, "extern void %s(void*,const void*);\n", name)
			fmt.Fprintf(&rows, "{%s,%d,%d},\n", name, chunk, (selector%(width/chunk))*chunk)
			count++
		}
	}
	if count != 70 {
		t.Fatal("incomplete unmasked extraction/selector inventory", count)
	}
	x86LEAActualTargetGoObject(t, arch, originalTriple, source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() + `
static const struct {
    void (*run)(void*,const void*);
    unsigned width, offset;
} cases[] = {
` + rows.String() + `
};
int main(void) {
    for (unsigned row = 0; row < sizeof(cases)/sizeof(cases[0]); ++row) {
        for (unsigned sample = 0; sample < 257; ++sample) {
            uint8_t input[66], original[66], output[66], expected[66];
            for (unsigned byte = 0; byte < sizeof(input); ++byte)
                input[byte] = (uint8_t)((byte*31 + sample*17) ^ (sample>>1));
            memcpy(original, input, sizeof(input));
            memset(output, 0xa5, sizeof(output));
            memcpy(expected, output, sizeof(output));
            memcpy(expected+1, input+1+cases[row].offset, cases[row].width);
            cases[row].run(output+1, input+1);
            if (memcmp(output, expected, sizeof(output)) ||
                memcmp(input, original, sizeof(input))) {
                fprintf(stderr, "row=%u sample=%u block bytes or canaries differ\n", row, sample);
                return 1;
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("initialized unmasked extraction rejected", err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86DwordProductIROptimize(t, text)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "block-extract-store",
							triple, text, driver, nil, level)
					})
				}
			}
		})
	}
}
