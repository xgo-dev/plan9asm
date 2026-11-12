package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestX86LegacyPackedRegisterMoveSparsePortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var assembly, declarations, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	// Independent bit-preserving source fixtures span both signs and byte
	// extrema. Every other source-vector byte deliberately remains unknown.
	for _, row := range []struct {
		op    string
		value uint32
	}{
		{"MOVOU", 0}, {"MOVOA", 1}, {"MOVO", 127}, {"MOVUPS", 128},
		{"MOVAPS", 165}, {"MOVUPD", 254}, {"MOVAPD", 255},
	} {
		name := "Copy" + row.op
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-4\nMOVL $%d,AX\nPINSRB $7,AX,X0\n%s X0,X1\nPEXTRB $7,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", name, row.value, row.op)
		fmt.Fprintf(&declarations, "func %s() uint32\n", name)
		fmt.Fprintf(&driver, "extern uint32_t %s(void);\n", name)
	}
	driver.WriteString(`int main(void) {
    const uint32_t expected[7] = {0, 1, 127, 128, 165, 254, 255};
    const uint32_t values[7] = {
        CopyMOVOU(), CopyMOVOA(), CopyMOVO(), CopyMOVUPS(),
        CopyMOVAPS(), CopyMOVUPD(), CopyMOVAPD()
    };
    for (unsigned i = 0; i < 7; ++i) {
        if (values[i] != expected[i]) {
            fprintf(stderr, "sparse register copy row=%u got=%u expected=%u\n", i, values[i], expected[i]);
            return 1;
        }
    }
    return 0;
}
`)
	goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
					text := ir
					if optimized {
						text = x86DwordProductIROptimize(t, ir)
					}
					for _, level := range []int{0, 2} {
						t.Run(fmt.Sprintf("backend-O%d", level), func(t *testing.T) {
							compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "sparse-legacy-copy", triple, text, driver.String(), nil, level)
						})
					}
				})
			}
		})
	}
}
