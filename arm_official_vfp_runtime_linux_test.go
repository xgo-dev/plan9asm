package plan9asm

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMOfficialPredicatedVFP(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	source := armOfficialVFPSource()
	const main = `package main
import (
	"encoding/json"
	"os"
)
` + armOfficialVFPDeclaration + `
func main() {
	var result [3][14]uint64
	for index, selector := range [...]uint32{0, 1, 0x80000000} {
		var memory [8]uint64
		officialvfp(selector, &memory, &result[index])
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
`
	observation := armConversionGoObservations(t, source, main)
	var results [][14]uint64
	if err := json.Unmarshal(observation, &results); err != nil || len(results) != 3 {
		t.Fatalf("incomplete original Go VFP observations: %v\n%s", err, observation)
	}
	for index := range results[0] {
		if results[0][index] == results[1][index] && results[1][index] == results[2][index] {
			t.Fatalf("original VFP case %d did not observe the predicate", index)
		}
	}

	var driver strings.Builder
	driver.WriteString(`#include <stdint.h>
#include <stdio.h>
extern void officialvfp(uint32_t, uint64_t *, uint64_t *);
static const uint64_t expected[3][14] = {
`)
	for _, result := range results {
		driver.WriteString("{")
		for _, value := range result {
			fmt.Fprintf(&driver, "UINT64_C(0x%x),", value)
		}
		driver.WriteString("},\n")
	}
	driver.WriteString(`};
int main(void) {
    static const uint32_t selectors[] = {0, 1, UINT32_C(0x80000000)};
    for (unsigned i = 0; i < 3; i++) {
        uint64_t memory[8] = {0}, result[14] = {0};
        officialvfp(selectors[i], memory, result);
        for (unsigned j = 0; j < 14; j++) {
            if (result[j] != expected[i][j]) {
                fprintf(stderr, "predicate %u, VFP case %u: got %llx, want %llx\n",
                        i, j, (unsigned long long)result[j], (unsigned long long)expected[i][j]);
                return 1;
            }
        }
    }
    return 0;
}
`)
	ir := armOfficialVFPIR(t, source)
	for index, variant := range []string{ir, armFloatEffectOptimizedIR(t, ir)} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR%d/backend-O%d", index, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"official_vfp", armOfficialVFPTriple, variant, driver.String(),
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
			})
		}
	}
}
