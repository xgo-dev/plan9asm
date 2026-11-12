package plan9asm

import (
	"strings"
	"testing"
)

func TestX86SqrtIsolatedNativeFeatures(t *testing.T) {
	for _, arch := range []string{"", "amd64", "386"} {
		for _, row := range x86SqrtInputRows("amd64") {
			if arch == "386" && len(strings.Split(strings.SplitN(row, " ", 2)[1], ",")) == 4 {
				continue // No named mode32 four-operand spelling.
			}
			t.Run(arch+"/"+row, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				base := strings.SplitN(row, " ", 2)[0]
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0])
				want := []string{"+sse"}
				if strings.HasPrefix(base, "V") {
					want = []string{"+avx"}
					if strings.Contains(row, "Z2") || strings.Contains(row, "K1") || strings.Contains(base, ".") {
						want = []string{"+avx512f"}
						if !strings.Contains(row, "Z2") && (strings.HasPrefix(base, "VSQRTPS") || strings.HasPrefix(base, "VSQRTPD")) {
							want = append(want, "+avx512vl")
						}
					}
				} else if strings.HasSuffix(base, "SD") || strings.HasSuffix(base, "PD") {
					want = []string{"+sse2"}
				}
				for _, feature := range want {
					if !strings.Contains(","+features+",", ","+feature+",") {
						t.Fatalf("isolated opcode lacks its own native register class %s: %s", feature, features)
					}
				}
			})
		}
	}
}
