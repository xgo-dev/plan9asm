package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// A complete logical FP span is not one native pointer: Go scalar results
// have separate LLVM storage. Keep the original Go object and all public APIs
// independent of the register-only and native-memory emitter observations.
func TestX86PackedCompressLogicalFPResultsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []string{"VCOMPRESSPS", "VCOMPRESSPD", "VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ"} {
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				for _, mode := range []string{"unmasked", "merge"} {
					var results []string
					var body strings.Builder
					for index := 0; index < width.bytes/8; index++ {
						results = append(results, fmt.Sprintf("r%d uint64", index))
						for _, half := range []int{0, 4} {
							fmt.Fprintf(&body, "MOVL $-1,r%d+%d(FP)\n", index, 8+index*8+half)
						}
					}
					instruction := strings.Replace(x86CompactExpandResultInstruction(opcode, width.bank, mode), width.bank+"1", "r0+8(FP)", 1)
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nKMOVQ mask+0(FP),K1\nVPXORD Z0,Z0,Z0\n%s%s\nRET\n",
						width.bytes+8, body.String(), instruction)
					declaration := "func Value(mask uint64) (" + strings.Join(results, ",") + ")"
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+opcode+"/"+width.bank+"/"+mode+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("complete initialized logical result fields failed", err)
							}
							if strings.Contains(ir, "call void @llvm.masked.compressstore.") {
								t.Fatal("independent logical result fields were treated as one native pointer")
							}
						})
					}
				}
			}
		}
	}
}
