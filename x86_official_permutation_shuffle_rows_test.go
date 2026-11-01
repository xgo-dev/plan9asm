package plan9asm

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialPermutationShuffleRowsInitializedThreeAPIsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86PermutationShuffleRows, 84, 328, 0,
		x86OfficialPackedAssembly, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86PermutationShuffleInputsAndZeroingStayIndependent(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86PermutationShuffleRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.Opcode != "VPERMD" && row.Opcode != "VPERMPS" && !strings.HasPrefix(row.Opcode, "VSHUF") {
			continue
		}
		for _, witness := range row.Witnesses {
			if witness.Width != 512 || !witness.Masked || witness.Memory {
				continue
			}
			fixture := []x86OfficialPackedCase{{row: row.ID, witness: witness}}
			source, declarations := x86OfficialPackedAssembly(fixture)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Fatal("valid actual inputs must precede missing-input controls", row.ID, witness.Instruction, api, err)
				}
				seeds := []string{"VMOVUPS (AX),Z16\n", "VMOVUPS (BX),Z17\n", "KMOVQ CX,K1\n"}
				if !witness.Zeroing {
					seeds = append(seeds, "VMOVUPS (BX),Z18\n")
				}
				for _, seed := range seeds {
					changed := strings.Replace(source, seed, "", 1)
					if changed == source {
						t.Fatal("missing-input negative did not change its source", seed)
					}
					ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, "amd64", "x86_64-unknown-linux-gnu", api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("missing source/control/mask/merge input gained authority", witness.Instruction, api, seed, err)
					}
				}
			}
			count++
		}
	}
	if count != 12 {
		t.Fatal("complete six-member merge/zero input directory changed", count)
	}
}
