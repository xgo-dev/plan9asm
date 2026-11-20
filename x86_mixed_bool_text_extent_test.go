package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86MixedBoolOmittedTEXTArguments(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range []struct {
			extent string
			valid  bool
		}{
			{"$0", true},
			{fmt.Sprintf("$0-%d", 2*word+1), true},
			{"$0-0", false},
			{fmt.Sprintf("$0-%d", 2*word), false},
			{fmt.Sprintf("$0-%d", 3*word), false},
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,%s\n%s $5,n+%d(FP)\nMOVB $1,ok+%d(FP)\nRET\n",
				row.extent, move, word, 2*word)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.extent+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func Value(p *byte) (n uintptr, ok bool)", target.arch, target.triple, api)
					if row.valid {
						if err != nil || ir == "" {
							t.Fatalf("ordinary typed mixed result rejected TEXT extent %s: %v", row.extent, err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("explicit TEXT mismatch gained a frame: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}
