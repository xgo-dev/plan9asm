package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86BranchHintCompletePredicateResultObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word := goWordSize(target.arch)
			var source, declarations strings.Builder
			count := 0
			for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
				for hint := 0; hint <= 1; hint++ {
					name := fmt.Sprintf("Hint%s%d", condition, hint)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOVL a+0(FP),AX\nCMPL AX,AX\n"+
						"J%s $%d,taken\nMOVL $11,BX\nJMP done\ntaken:\nMOVL $19,BX\ndone:\nMOVL BX,ret+%d(FP)\nRET\n",
						name, word+4, condition, hint, word)
					fmt.Fprintf(&declarations, "func %s(a uint32) uint32\n", name)
					count++
				}
			}
			if count != 32 {
				t.Fatal("complete conditional hint/FLAGS inventory changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}
