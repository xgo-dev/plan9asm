package main

import (
	"errors"
	"fmt"
	"go/types"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestX86InferredFrameRequiresOriginalTextExtent(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := 4, "MOVL"
		if arch == "amd64" {
			word, move = 8, "MOVQ"
		}
		for _, test := range []struct {
			header string
			valid  bool
		}{
			{"$0", false},
			{"$0-0", false},
			{fmt.Sprintf("$0-%d", word-1), false},
			{fmt.Sprintf("$0-%d", word), true},
			{fmt.Sprintf("$0-%d", word*2), true},
		} {
			for _, hasPackage := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/package=%t", arch, test.header, hasPackage), func(t *testing.T) {
					file, err := plan9asm.Parse(plan9asm.ArchAMD64,
						"TEXT helper(SB),4,"+test.header+"\n"+move+" arg+0(FP),AX\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					var pkg *packages.Package
					if hasPackage {
						pkg = &packages.Package{
							Types:      types.NewPackage("example.com/fixture", "fixture"),
							TypesSizes: types.SizesFor("gc", arch),
						}
					}
					_, _, err = sigsForAsmFile(pkg, file, func(name string) string { return name }, arch)
					if test.valid && err != nil || !test.valid && !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
						t.Fatal("inferred FP words must fit the original explicit TEXT, not their own heuristic", err)
					}
				})
			}
		}
	}
}
