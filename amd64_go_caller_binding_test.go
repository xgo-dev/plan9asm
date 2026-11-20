package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"
)

func TestX86GoCallerRegionBindingRequiresCompleteTypedSelection(t *testing.T) {
	for _, change := range []string{"none", "missing selection", "missing sizes", "wrong sizes", "changed source", "missing assembly"} {
		t.Run(change, func(t *testing.T) {
			pkg, selected, _, sig := x86CallerFixture(t, x86CallerFixtureSource)
			file := selected.Assembly["kernel_amd64.s"]
			pkg.SourceSelection = &selected
			sigs := map[string]FuncSig{sig.Name: sig}
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			switch change {
			case "missing selection":
				pkg.SourceSelection = nil
			case "missing sizes":
				selected.Sizes = nil
			case "wrong sizes":
				selected.Sizes = types.SizesFor("gc", "386")
			case "changed source":
				selected.GoSources["caller.go"] = []byte(x86CallerFixtureSource + "\nvar exposed = kernel\n")
			case "missing assembly":
				selected.SelectedAssemblyFiles = nil
			}
			bound, err := BindGoX86RawReturnCallerRegions(pkg, file, "amd64", resolve, sigs)
			if change == "none" {
				if err != nil || bound[sig.Name].x86CallerRegions == nil {
					t.Fatalf("actual selection acquired no private binding: %v", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) || bound != nil {
				t.Fatalf("%s obtained complete/partial binding: %+v, %v", change, bound, err)
			}
			if sigs[sig.Name].x86CallerRegions != nil {
				t.Fatal("caller-owned signature map was mutated")
			}
		})
	}
}
