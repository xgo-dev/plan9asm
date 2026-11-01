package gotoolprofile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestInstrumentationABI0ObservationRetainsPublicLayoutWithoutPrivatePermission(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		for _, parameters := range []string{"value uint64", "values [3]uint64", "data []byte"} {
			t.Run(arch+"/"+parameters, func(t *testing.T) {
				source := "package replay\nfunc Probe(" + parameters + ") uintptr\n"
				input, pkg, declaration := instrumentationReplayFixture(t, source, arch)
				if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
					t.Fatal(err)
				}
				// Serialized layout observes all public fields. It cannot
				// reconstruct a live source-bound opaque declaration input.
				if strings.Contains(string(declaration.Layout), "arm64ABI0Declaration") {
					t.Fatal("private declaration input escaped into public metadata")
				}
				for _, axis := range []string{"result offset", "result width", "native contract"} {
					t.Run(axis, func(t *testing.T) {
						var layout plan9asm.FuncSig
						if err := json.Unmarshal(declaration.Layout, &layout); err != nil {
							t.Fatal(err)
						}
						switch axis {
						case "result offset":
							layout.Frame.Results[0].Offset++
						case "result width":
							layout.Frame.Results[0].Type = plan9asm.I8
						case "native contract":
							layout.ArgRegs = []plan9asm.Reg{"R0"}
						}
						changed := declaration
						var err error
						changed.Layout, err = json.Marshal(layout)
						if err != nil {
							t.Fatal(err)
						}
						if err := validateInstrumentationPackageDeclarations(input, pkg, []InstrumentationDeclarationProof{changed}); err == nil {
							t.Fatal("layout observation accepted an invented field or native contract")
						}
					})
				}
			})
		}
	}
}
