package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86LoweredVectorEntryRequiresTypedLogicalFrame(t *testing.T) {
	const bare = "TEXT ·Value(SB),4,$0-0\nPEXTRB $0,X0,AX\nTESTL AX,AX\nSETNE CX\nRET\n"
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", bare)
	for _, row := range []struct {
		name string
		sig  FuncSig
	}{
		{"synthetic-Void", FuncSig{Name: "Value", Ret: Void}},
		{"bare-register-result", FuncSig{Name: "Value", Ret: I64}},
	} {
		file, err := Parse(ArchAMD64, bare)
		if err != nil {
			t.Fatal(err)
		}
		for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
					Sigs:       map[string]FuncSig{"Value": row.sig},
					ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
				ir, err := x86PackedFloatStorageAPI(api, file, options)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("an empty frame acquired a declared ABI0 scratch choice", err)
				}
			})
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("declared-empty-Void/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, bare, "func Value()", "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an empty Go declaration supplied a nonempty logical frame", err)
			}
		})
	}
	for _, row := range []struct {
		name, source, declaration string
	}{
		{"typed-parameter-Void", strings.Replace(bare, "$0-0", "$0-8", 1), "func Value(unused uint64)"},
		{"typed-result", "TEXT ·Value(SB),4,$0-4\nPEXTRB $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n", "func Value() uint32"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				x86VectorScratchCodegenControl(t, row.source, row.declaration, "amd64", "x86_64-unknown-linux-gnu", ir, err)
			})
		}
	}
}
