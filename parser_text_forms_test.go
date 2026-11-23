package plan9asm

import "testing"

func TestTEXTSourceOperandsMatchGo(t *testing.T) {
	targets := []struct {
		goarch string
		parse  Arch
	}{{"386", ArchAMD64}, {"amd64", ArchAMD64}, {"arm", ArchARM}, {"arm64", ArchARM64}, {"wasm", ArchWASM}}
	for _, target := range targets {
		for _, row := range []struct {
			name, operands string
			accepted       bool
		}{
			{"two-operands", "·Value(SB),$0-0", true},
			{"three-operands", "·Value(SB),4,$0-0", true},
			{"omitted-arg-size", "·Value(SB),$0", true},
			{"explicit-zero-offset", "·Value+0(SB),$0-0", true},
			{"nonzero-symbol-offset", "·Value+1(SB),$0-0", false},
			{"missing-frame", "·Value(SB)", false},
			{"non-immediate-frame", "·Value(SB),4", false},
			{"extra-operand", "·Value(SB),4,$0-0,$0-0", false},
			{"empty-flags", "·Value(SB),,$0-0", false},
		} {
			t.Run(target.goarch+"/"+row.name, func(t *testing.T) {
				source := "TEXT " + row.operands + "\nRET\n"
				goAssemblerOracleOutput(t, target.goarch, source, "", row.accepted)
				file, err := Parse(target.parse, source)
				if !row.accepted {
					if err == nil {
						t.Fatal("parser accepted a TEXT declaration rejected by Go")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(file.Funcs) != 1 || file.Funcs[0].Sym != "·Value" {
					t.Fatalf("function symbol or zero-offset normalization changed: %+v", file.Funcs)
				}
			})
		}
	}
}
