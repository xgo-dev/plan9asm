package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// A correct but uncalled helper is not instruction coverage. Independently
// follow every public source body through dispatch and both IR levels.
func TestX86LockScalarRMWPublicBodiesCallCompleteNativeHelpers(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86LockScalarOracleForms(target.arch)
			want := 90
			if target.arch == "386" {
				want = 66
			}
			if len(rows) != want {
				t.Fatal("incomplete independent scalar LOCK family", len(rows), want)
			}
			var source, declarations strings.Builder
			declarations.WriteString("package ordering\n")
			names := make([]string, len(rows))
			helpers := make([]string, len(rows))
			for index, row := range rows {
				names[index] = fmt.Sprintf("locked%d", index)
				original := x86NamedLockOracleSource(target.arch, "CMPL AX,AX\nLOCK\n"+row.text)
				source.WriteString(strings.Replace(original, "·locked", "·"+names[index], 1))
				fmt.Fprintf(&declarations, "func %s(p *[16]byte)\n", names[index])
				bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
				stem := strings.ToLower(row.op[:len(row.op)-1])
				helpers[index] = fmt.Sprintf("__plan9asm_lock_rmw_0_%s_%s%d_native", target.arch, stem, bits)
				if strings.Contains(row.text, "$1") {
					helpers[index] += "_imm_0000000000000001"
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []int{0, 2} {
						t.Run(fmt.Sprintf("IR%d", level), func(t *testing.T) {
							text := ir
							if level == 2 {
								text = x86MulDivRoundOptimize(t, text)
							}
							bodies := x86StringMemoryFunctions(t, text, names)
							for index, name := range names {
								t.Run(rows[index].text, func(t *testing.T) {
									body := bodies[name]
									if strings.Count(body, "@"+helpers[index]+"(") != 1 {
										t.Fatal("public body bypassed its complete native LOCK helper", name, helpers[index], body)
									}
								})
							}
							for _, backend := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, backend)
							}
						})
					}
				})
			}
		})
	}
}
