package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialConditionalMoveRowsOriginalBytesAndObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, mode := range []struct {
		arch, triple string
		count        int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 96},
		{"386", "i386-unknown-linux-gnu", 64},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			rows, err := goasmrules.X86ConditionalMoveRows(catalog, mode.arch)
			if err != nil {
				t.Fatal(err)
			}
			var cases []x86OfficialPackedCase
			for _, row := range rows {
				if row.ModeFiltered != "" {
					continue
				}
				for _, witness := range row.Witnesses {
					cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: goasmrules.X86PackedBinaryWitness{Instruction: witness.Instruction, Encoding: witness.Encoding}})
				}
			}
			if len(rows) != 48 || len(cases) != mode.count {
				t.Fatal("complete conditional row/mode union changed", len(rows), len(cases))
			}
			for start := 0; start < len(cases); start += 32 {
				end := start + 32
				if end > len(cases) {
					end = len(cases)
				}
				t.Run(fmt.Sprint("batch", start/32), func(t *testing.T) {
					batch := cases[start:end]
					var source, declarations strings.Builder
					for index := range batch {
						fixture := &batch[index]
						fixture.symbol = fmt.Sprint("ConditionalOfficial", index)
						body, declaration := x86ConditionalMoveInitializedFunction(fixture.symbol, fixture.witness.Instruction, "BX", mode.arch)
						position := strings.Index(body, "\n"+fixture.witness.Instruction+"\n")
						if position < 0 {
							t.Fatal("original CMOV producer lost the exact observed instruction")
						}
						fixture.line = strings.Count(source.String(), "\n") + strings.Count(body[:position+1], "\n") + 1
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
					listing, err := x86ScalarLiteralGoListing(t, mode.arch, source.String())
					if err != nil {
						t.Fatal(err)
					}
					if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
						t.Fatal("actual original conditional-move row byte identity", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), mode.arch, mode.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized source/old/FLAGS and observable data+preserved status rejected", api, err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, mode.triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86OfficialConditionalMoveMode32Refusals(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86ConditionalMoveRows(catalog, "386")
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, row := range rows {
		if row.ModeFiltered == "" {
			continue
		}
		refused++
		for _, source := range []string{"CX", "0(SI)"} {
			t.Run(row.Opcode+"/"+source, func(t *testing.T) {
				assembly := "TEXT RefusedConditional(SB),4,$0-0\n" + row.Opcode + " " + source + ",BX\nRET\n"
				goAssemblerOracleOutput(t, "386", assembly, "", false)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, assembly, "func RefusedConditional()", "386", "i386-unknown-linux-gnu", api)
					if ir != "" || err == nil {
						t.Fatal("actual Go mode refusal acquired public translation", api, err)
					}
					if errors.Is(err, ErrProbeNeedsContext) {
						t.Log("mode/source context refusal retained separately from byte/object evidence")
					}
				}
			})
		}
	}
	if refused != 16 {
		t.Fatal("complete Q-width mode32 source refusal inventory changed", refused)
	}
}
