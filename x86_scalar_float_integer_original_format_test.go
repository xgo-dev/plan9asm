package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Pair every original named encoder row with actual producers. An initialized
// vector does not supply a physical SP/BP, segment, AUTO or FP pointer value;
// those separate storage/entry roles remain explicit Context controls.
func TestX86ScalarFloatIntegerOriginalRowsInitializedNamedCounterparts(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			type sample struct {
				source, declaration string
				context             bool
			}
			var samples []sample
			var original strings.Builder
			for index, row := range x86ScalarFloatIntegerFormRows(target.arch) {
				ins := x86ScalarLaneInstruction(t, row)
				_, known, err := x86ScalarFloatIntegerProperties(ins, target.arch)
				if !known || err != nil && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original named directory became malformed", row, err)
				}
				context := err != nil || x86LogicalSourceFrameRegister(ins.Args[1].Reg, target.arch)
				setup := fmt.Sprintf("%s p+0(FP),BX\nMOVL $0,CX\n", move)
				source := ins.Args[0]
				if source.Kind == OpReg {
					bank, _ := amd64ParseXReg(source.Reg)
					if target.arch == "386" && bank >= 8 {
						// Go accepts the original row, but this mode has no
						// independent physical producer for its high bank.
						// Initialize only an unrelated, legal low register.
						context = true
						setup += "PXOR X0,X0\n"
					} else if bank >= 16 {
						setup += fmt.Sprintf("VPXORD Z%d,Z%d,Z%d\n", bank, bank, bank)
					} else {
						setup += fmt.Sprintf("PXOR %s,%s\n", source.Reg, source.Reg)
					}
				} else if source.Kind != OpMem || source.Mem.Sym != "" || source.Mem.Base != BX {
					context = true
				}
				name := fmt.Sprintf("originalrow%d", index)
				body := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s%s\nRET\n", name, word, setup, row)
				decl := fmt.Sprintf("func %s(p *byte)\n", name)
				samples = append(samples, sample{body, decl, context})
				original.WriteString(body)
			}
			goAssemblerOracleOutput(t, target.arch, original.String(), "", true)
			var body, declarations strings.Builder
			positive, contextual, batch, count := 0, 0, 0, 0
			flush := func() {
				if count == 0 {
					return
				}
				t.Run(fmt.Sprintf("initialized-batch-%d", batch), func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							if _, err := x86ScalarFPBitViewAPI(t, body.String(), declarations.String(), target.arch, target.triple, api); err != nil {
								t.Fatal("complete initialized original rows did not close", err)
							}
						})
					}
				})
				body.Reset()
				declarations.Reset()
				batch++
				count = 0
			}
			for index, item := range samples {
				if item.context {
					contextual++
					t.Run(fmt.Sprintf("independent-storage-role-%d", index), func(t *testing.T) {
						for _, api := range []string{"text", "module", "Go"} {
							_, err := x86ScalarFPBitViewAPI(t, item.source, "var data [8]byte\n"+item.declaration, target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("initialized source supplied a different native storage/entry role", api, err)
							}
						}
					})
					continue
				}
				positive++
				body.WriteString(item.source)
				declarations.WriteString(item.declaration)
				count++
				if count == 96 {
					flush()
				}
			}
			flush()
			if positive+contextual != len(samples) {
				t.Fatal("original named directory lost a row")
			}
			t.Logf("all %d original named rows: %d independently initialized, %d require a separate storage/physical-entry role; 3 public APIs; not native execution", len(samples), positive, contextual)
		})
	}
}
