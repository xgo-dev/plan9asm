package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// All inputs have their actual roles: memory is a bounded typed source, BX is
// the old destination, CX the numerical source, and CMP defines CF/OF. Observe
// the whole GP result, including preserved bytes and a failed query/zero scan's
// old destination. Do not read BSF/BSR's undefined non-ZF status bits.
func x86ScalarRMRegisterInitializedFunction(name, operation, arch string) (string, string) {
	word, suffix := goWordSize(arch), "Q"
	if word == 4 {
		suffix = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),SI\n"+
		"MOV%s old+%d(FP),BX\nMOV%s input+%d(FP),CX\nCMPL CX,CX\n%s\n"+
		"MOV%s BX,ret+%d(FP)\nRET\n", name, 4*word, suffix,
		suffix, word, suffix, 2*word, operation, suffix, 3*word)
	declaration := fmt.Sprintf("func %s(memory *[8]byte,old,input uintptr) uintptr\n", name)
	return source, declaration
}

func TestX86OfficialScalarRMRegisterRowsOriginalBytesAndObjects(t *testing.T) {
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
		{"amd64", "x86_64-unknown-linux-gnu", 56},
		{"386", "i386-unknown-linux-gnu", 34},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			rows, err := goasmrules.X86ScalarRMRegisterRows(catalog, mode.arch)
			if err != nil {
				t.Fatal(err)
			}
			var cases []x86OfficialPackedCase
			for _, row := range rows {
				if row.ModeFiltered != "" {
					continue
				}
				for _, witness := range row.Witnesses {
					cases = append(cases, x86OfficialPackedCase{row: row.ID,
						witness: goasmrules.X86PackedBinaryWitness{Instruction: witness.Instruction, Encoding: witness.Encoding}})
				}
			}
			if len(rows) != 28 || len(cases) != mode.count {
				t.Fatal("complete original scalar row/mode union changed", len(rows), len(cases))
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
						fixture.symbol = fmt.Sprint("ScalarRMOfficial", index)
						body, declaration := x86ScalarRMRegisterInitializedFunction(fixture.symbol, fixture.witness.Instruction, mode.arch)
						position := strings.Index(body, "\n"+fixture.witness.Instruction+"\n")
						if position < 0 {
							t.Fatal("original scalar producer lost the exact observed instruction")
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
						t.Fatal("actual original scalar row byte identity", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), mode.arch, mode.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized scalar source/old destination/status rejected", api, err)
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

func TestX86OfficialScalarRMRegisterInitializedInputsRemainRequired(t *testing.T) {
	for _, item := range []struct{ operation, removed string }{
		{"ADCXL CX,BX", "CMPL CX,CX\n"},
		{"ADOXQ CX,BX", "CMPL CX,CX\n"},
		{"BSFW CX,BX", "MOVQ old+8(FP),BX\n"},
		{"LARQ CX,BX", "MOVQ old+8(FP),BX\n"},
		{"MOVWLSX CX,BX", "MOVQ input+16(FP),CX\n"},
		{"POPCNTL 0(SI),BX", "MOVQ memory+0(FP),SI\n"},
	} {
		t.Run(item.operation, func(t *testing.T) {
			source, declaration := x86ScalarRMRegisterInitializedFunction("ScalarInputs", item.operation, "amd64")
			if strings.Count(source, item.removed) != 1 {
				t.Fatal("negative does not remove exactly one original input", item.removed)
			}
			changed := strings.Replace(source, item.removed, "", 1)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("source-row syntax supplied a missing numerical/address/flag input", api, err)
				}
			}
		})
	}
}
