package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x87EncodedTenByteProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	word, move := goWordSize(arch), "MOVQ"
	if word == 4 {
		move = "MOVL"
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, entry := range catalog.Optab {
		switch entry.Opcode {
		case "FMOVB", "FMOVBP", "FMOVX", "FMOVXP", "FBLD", "FBSTP":
			if len(entry.Rows) != 1 || entry.Rows[0].RowIndex != 0 {
				t.Fatal("original ten-byte instruction schema changed", entry)
			}
			ids[entry.Opcode] = fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab)
		}
	}
	if len(ids) != 6 {
		t.Fatal("incomplete original ten-byte instruction family", ids)
	}
	var source, declarations strings.Builder
	var original [2][]x86OfficialPackedCase
	lines := 0
	type copyForm struct {
		name, input, output string
		load, store         string
		loadCode, storeCode []byte
	}
	forms := []copyForm{
		{"CopyBCD", "SI", "DI", "FMOVB (SI),F0", "FMOVBP F0,(DI)", []byte{0xdf, 0x26}, []byte{0xdf, 0x37}},
		{"CopyExtended", "SI", "DI", "FMOVX (SI),F0", "FMOVXP F0,(DI)", []byte{0xdb, 0x2e}, []byte{0xdb, 0x3f}},
	}
	if arch == "amd64" {
		// The exact FBLD/FBSTP occurrences and bytes in amd64enc.s.
		forms = append(forms,
			copyForm{"CopyBCDFromBX", "BX", "R11", "FBLD (BX)", "FBSTP (R11)", []byte{0xdf, 0x23}, []byte{0x41, 0xdf, 0x33}},
			copyForm{"CopyBCDFromR11", "R11", "BX", "FBLD (R11)", "FBSTP (BX)", []byte{0x41, 0xdf, 0x23}, []byte{0xdf, 0x33}},
		)
	}
	for _, form := range forms {
		body := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s input+0(FP),%s\n%s output+%d(FP),%s\nFINIT\n%s\n%s\nRET\n",
			form.name, 2*word, move, form.input, move, word, form.output, form.load, form.store)
		for role, instruction := range []struct {
			text string
			code []byte
		}{
			{form.load, form.loadCode},
			{form.store, form.storeCode},
		} {
			op, _, _ := strings.Cut(instruction.text, " ")
			position := strings.Index(body, "\n"+instruction.text+"\n")
			original[role] = append(original[role], x86OfficialPackedCase{
				row: ids[op], symbol: form.name,
				line:    lines + strings.Count(body[:position+1], "\n") + 1,
				witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction.text, Encoding: instruction.code},
			})
		}
		lines += strings.Count(body, "\n")
		source.WriteString(body)
		fmt.Fprintf(&declarations, "func %s(input,output *[10]byte)\n", form.name)
	}
	listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
	if err != nil {
		t.Fatal(err)
	}
	// The existing byte checker owns one selected instruction per function.
	// Verify the load and store views separately, retaining both exact lines.
	for _, view := range original {
		if err := x86OfficialPackedVerifyListing(listing, view); err != nil {
			t.Fatal("actual original ten-byte row encodings", err)
		}
	}
	return source.String(), declarations.String()
}

func TestX86X87EncodedTenByteOriginalRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) { x87EncodedTenByteProgram(t, arch) })
	}
}

func TestX86X87EncodedTenByteInitializedThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		source, declaration := x87EncodedTenByteProgram(t, target.arch)
		for _, mode := range []X87Mode{X87Auto, X87Hardware} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mode%d/%s", target.triple, mode, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, mode)
					if err != nil || ir == "" {
						t.Fatal("complete initialized ten-byte source has no value continuation", err)
					}
					if strings.Contains(ir, "fptrunc x86_fp80") || strings.Contains(ir, "fpext double") {
						t.Fatal("ten-byte transport must preserve the full value")
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		}
	}
}

func TestX86X87EncodedTenByteKeepsInputObligations(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		for _, format := range []struct{ load, store string }{
			{"FMOVB", "FMOVBP"}, {"FMOVX", "FMOVXP"},
		} {
			for _, invalid := range []struct{ name, input, body string }{
				{"unknown-address", "", format.load + " (SI),F0\n" + format.store + " F0,(DI)\n"},
				{"partial-address", "MOVW input+0(FP),SI\n", format.load + " (SI),F0\n" + format.store + " F0,(DI)\n"},
				{"unknown-value", "", format.store + " F0,(DI)\n"},
			} {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s output+%d(FP),DI\nFINIT\n%s%sRET\n", 2*word, move, word, invalid.input, invalid.body)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+format.load+"/"+invalid.name+"/"+api, func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, "func Value(input,output *[10]byte)\n", target.arch, target.triple, api, X87Hardware)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("a ten-byte format supplied missing address or FPU input facts", err, ir)
						}
					})
				}
			}
		}
	}
}

func TestX86X87EncodedTenByteKeepsBackendObligations(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		source, declaration := x87EncodedTenByteProgram(t, target.arch)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/software/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, X87Software)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("native encoded access became a portable binary64 codec", err, ir)
				}
			})
		}
	}
	source, declaration := x87EncodedTenByteProgram(t, "amd64")
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		for _, mode := range []X87Mode{X87Auto, X87Hardware} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mode%d/%s", triple, mode, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declaration, "amd64", triple, api, mode)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("encoded x87 access lost its matching backend requirement", err, ir)
					}
				})
			}
		}
	}
}
