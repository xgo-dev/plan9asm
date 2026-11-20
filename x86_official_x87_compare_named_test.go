package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86X87CompareNamedRows(catalog goasmrules.X86LegacyCatalog, arch string) ([]goasmrules.X86PackedBinaryRow, error) {
	// This finite source family is independent of the typed value-spec map.
	names := strings.Fields("FCOMD FCOMDP FCOMDPP FCOMF FCOMFP FCOMI FCOMIP FCOML FCOMLP FCOMW FCOMWP FUCOM FUCOMI FUCOMIP FUCOMP FUCOMPP")
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		selected[name] = false
	}
	original, err := goasmrules.X86X87Rows(catalog, arch)
	if err != nil {
		return nil, err
	}
	var rows []goasmrules.X86PackedBinaryRow
	canonical, refused := 0, 0
	for _, row := range original {
		if _, included := selected[row.Opcode]; !included {
			continue
		}
		selected[row.Opcode] = true
		named := goasmrules.X86PackedBinaryRow{ID: row.ID, Opcode: row.Opcode}
		for _, witness := range row.Witnesses {
			canonical++
			if (row.Opcode == "FCOMDPP" || row.Opcode == "FUCOMPP") && witness.Instruction != row.Opcode+" F0,F1" {
				refused++ // Retain the original carrier in the byte owner, never rewrite it to F1.
				continue
			}
			named.Witnesses = append(named.Witnesses, goasmrules.X86PackedBinaryWitness{
				Instruction: witness.Instruction, Encoding: append([]byte(nil), witness.Encoding...),
			})
		}
		rows = append(rows, named)
	}
	for name, found := range selected {
		if !found {
			return nil, fmt.Errorf("missing original compare member %s", name)
		}
	}
	if len(rows) != 20 || canonical != 40 || refused != 2 {
		return nil, fmt.Errorf("compare source closure changed: rows=%d canonical=%d refused=%d", len(rows), canonical, refused)
	}
	return rows, nil
}

func TestX86X87CompareNamedInputsAndRawBoundary(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		d, top := 16, 32
		if arch == "386" {
			triple, d, top = "i386-unknown-linux-gnu", 12, 28
		}
		fixture := x86OfficialPackedCase{witness: goasmrules.X86PackedBinaryWitness{
			Instruction: "FCOMD F0,F7", Encoding: []byte{0xdc, 0xd7},
		}}
		source, declaration := x86X87CompareNamedAssembly([]x86OfficialPackedCase{fixture}, arch, false)
		for _, test := range []struct{ name, source, failure string }{
			{"no-stack", strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(source, fmt.Sprintf("FMOVD d+%d(FP),F0\n", d), ""), fmt.Sprintf("FMOVD top+%d(FP),F0\n", top), ""), "FLD1\n", ""), "FCOMD F0,F7"},
			{"missing-F7", strings.Replace(source, fmt.Sprintf("FMOVD d+%d(FP),F0\n", d), "", 1), "FCOMD F0,F7"},
			{"unknown-CPU-flags", strings.Replace(source, "MOVL $-1,CX\nADDL $1,CX\n", "", 1), "SETEQ AX"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, test.source, declaration, arch, triple, api, X87Software)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), test.failure) {
						t.Fatalf("missing input escaped its exact boundary: output=%t error=%v", ir != "", err)
					}
				})
			}
		}
		for _, code := range [][]byte{{0xd8, 0xd1}, {0xdc, 0xd7}, {0xdb, 0xf1}, {0xde, 0xd9}, {0xde, 0xdf}, {0xda, 0xef}} {
			// The raw byte decoder and original-source authorization are
			// independent of the named form's complete numerical inputs.
			raw := strings.Replace(source, "FCOMD F0,F7\n", x86RawDisplacementDirectives(code), 1)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/raw-%x/%s", arch, code, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, raw, declaration, arch, triple, api, X87Software)
					if bytes.Equal(code, []byte{0xd8, 0xd1}) || bytes.Equal(code, []byte{0xdc, 0xd7}) {
						if err != nil || ir == "" {
							t.Fatal("complete replay lost its defined register compare", err)
						}
						return
					}
					if err == nil || ir != "" {
						t.Fatalf("illegal or mismatched status/pop source acquired a result: output=%t error=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func x86X87CompareNamedAssembly(cases []x86OfficialPackedCase, arch string, topResult bool) (string, string) {
	return x86X87CompareAssembly(cases, arch, topResult, false, false)
}

func x86X87CompareAssembly(cases []x86OfficialPackedCase, arch string, topResult, nativeMemory, raw bool) (string, string) {
	d, w, l, top, result := 12, 20, 24, 28, 36
	if arch == "amd64" {
		d, w, l, top, result = 16, 24, 28, 32, 40
	}
	memory := result
	if nativeMemory {
		result += goWordSize(arch)
	}
	var source, declarations strings.Builder
	line := 1
	for index := range cases {
		fixture := &cases[index]
		prefix := "X87Compare"
		if topResult {
			prefix = "X87Top"
		}
		fixture.symbol = fmt.Sprint(prefix, index)
		instruction := fixture.witness.Instruction
		op := strings.Fields(instruction)[0]
		if !nativeMemory && strings.Contains(instruction, "(AX)") {
			operand, offset := fmt.Sprintf("d+%d(FP)", d), d
			switch op {
			case "FCOMF", "FCOMFP":
				operand, offset = "f+8(FP)", 8
			case "FCOMW", "FCOMWP":
				operand, offset = fmt.Sprintf("w+%d(FP)", w), w
			case "FCOML", "FCOMLP":
				operand, offset = fmt.Sprintf("l+%d(FP)", l), l
			}
			instruction = op + " " + operand + ",F0"
			// A typed FP parameter supplies the existing logical scalar role.
			// It is a different address/encoding from both original AX carriers.
			code := fixture.witness.Encoding
			fixture.witness.Encoding = []byte{code[0], 0x44 | code[1]&0x38, 0x24, byte(offset + goWordSize(arch))}
			fixture.witness.Instruction = instruction
		}
		var body strings.Builder
		fmt.Fprintf(&body, "TEXT ·%s(SB),4,$0-%d\nMOVL gate+4(FP),AX\nFINIT\n", fixture.symbol, result+8)
		if nativeMemory {
			move := "MOVQ"
			if arch == "386" {
				move = "MOVL"
			}
			fmt.Fprintf(&body, "%s memory+%d(FP),AX\n", move, memory)
		}
		for i := 0; i < 5; i++ {
			fmt.Fprintf(&body, "FMOVD d+%d(FP),F0\n", d)
		}
		// F1 and F7 retain d for both official carriers. F2 is distinct,
		// so the runtime oracle can distinguish one pop from two pops.
		fmt.Fprintf(&body, "FLD1\nFMOVD d+%d(FP),F0\n", d)
		fmt.Fprintf(&body, "FMOVD top+%d(FP),F0\nMOVL $-1,CX\nADDL $1,CX\n", top)
		fixture.line = line + strings.Count(body.String(), "\n")
		if raw {
			fixture.witness.Instruction = strings.TrimSpace(x86RawDisplacementDirectives(fixture.witness.Encoding))
			body.WriteString(fixture.witness.Instruction + "\n")
		} else {
			body.WriteString(instruction + "\n")
		}
		pops := 0
		switch op {
		case "FCOMDPP", "FUCOMPP":
			pops = 2
		case "FCOMDP", "FCOMFP", "FCOMLP", "FCOMWP", "FCOMIP", "FUCOMIP", "FUCOMP":
			pops = 1
		}
		remaining := 8 - pops
		if topResult {
			fmt.Fprintf(&body, "FMOVDP F0,ret+%d(FP)\n", result)
			remaining--
		} else if op == "FCOMI" || op == "FCOMIP" || op == "FUCOMI" || op == "FUCOMIP" {
			for offset, condition := range []string{"EQ", "CS", "PS", "OS", "MI", "LT"} {
				fmt.Fprintf(&body, "SET%s AX\nMOVB AX,ret+%d(FP)\n", condition, result+offset)
			}
			fmt.Fprintf(&body, "MOVW $0,ret+%d(FP)\n", result+6)
		} else {
			// Capture the independent CPU flags before ANDW changes them.
			for offset, condition := range []string{"EQ", "CS", "PS", "OS", "MI", "LT"} {
				fmt.Fprintf(&body, "SET%s AX\nMOVB AX,ret+%d(FP)\n", condition, result+2+offset)
			}
			fmt.Fprintf(&body, "FSTSW AX\nANDW $0x4500,AX\nMOVW AX,ret+%d(FP)\n", result)
		}
		body.WriteString(strings.Repeat("FMOVDP F0,F0\n", remaining) + "RET\n")
		source.WriteString(body.String())
		parameters := "gate uint64, f float32, d float64, w int16, l int32, top float64"
		if nativeMemory {
			parameters += ", memory *byte"
		}
		fmt.Fprintf(&declarations, "func %s(%s) float64\n", fixture.symbol, parameters)
		line += strings.Count(body.String(), "\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialX87CompareNamedRowsInitializedThreeAPIsObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	canonical := x86X87OriginalSourceCases(t, catalog)
	identities := make(map[string][]map[string]interface{})
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var original []goasmrules.X86PackedBinaryWitness
			build := func(source goasmrules.X86LegacyCatalog, _ []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
				rows, err := x86X87CompareNamedRows(source, target.arch)
				for _, row := range rows {
					original = append(original, row.Witnesses...)
				}
				return rows, err
			}
			verified := x86OfficialPackedRowsObjectsForTarget(t, target.arch, target.triple, build, 20, 38, 0,
				func(cases []x86OfficialPackedCase) (string, string) {
					return x86X87CompareNamedAssembly(cases, target.arch, false)
				}, func(*testing.T, string, []x86OfficialPackedCase) {})
			if len(original) != len(verified) {
				t.Fatal("canonical and named counterpart inventories differ", len(original), len(verified))
			}
			for index, actual := range verified {
				found := false
				for _, canonicalCase := range canonical {
					if canonicalCase.row != actual.row {
						continue
					}
					if strings.Contains(canonicalCase.witness.Instruction, "(AX)") {
						found = strings.Contains(actual.witness.Instruction, "(FP)") &&
							canonicalCase.witness.Encoding[0] == actual.witness.Encoding[0] &&
							canonicalCase.witness.Encoding[1]&0x38 == actual.witness.Encoding[1]&0x38
					} else if canonicalCase.witness.Instruction == actual.witness.Instruction {
						found = bytes.Equal(canonicalCase.witness.Encoding, actual.witness.Encoding)
					}
					if found {
						break
					}
				}
				if !found {
					t.Fatal("public counterpart lost its original owning compare row", actual)
				}
				identities[target.triple] = append(identities[target.triple], map[string]interface{}{
					"Row": actual.row, "CanonicalInstruction": original[index].Instruction,
					"CanonicalEncoding": original[index].Encoding, "PublicInstruction": actual.witness.Instruction,
					"PublicEncoding": actual.witness.Encoding,
				})
			}
		})
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_X87_COMPARE_NAMED_IDENTITY_OUTPUT", identities)
	}
}
