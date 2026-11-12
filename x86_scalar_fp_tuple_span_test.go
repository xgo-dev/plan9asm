package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These byte tuples have no padding. Their independently specified little-
// endian bytes describe physical FP storage, not a coercion to its first field.
type x86ScalarFPTupleSpanCase struct {
	name, source, declaration string
	want                      []uint64
}

func x86ScalarFPTupleSpanCases(arch string, read bool) []x86ScalarFPTupleSpanCase {
	widths := []int{2, 4}
	if arch == "amd64" {
		widths = append(widths, 8)
	}
	var cases []x86ScalarFPTupleSpanCase
	for _, width := range widths {
		for _, boolean := range []int{0, width - 1, -1} {
			position := "numeric"
			if boolean == 0 {
				position = "bool-first"
			} else if boolean == width-1 {
				position = "bool-last"
			}
			var fields []string
			var values []uint64
			var packed uint64
			for index := 0; index < width; index++ {
				typ, value := "uint8", uint64(index+2)
				if boolean == 0 {
					value--
				}
				if index == boolean {
					typ, value = "bool", 1
				}
				fields = append(fields, typ)
				values = append(values, value)
				packed |= value << uint(8*index)
			}
			move := map[int]string{2: "MOVW", 4: "MOVL", 8: "MOVQ"}[width]
			var body strings.Builder
			role, extent := "store", width
			if read {
				role, extent = "read", 2*width
				for index, value := range values {
					fmt.Fprintf(&body, "MOVB $%d,ret+%d(FP)\n", value, index)
				}
				fmt.Fprintf(&body, "%s ret+0(FP),AX\n%s AX,ret+%d(FP)\n", move, move, width)
				fields = append(fields, fmt.Sprintf("uint%d", 8*width))
				values = append(values, packed)
			} else {
				// Register transport keeps Q's full-width literal legal: x86 has
				// no arbitrary imm64-to-memory encoding.
				fmt.Fprintf(&body, "%s $0x%x,AX\n%s AX,ret+0(FP)\n", move, packed, move)
			}
			body.WriteString("RET\n")
			cases = append(cases, x86ScalarFPTupleSpanCase{
				name:        fmt.Sprintf("%s/%s/%s", role, move, position),
				declaration: "func Value() (" + strings.Join(fields, ",") + ")",
				source:      fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", extent, body.String()),
				want:        values,
			})
			if read && boolean >= 0 {
				// The Go bool return must be restored to one, but its earlier
				// physical byte two must survive the wide numerical read.
				physical := strings.Replace(body.String(), fmt.Sprintf("MOVB $1,ret+%d(FP)", boolean), fmt.Sprintf("MOVB $2,ret+%d(FP)", boolean), 1)
				physical = strings.Replace(physical, "RET\n", fmt.Sprintf("MOVB $1,ret+%d(FP)\nRET\n", boolean), 1)
				expected := append([]uint64(nil), values...)
				expected[len(expected)-1] += uint64(1) << uint(8*boolean)
				cases = append(cases, x86ScalarFPTupleSpanCase{
					name:        fmt.Sprintf("%s/%s/%s-physical-two", role, move, position),
					declaration: "func Value() (" + strings.Join(fields, ",") + ")",
					source:      fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", extent, physical),
					want:        expected,
				})
			}
		}
	}
	return cases
}

func x86ScalarFPTupleSpanConstantResult(t *testing.T, ir string, want []uint64) {
	x86ScalarFPNamedConstantResult(t, ir, "Value", want)
}

func x86ScalarFPNamedConstantResult(t *testing.T, ir, name string, want []uint64) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	function := module.NamedFunction(name)
	if function.IsNil() {
		t.Fatal("missing exact translated entry", name)
	}
	returns := 0
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
			if instruction.IsAReturnInst().IsNil() {
				continue
			}
			returns++
			if instruction.OperandsCount() != 1 {
				t.Fatalf("missing physical-byte tuple result: %s", function.String())
			}
			result := instruction.Operand(0)
			if len(want) == 1 && !result.IsAConstantInt().IsNil() {
				if result.ZExtValue() != want[0] {
					t.Errorf("FP span scalar result: got %s, want %d; optimized actual fixture:\n%s", result.String(), want[0], function.String())
				}
				continue
			}
			if result.IsAConstantStruct().IsNil() || result.OperandsCount() != len(want) {
				t.Fatalf("whole constant fixture did not produce an inspectable tuple: %s", function.String())
			}
			for index, expected := range want {
				field := result.Operand(index)
				if field.IsAConstantInt().IsNil() || field.ZExtValue() != expected {
					t.Errorf("FP span lost field %d: got %s, want %d; optimized actual fixture:\n%s", index, field.String(), expected, function.String())
				}
			}
		}
	}
	if returns != 1 {
		t.Fatalf("constant fixture has %d returns, want one", returns)
	}
}

func x86ScalarFPTupleSpanThreeAPIs(t *testing.T, read bool) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ScalarFPTupleSpanCases(target.arch, read) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("complete initialized physical FP span rejected: %v", err)
					}
					x86ScalarFPTupleSpanConstantResult(t, ir, row.want)
				})
			}
		}
	}
}

func TestX86ScalarFPWideTupleStoresPreserveEveryField(t *testing.T) {
	x86ScalarFPTupleSpanThreeAPIs(t, false)
}

func TestX86ScalarFPWideTupleReadsPreserveEveryField(t *testing.T) {
	x86ScalarFPTupleSpanThreeAPIs(t, true)
}

func x86ScalarFPInteriorCases(arch string) []x86ScalarFPTupleSpanCase {
	word, full, seed := 8, "MOVQ", uint64(0x0807060504030201)
	if arch == "386" {
		word, full, seed = 4, "MOVL", 0x04030201
	}
	var cases []x86ScalarFPTupleSpanCase
	for _, width := range []int{1, 2, 4, 8} {
		if width > word {
			continue // No GP qword row exists in the mode32 Go table.
		}
		mask := ^uint64(0)
		if width < 8 {
			mask = uint64(1)<<uint(8*width) - 1
		}
		move := map[int]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[width]
		for offset := 0; offset <= word-width; offset++ {
			for _, read := range []bool{false, true} {
				role, first, second := "write", seed, seed
				body := fmt.Sprintf("%s $0x%x,AX\n%s AX,ret+0(FP)\n", full, seed, full)
				if read {
					role, second = "read", seed>>uint(8*offset)&mask
					body += fmt.Sprintf("%s $0,AX\n%s ret+%d(FP),AX\n", full, move, offset)
				} else {
					part := uint64(0x1514131211100f0e) & mask
					first = seed&^(mask<<uint(8*offset)) | part<<uint(8*offset)
					second = first
					body += fmt.Sprintf("%s $0x%x,BX\n%s BX,ret+%d(FP)\n%s ret+0(FP),AX\n", move, part, move, offset, full)
				}
				body += fmt.Sprintf("%s AX,ret+%d(FP)\nRET\n", full, word)
				cases = append(cases, x86ScalarFPTupleSpanCase{
					name:        fmt.Sprintf("%s/%s/offset-%d", role, move, offset),
					declaration: fmt.Sprintf("func Value() (uint%d,uint%d)", 8*word, 8*word),
					source:      fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", 2*word, body),
					want:        []uint64{first, second},
				})
			}
		}
	}
	return cases
}

func TestX86ScalarFPIntegerPartialAndInteriorBytesThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ScalarFPInteriorCases(target.arch) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("complete initialized physical FP span rejected: %v", err)
					}
					x86ScalarFPTupleSpanConstantResult(t, ir, row.want)
				})
			}
		}
	}
}

func TestX86ScalarFPWideTupleSpanOriginalGoAssembly(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			for _, read := range []bool{false, true} {
				for index, row := range x86ScalarFPTupleSpanCases(arch, read) {
					name := fmt.Sprintf("Span%dRead%t", index, read)
					source.WriteString(strings.ReplaceAll(row.source, "Value", name))
				}
			}
			for index, row := range x86ScalarFPInteriorCases(arch) {
				source.WriteString(strings.ReplaceAll(row.source, "Value", fmt.Sprintf("Interior%d", index)))
			}
			word := 8
			if arch == "386" {
				word = 4
			}
			for index, row := range x86IntegerFPByteRoleCases(word) {
				fmt.Fprintf(&source, "TEXT ·Role%d(SB),4,$0-%d\n%s\n", index, row.args, row.body)
			}
			source.WriteString(strings.ReplaceAll(x86IntegerFPByteStatusSource, "Value", "Status"))
			if arch == "386" {
				for index, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
					fmt.Fprintf(&source, "TEXT ·Vector%d(SB),4,$0-8\nPXOR X0,X0\n%s X0,ret+0(FP)\n%s ret+0(FP),X1\n%s X1,ret+0(FP)\nRET\n", index, alias, alias, alias)
				}
			}
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
		})
	}
	// These are Go-invalid GP rows, not another admitted mode32 format. Require
	// the actual assembler's fixture-bound exit-1 diagnostic independently of
	// the translator's conservative Context result and the valid X/m64 controls.
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		for _, row := range []struct{ name, body string }{{"store", alias + " AX,ret+0(FP)"}, {"load", alias + " ret+0(FP),AX"}} {
			t.Run("386-GP-qword-rejected/"+alias+"/"+row.name, func(t *testing.T) {
				goAssemblerOracleOutput(t, "386", "TEXT ·Invalid(SB),4,$0-8\n"+row.body+"\nRET\n", "", false)
			})
		}
	}
}
