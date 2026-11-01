package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawIntegerCompareOriginCase struct {
	row, bank, destination string
	legacy, memory, mask   bool
}

// Independent ymm/yxm_q4 and ordered _yvpcmpeqb directory. The six MMX
// members retain their separate complete native-MMX region owner; this adapter
// must not project those physical x87-tag effects into ordinary vector bytes.
func x86RawIntegerCompareOriginCases() []x86RawIntegerCompareOriginCase {
	var rows []x86RawIntegerCompareOriginCase
	for _, name := range x86PackedIntegerCompareTestNames[:8] {
		for _, memory := range []bool{false, true} {
			first := "X1"
			if memory {
				first = "(BX)"
			}
			rows = append(rows, x86RawIntegerCompareOriginCase{name + " " + first + ",X2", "X", "X2", true, memory, false})
		}
	}
	for _, name := range x86PackedIntegerCompareTestNames[8:] {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, memory := range []bool{false, true} {
				first := bank + "1"
				if memory {
					first = "(BX)"
				}
				if bank != "Z" {
					rows = append(rows, x86RawIntegerCompareOriginCase{name + " " + first + "," + bank + "0," + bank + "2", bank, bank + "2", false, memory, false})
				}
				for _, masked := range []bool{false, true} {
					mask := ""
					if masked {
						mask = "K1,"
					}
					operands := first + "," + bank + "0," + mask + "K2"
					rows = append(rows, x86RawIntegerCompareOriginCase{name + " " + operands, bank, "K2", false, memory, masked})
					if memory && (strings.HasSuffix(name, "D") || strings.HasSuffix(name, "Q")) {
						rows = append(rows, x86RawIntegerCompareOriginCase{name + ".BCST " + operands, bank, "K2", false, true, masked})
					}
				}
			}
		}
	}
	return rows
}

func x86RawIntegerCompareOriginBytes(t *testing.T, rows []x86RawIntegerCompareOriginCase) [][]byte {
	t.Helper()
	var body strings.Builder
	for _, row := range rows {
		body.WriteString(row.row + "\n")
	}
	// Low physical registers have identical encodings in both modes. Observe
	// actual Go AMD64 bytes once; its named frontend, unlike the machine,
	// permits the four-operand EVEX rows. Original 386 BYTE objects remain
	// independent required witnesses, not named-386 arity permission.
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String()+"RET")
	if len(pcs) != len(rows)+1 || code[len(code)-1] != 0xc3 {
		t.Fatal("incomplete independent original Go comparison bytes/PCs")
	}
	result := make([][]byte, len(rows))
	for index := range rows {
		result[index] = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
	}
	return result
}

func x86RawIntegerCompareOriginSource(row x86RawIntegerCompareOriginCase, code []byte, arch, control string) (string, string) {
	word, suffix, move := goWordSize(arch), "Q", "MOVQ"
	if arch == "386" {
		suffix, move = "L", "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Compare(SB),4,$0-%d\n%s a+0(FP),AX\n", 3*word+8, move)
	if control == "numeric address" {
		source.WriteString("MOVL $42,BX\n")
	} else if control != "address" {
		fmt.Fprintf(&source, "%s b+%d(FP),BX\n", move, word)
	}
	fmt.Fprintf(&source, "%s out+%d(FP),DI\n", move, 2*word)
	if control != "mask" {
		fmt.Fprintf(&source, "KMOVD mask+%d(FP),K1\n", 3*word)
	}
	if control != "second" || row.legacy {
		source.WriteString("VMOVUPS (AX),Z0\n")
	}
	if control != "second" || !row.legacy {
		source.WriteString("VMOVUPS (AX),Z2\n")
	}
	if !row.memory && control != "first" {
		source.WriteString("VMOVUPS (BX),Z1\n")
	}
	// All six status flags and DF have real producers. An integer compare
	// changes none of them; the adjacent masked PUSHF observation consumes
	// only these defined bits, not unknown reserved/privileged FLAGS bits.
	source.WriteString("MOVL $3,CX\nCMPL CX,$3\nSTD\n")
	if control == "named" {
		source.WriteString(row.row + "\n")
	} else {
		for _, value := range code {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
	}
	if row.destination == "K2" {
		source.WriteString("KMOVQ K2,(DI)\nVMOVUPS Z0,16(DI)\n")
	} else {
		source.WriteString("VMOVUPS Z2,(DI)\n")
	}
	fmt.Fprintf(&source, "PUSHF%s\nPOP%s CX\nANDL $0xcd5,CX\nMOVL CX,96(DI)\nCLD\nRET\n", suffix, suffix)
	return source.String(), "func Compare(a,b,out *[128]byte,mask uint64)\n"
}

func x86RawIntegerCompareUnusedBoolSource(source, declaration, arch string) (string, string) {
	extent := 3*goWordSize(arch) + 8
	source = strings.Replace(source, fmt.Sprintf("$0-%d\n", extent), fmt.Sprintf("$0-%d\n", extent+1), 1)
	declaration = strings.Replace(declaration, "mask uint64)", "mask uint64,unused bool)", 1)
	return source, declaration
}

func TestX86RawIntegerCompareCompleteIndependentOriginDirectory(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	if len(rows) != 168 {
		t.Fatal("complete legacy/VEX/EVEX/K/broadcast directory changed", len(rows))
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		if seen[row.row] {
			t.Fatal("duplicate independent comparison row", row.row)
		}
		seen[row.row] = true
	}
	code := x86RawIntegerCompareOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, code[index])
				form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, arch)
				if !known || err != nil || string(ins.Op) != strings.Fields(row.row)[0] ||
					form.byteWidth != map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank] ||
					form.broadcast != strings.Contains(row.row, ".BCST ") || form.legacy != row.legacy || form.mmx ||
					(form.memory >= 0) != row.memory || (form.mask >= 0) != row.mask ||
					ins.Args[form.destination].Reg != Reg(row.destination) {
					t.Fatal("original Go bytes lost their complete independent typed comparison roles", err)
				}
			})
		}
	}
}

// Use exactly the same initialized loads, fields, result uses and defined-only
// FLAGS/DF observation. Only the compare's original representation changes.
// This independently distinguishes its raw-origin gap from an earlier named
// native load that a whole-source diagnostic might otherwise report first.
func TestX86RawIntegerCompareSameSourceNamedControls(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	for start := 0; start < len(rows); start += x86RawIntegerCompareOriginBatchSize {
		end := start + x86RawIntegerCompareOriginBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint(start/x86RawIntegerCompareOriginBatchSize), func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows[start:end] {
				body, declaration := x86RawIntegerCompareOriginSource(row, nil, "amd64", "named")
				name := fmt.Sprint("Compare", start+index)
				source.WriteString(strings.ReplaceAll(body, "Compare", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Compare", name))
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("same-source named control lost an initialized load, input or defined-only FLAGS/DF observation", err)
					}
				})
			}
		})
	}
}

const x86RawIntegerCompareOriginBatchSize = 32

func TestX86RawIntegerCompareInitializedFiveTargetsBatch00(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 0)
}
func TestX86RawIntegerCompareInitializedFiveTargetsBatch01(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 1)
}
func TestX86RawIntegerCompareInitializedFiveTargetsBatch02(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 2)
}
func TestX86RawIntegerCompareInitializedFiveTargetsBatch03(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 3)
}
func TestX86RawIntegerCompareInitializedFiveTargetsBatch04(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 4)
}
func TestX86RawIntegerCompareInitializedFiveTargetsBatch05(t *testing.T) {
	x86RawIntegerCompareOriginObjectBatch(t, 5)
}

func x86RawIntegerCompareOriginObjectBatch(t *testing.T, batch int) {
	t.Helper()
	rows := x86RawIntegerCompareOriginCases()
	start, end := batch*x86RawIntegerCompareOriginBatchSize, (batch+1)*x86RawIntegerCompareOriginBatchSize
	if start < 0 || start >= len(rows) {
		t.Fatal("invalid original comparison object batch", batch)
	}
	if end > len(rows) {
		end = len(rows)
	}
	rows = rows[start:end]
	code := x86RawIntegerCompareOriginBytes(t, rows)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				body, declaration := x86RawIntegerCompareOriginSource(row, code[index], target.arch, "")
				name := fmt.Sprint("Compare", start+index)
				source.WriteString(strings.ReplaceAll(body, "Compare", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Compare", name))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original comparison cannot compose with named native views and defined FLAGS/DF", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "compare-origin.ll", "compare-origin.o", body)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86RawIntegerCompareVoidAndUnusedBoolCannotBorrowInputs(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	code := x86RawIntegerCompareOriginBytes(t, rows)
	for index, row := range rows {
		for _, control := range []string{"first", "second", "mask", "address", "numeric address"} {
			if control == "first" && row.memory || control == "mask" && !row.mask ||
				(control == "address" || control == "numeric address") && !row.memory {
				continue
			}
			t.Run(row.row+"/"+control, func(t *testing.T) {
				for _, arch := range []string{"386", "amd64"} {
					source, declaration := x86RawIntegerCompareOriginSource(row, code[index], arch, control)
					for _, unused := range []bool{false, true} {
						body, decl := source, declaration
						if unused {
							body, decl = x86RawIntegerCompareUnusedBoolSource(body, decl, arch)
						}
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, body, decl, arch, x86AddressMemoryTargets(arch)[0], api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("dead/unused-bool compare acquired missing data, mask or native pointer facts", arch, unused, api, err)
							}
						}
					}
				}
			})
		}
	}
}

func TestX86RawIntegerCompareInitializedUnusedBoolAllSourceForms(t *testing.T) {
	rows := x86RawIntegerCompareOriginCases()
	code := x86RawIntegerCompareOriginBytes(t, rows)
	for start := 0; start < len(rows); start += x86RawIntegerCompareOriginBatchSize {
		end := start + x86RawIntegerCompareOriginBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint(start/x86RawIntegerCompareOriginBatchSize), func(t *testing.T) {
			for _, target := range x86RawReturnTargets {
				t.Run(target.triple, func(t *testing.T) {
					var source, declarations strings.Builder
					for index, row := range rows[start:end] {
						body, declaration := x86RawIntegerCompareOriginSource(row, code[start+index], target.arch, "")
						body, declaration = x86RawIntegerCompareUnusedBoolSource(body, declaration, target.arch)
						name := fmt.Sprint("Compare", start+index)
						source.WriteString(strings.ReplaceAll(body, "Compare", name))
						declarations.WriteString(strings.ReplaceAll(declaration, "Compare", name))
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("unused bool changed a completely initialized raw comparison with its exact source extent", err)
							}
						})
					}
				})
			}
		})
	}
}
