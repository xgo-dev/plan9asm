package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawBroadcastOriginCase struct {
	row, source, bank string
	bytes, lane       int
	masked, zero      bool
}

// Expand the independent twenty-name Go encoder directory, not production
// registry keys. Memory, X, GP and K-data sources retain distinct roles even
// when their canonical spelling happens to select the same destination bank.
func x86RawBroadcastOriginCases() []x86RawBroadcastOriginCase {
	var rows []x86RawBroadcastOriginCase
	for _, spec := range x86BroadcastTestDirectory {
		var sources []string
		if spec.source == "K" {
			sources = []string{"K1"}
		} else {
			sources = []string{"(SI)"}
			if strings.Contains(spec.source, "X") {
				sources = append(sources, "X1")
			}
			if strings.Contains(spec.source, "G") {
				sources = append(sources, "AX")
			}
		}
		for _, bank := range spec.destinations {
			for _, source := range sources {
				for _, mask := range []string{"", "merge", "zero"} {
					if mask != "" && (spec.source == "K" || spec.table == "_yvbroadcastf128") {
						continue
					}
					name, operands := spec.name, source+","
					if mask != "" {
						operands += "K3,"
					}
					if mask == "zero" {
						name += ".Z"
					}
					rows = append(rows, x86RawBroadcastOriginCase{
						row: name + " " + operands + string(bank) + "2", source: source,
						bank: string(bank), bytes: spec.bytes, lane: spec.lane,
						masked: mask != "", zero: mask == "zero",
					})
				}
			}
		}
	}
	return rows
}

func x86RawBroadcastOriginBytes(t *testing.T, rows []x86RawBroadcastOriginCase) [][]byte {
	t.Helper()
	var body strings.Builder
	for _, row := range rows {
		body.WriteString(row.row + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String()+"RET")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("incomplete independent original Go broadcast bytes/PCs")
	}
	result := make([][]byte, len(rows))
	for index := range rows {
		result[index] = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
	}
	return result
}

func x86RawBroadcastOriginSource(row x86RawBroadcastOriginCase, code []byte, arch, control string, dead bool) (string, string) {
	word, move, suffix := goWordSize(arch), "MOVQ", "Q"
	if arch == "386" {
		move, suffix = "MOVL", "L"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Broadcast(SB),4,$0-%d\n", 3*word+16)
	if control == "numeric address" {
		source.WriteString("MOVL $42,SI\n")
	} else if control != "address" {
		fmt.Fprintf(&source, "%s a+0(FP),SI\n", move)
	}
	fmt.Fprintf(&source, "%s old+%d(FP),BX\n%s out+%d(FP),DI\n", move, word, move, 2*word)
	if control != "mask" {
		fmt.Fprintf(&source, "KMOVQ mask+%d(FP),K3\n", 3*word)
	}
	if control != "first" || row.source != "AX" {
		fmt.Fprintf(&source, "%s scalar+%d(FP),AX\n", move, 3*word+8)
	}
	if control != "first" || row.source != "K1" {
		fmt.Fprintf(&source, "KMOVQ scalar+%d(FP),K1\n", 3*word+8)
	}
	if row.source == "X1" && control != "first" {
		source.WriteString("VMOVUPS (SI),Z1\n")
	}
	if control != "merge" {
		source.WriteString("VMOVUPS (BX),Z2\n")
	}
	// Defined status and DF survive all broadcast forms. Keep the original
	// opcode between the producer and the adjacent defined-only observation.
	// Unused Go results must not erase its input or native access obligations.
	source.WriteString("MOVL $3,CX\nCMPL CX,$3\nSTD\n")
	if control == "named" {
		source.WriteString(row.row + "\n")
	} else {
		for _, value := range code {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
	}
	if !dead {
		source.WriteString("VMOVUPS Z2,(DI)\n")
		if row.source == "X1" {
			source.WriteString("VMOVUPS Z1,64(DI)\n")
		}
	}
	fmt.Fprintf(&source, "PUSHF%s\nPOP%s CX\nANDL $0xcd5,CX\nMOVL CX,128(DI)\nCLD\nRET\n", suffix, suffix)
	return source.String(), "func Broadcast(a,old,out *[144]byte,mask,scalar uint64)\n"
}

func x86RawBroadcastUnusedBoolSource(source, declaration, arch string) (string, string) {
	extent := 3*goWordSize(arch) + 16
	source = strings.Replace(source, fmt.Sprintf("$0-%d\n", extent), fmt.Sprintf("$0-%d\n", extent+1), 1)
	declaration = strings.Replace(declaration, "scalar uint64)", "scalar uint64,unused bool)", 1)
	return source, declaration
}

func TestX86RawBroadcastCompleteIndependentOriginDirectory(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	if len(rows) != 212 {
		t.Fatal("complete scalar/block/K-data broadcast directory changed", len(rows))
	}
	seen, sources := make(map[string]bool), make(map[string]int)
	for _, row := range rows {
		if seen[row.row] {
			t.Fatal("duplicate independent broadcast row", row.row)
		}
		seen[row.row], sources[row.source] = true, sources[row.source]+1
	}
	if sources["(SI)"] != 104 || sources["X1"] != 66 || sources["AX"] != 36 || sources["K1"] != 6 {
		t.Fatal("independent source-role matrix changed", sources)
	}
	code := x86RawBroadcastOriginBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, code[index])
				form, known, err := x86BroadcastProperties(ins.Op, ins, arch)
				bytes, lane := row.bytes, row.lane
				if arch == "386" && strings.HasPrefix(row.row, "VPBROADCASTQ") && row.source == "AX" {
					bytes, lane = 4, 4 // GP-only opcode 7C physically ignores W in mode32.
				}
				if !known || err != nil || string(ins.Op) != strings.Fields(row.row)[0] ||
					form.sourceBytes != bytes || form.laneBits != lane*8 ||
					form.byteWidth != map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank] ||
					(form.mask >= 0) != row.masked || form.zeroing != row.zero ||
					ins.Args[form.destination].Reg != Reg(row.bank+"2") ||
					(row.source == "(SI)") != (ins.Args[0].Kind == OpMem) ||
					(row.source != "(SI)" && ins.Args[0].Reg != Reg(row.source)) {
					t.Fatal("original Go bytes lost their complete independent typed broadcast roles", err)
				}
			})
		}
	}
}

const x86RawBroadcastOriginBatchSize = 32

// These controls use exactly the same pointers, numeric scalar/K inputs,
// complete old vector, output views and defined FLAGS/DF observation. Only the
// broadcast representation changes, so a raw whole-source diagnostic at a
// preceding named VMOVUPS cannot establish that load as the actual cause.
func TestX86RawBroadcastSameSourceNamedControls(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	for start := 0; start < len(rows); start += x86RawBroadcastOriginBatchSize {
		end := start + x86RawBroadcastOriginBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint(start/x86RawBroadcastOriginBatchSize), func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows[start:end] {
				body, declaration := x86RawBroadcastOriginSource(row, nil, "amd64", "named", false)
				name := fmt.Sprint("Broadcast", start+index)
				source.WriteString(strings.ReplaceAll(body, "Broadcast", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Broadcast", name))
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("same-source named broadcast lost initialized inputs, native views or defined FLAGS/DF", err)
					}
				})
			}
		})
	}
}

func TestX86RawBroadcastInitializedFiveTargetsBatch00(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 0)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch01(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 1)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch02(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 2)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch03(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 3)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch04(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 4)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch05(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 5)
}
func TestX86RawBroadcastInitializedFiveTargetsBatch06(t *testing.T) {
	x86RawBroadcastOriginObjectBatch(t, 6)
}

func x86RawBroadcastOriginObjectBatch(t *testing.T, batch int) {
	t.Helper()
	rows := x86RawBroadcastOriginCases()
	start, end := batch*x86RawBroadcastOriginBatchSize, (batch+1)*x86RawBroadcastOriginBatchSize
	if start < 0 || start >= len(rows) {
		t.Fatal("invalid original broadcast object batch", batch)
	}
	if end > len(rows) {
		end = len(rows)
	}
	rows = rows[start:end]
	code := x86RawBroadcastOriginBytes(t, rows)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				body, declaration := x86RawBroadcastOriginSource(row, code[index], target.arch, "", false)
				name := fmt.Sprint("Broadcast", start+index)
				source.WriteString(strings.ReplaceAll(body, "Broadcast", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Broadcast", name))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original broadcast cannot compose with native views and defined FLAGS/DF", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "broadcast-origin.ll", "broadcast-origin.o", body)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86RawBroadcastVoidAndUnusedBoolCannotBorrowInputs(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	code := x86RawBroadcastOriginBytes(t, rows)
	for index, row := range rows {
		for _, control := range []string{"first", "merge", "mask", "address", "numeric address"} {
			if control == "first" && row.source == "(SI)" || control == "merge" && (!row.masked || row.zero) ||
				control == "mask" && !row.masked ||
				(control == "address" || control == "numeric address") && row.source != "(SI)" {
				continue
			}
			t.Run(row.row+"/"+control, func(t *testing.T) {
				for _, arch := range []string{"386", "amd64"} {
					for _, dead := range []bool{false, true} {
						source, declaration := x86RawBroadcastOriginSource(row, code[index], arch, control, dead)
						for _, unused := range []bool{false, true} {
							body, decl := source, declaration
							if unused {
								body, decl = x86RawBroadcastUnusedBoolSource(body, decl, arch)
							}
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, body, decl, arch, x86AddressMemoryTargets(arch)[0], api)
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("dead/unused-bool broadcast acquired missing scalar, vector, mask, old result or native pointer facts", arch, dead, unused, api, err)
								}
							}
						}
					}
				}
			})
		}
	}
}

// Legal storage extent is an independent positive, not an accidental negative
// caused by appending a bool to the declaration without updating TEXT.
func TestX86RawBroadcastInitializedUnusedBoolAndDeadAllSourceForms(t *testing.T) {
	rows := x86RawBroadcastOriginCases()
	code := x86RawBroadcastOriginBytes(t, rows)
	for start := 0; start < len(rows); start += x86RawBroadcastOriginBatchSize {
		end := start + x86RawBroadcastOriginBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint(start/x86RawBroadcastOriginBatchSize), func(t *testing.T) {
			for _, target := range x86RawReturnTargets {
				t.Run(target.triple, func(t *testing.T) {
					var source, declarations strings.Builder
					for index, row := range rows[start:end] {
						for _, dead := range []bool{false, true} {
							body, declaration := x86RawBroadcastOriginSource(row, code[start+index], target.arch, "", dead)
							body, declaration = x86RawBroadcastUnusedBoolSource(body, declaration, target.arch)
							name := fmt.Sprintf("Broadcast%dDead%t", start+index, dead)
							source.WriteString(strings.ReplaceAll(body, "Broadcast", name))
							declarations.WriteString(strings.ReplaceAll(declaration, "Broadcast", name))
						}
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("unused bool or dead output changed a completely initialized original broadcast", err)
							}
						})
					}
				})
			}
		})
	}
}
