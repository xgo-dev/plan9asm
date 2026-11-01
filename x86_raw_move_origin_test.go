package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawMoveOriginCase struct {
	row, bank, role, masking string
	scalar                   bool
}

// Reuse the independent Go-table directory, not the production move registry.
// Every source/destination width, memory direction and legal mask/zero role
// appears here; architectural .Z memory-store faults remain separate controls.
func x86RawMoveOriginCases() []x86RawMoveOriginCase {
	var cases []x86RawMoveOriginCase
	add := func(name, bank string, scalar, vexOnly bool) {
		for _, role := range []string{"register", "load", "store"} {
			for _, masking := range []string{"plain", "merge", "zero"} {
				if vexOnly && masking != "plain" || role == "store" && masking == "zero" {
					continue
				}
				op, mask := name, ""
				if masking != "plain" {
					mask = "K1,"
				}
				if masking == "zero" {
					op += ".Z"
				}
				operands := bank + "0," + mask + bank + "2"
				if scalar {
					operands = "X0,X1," + mask + "X2"
				}
				if role == "load" {
					operands = "(BX)," + mask + bank + "2"
				} else if role == "store" {
					operands = bank + "2," + mask + "(DI)"
				}
				cases = append(cases, x86RawMoveOriginCase{
					row: op + " " + operands, bank: bank, role: role, masking: masking, scalar: scalar,
				})
			}
		}
	}
	for _, row := range x86PackedMoveResultOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			add(row.name, bank, false, row.vexOnly)
		}
	}
	add("VMOVSS", "X", true, false)
	add("VMOVSD", "X", true, false)
	return cases
}

// Actual Go listing PCs delimit the observed bytes without consulting the
// translator decoder. Mode32's physical four-operand scalar mask form has no
// named frontend row; observe its low-bank encoding in amd64, then retain it
// verbatim in the separately assembled original mode32 BYTE program.
func x86RawMoveOriginGoBytes(t *testing.T, arch string, rows []x86RawMoveOriginCase) [][]byte {
	t.Helper()
	result := make([][]byte, len(rows))
	for _, physical := range []bool{false, true} {
		var source strings.Builder
		var indexes []int
		for index, row := range rows {
			mode32Physical := arch == "386" && row.scalar && row.role == "register" && row.masking != "plain"
			if mode32Physical != physical {
				continue
			}
			source.WriteString(row.row + "\n")
			indexes = append(indexes, index)
		}
		if len(indexes) == 0 {
			continue
		}
		encoder := arch
		if physical {
			encoder = "amd64"
		}
		code, pcs := x86NumericalBoundaryGoBytes(t, encoder, source.String()+"RET")
		if len(pcs) != len(indexes)+1 || code[len(code)-1] != 0xc3 {
			t.Fatal("incomplete actual Go move byte boundaries", encoder, len(pcs), len(indexes))
		}
		for position, index := range indexes {
			result[index] = append([]byte(nil), code[pcs[position]:pcs[position+1]]...)
		}
	}
	return result
}

func x86RawMoveOriginSource(rows []x86RawMoveOriginCase, code [][]byte, arch string) (string, string) {
	word, pointerMove := goWordSize(arch), "MOVQ"
	if arch == "386" {
		pointerMove = "MOVL"
	}
	var source, declarations strings.Builder
	for index := range rows {
		fmt.Fprintf(&declarations, "func Move%d(input,old,out *[128]byte,mask uint64)\n", index)
		fmt.Fprintf(&source, "TEXT ·Move%d(SB),4,$0-%d\n%s input+0(FP),BX\n%s old+%d(FP),SI\n%s out+%d(FP),DI\nKMOVD mask+%d(FP),K1\n",
			index, 3*word+8, pointerMove, pointerMove, word, pointerMove, 2*word, 3*word)
		source.WriteString("VMOVDQU64 (BX),Z0\nVMOVDQU64 (SI),Z1\nVMOVDQU64 (SI),Z2\n")
		for _, value := range code[index] {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
		source.WriteString("VMOVDQU64 Z2,64(DI)\nRET\n")
	}
	return source.String(), declarations.String()
}

const x86RawMoveOriginBatchSize = 48

func TestX86RawMoveCompleteIndependentBatchDirectory(t *testing.T) {
	rows := x86RawMoveOriginCases()
	if len(rows) != 268 {
		t.Fatal("complete packed12/scalar2 move role/mask/width directory changed", len(rows))
	}
	seen := make(map[string]bool)
	for _, row := range rows {
		if seen[row.row] {
			t.Fatal("duplicate independent move witness", row.row)
		}
		seen[row.row] = true
	}
	if (len(rows)+x86RawMoveOriginBatchSize-1)/x86RawMoveOriginBatchSize != 6 {
		t.Fatal("incomplete or unbounded raw move object partition")
	}
}

func TestX86RawMoveInitializedFiveTargetsBatch00(t *testing.T) { x86RawMoveOriginObjectBatch(t, 0) }
func TestX86RawMoveInitializedFiveTargetsBatch01(t *testing.T) { x86RawMoveOriginObjectBatch(t, 1) }
func TestX86RawMoveInitializedFiveTargetsBatch02(t *testing.T) { x86RawMoveOriginObjectBatch(t, 2) }
func TestX86RawMoveInitializedFiveTargetsBatch03(t *testing.T) { x86RawMoveOriginObjectBatch(t, 3) }
func TestX86RawMoveInitializedFiveTargetsBatch04(t *testing.T) { x86RawMoveOriginObjectBatch(t, 4) }
func TestX86RawMoveInitializedFiveTargetsBatch05(t *testing.T) { x86RawMoveOriginObjectBatch(t, 5) }

func x86RawMoveOriginObjectBatch(t *testing.T, batch int) {
	t.Helper()
	rows := x86RawMoveOriginCases()
	first, last := batch*x86RawMoveOriginBatchSize, (batch+1)*x86RawMoveOriginBatchSize
	if first < 0 || first >= len(rows) {
		t.Fatal("invalid raw move batch", batch)
	}
	if last > len(rows) {
		last = len(rows)
	}
	rows = rows[first:last]
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			code := x86RawMoveOriginGoBytes(t, arch, rows)
			source, declarations := x86RawMoveOriginSource(rows, code, arch)
			for _, target := range x86RawReturnTargets {
				if target.arch != arch {
					continue
				}
				t.Run(target.triple, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized original move bytes could not compose with native inputs/output", err)
							}
							for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								compileLLVMToObject(t, llc, target.triple, "raw-move.ll", "raw-move.o", body)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86ScalarMoveNativeDeadAccessRetainsExactVolatileWidth(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, pointerMove, triple := goWordSize(arch), "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			pointerMove, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range []struct {
			name string
			bits int
		}{{"VMOVSS", 32}, {"VMOVSD", 64}} {
			for _, store := range []bool{false, true} {
				for _, masked := range []bool{false, true} {
					mask, operation := "", row.name
					if masked {
						mask = "K1,"
						if !store {
							operation += ".Z"
						}
					}
					operands := "(BX)," + mask + "X2"
					if store {
						operands = "X2," + mask + "(BX)"
					}
					instruction := operation + " " + operands
					for _, raw := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/store=%t/masked=%t/raw=%t", arch, row.name, store, masked, raw), func(t *testing.T) {
							var source strings.Builder
							fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),BX\nKMOVD mask+%d(FP),K1\nVPXORQ Z2,Z2,Z2\n", word+8, pointerMove, word)
							emitX86GoEncodedTestInstructionForArch(t, &source, instruction, raw, arch)
							source.WriteString("RET\n")
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value(p *byte,mask uint64)", arch, triple, "Go")
							if err != nil {
								t.Fatal("initialized scalar native access lost its source role", err)
							}
							access := "load"
							if store {
								access = "store"
							}
							for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								if !strings.Contains(body, fmt.Sprintf("%s volatile i%d", access, row.bits)) ||
									!strings.Contains(body, "align 1") || masked && !strings.Contains(body, "br i1") {
									t.Fatal("dead scalar access vanished, widened, asserted alignment or lost active-mask guard", instruction, body)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestX86RawMoveActualGoByteCaptureDoesNotChangeOriginalRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86RawMoveOriginCases()
		code := x86RawMoveOriginGoBytes(t, arch, rows)
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				original := append([]byte(nil), code[index]...)
				file, err := Parse(ArchAMD64, "TEXT ·Raw(SB),4,$0-0\n"+row.row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				var raw strings.Builder
				raw.WriteString("TEXT ·Raw(SB),4,$0-0\n")
				for _, value := range original {
					fmt.Fprintf(&raw, "BYTE $%d\n", value)
				}
				raw.WriteString("RET\n")
				decoded, err := Parse(ArchAMD64, raw.String())
				if err == nil {
					decoded, err = normalizeX86RawFile(decoded, arch)
				}
				if err != nil || len(decoded.Funcs[0].Instrs) != 3 {
					t.Fatal("actual original move instruction failed physical normalization", err)
				}
				got, want := decoded.Funcs[0].Instrs[1], file.Funcs[0].Instrs[1]
				if got.Op != want.Op || !x86RawOperandsMatchGoSource(got.Args, want.Args) ||
					got.x86SourceRaw == nil || !bytes.Equal(code[index], original) {
					t.Fatal("captured move bytes changed operation, operands or original identity", got, want)
				}
			})
		}
	}
}

func TestX86RawMoveVoidCannotBorrowInputsMasksOrNativeAddresses(t *testing.T) {
	rows := x86RawMoveOriginCases()
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := goWordSize(arch), "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		code := x86RawMoveOriginGoBytes(t, arch, rows)
		for index, row := range rows {
			if row.bank != "X" {
				continue // Width completeness belongs to the partitioned object matrix.
			}
			var controls []string
			if row.role == "load" && row.masking == "plain" {
				controls = []string{"unknown address", "numeric address", "lost pointer"}
			} else if row.role == "load" && row.masking == "zero" {
				controls = []string{"unknown mask"}
			} else if row.role == "load" && row.masking == "merge" {
				controls = []string{"unknown merge"}
			} else if row.role == "store" && row.masking == "plain" {
				controls = []string{"unknown stored bytes"}
			}
			for _, control := range controls {
				for _, unused := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/unused=%t", arch, row.row, control, unused), func(t *testing.T) {
						declaration, extent := "func Value(p *byte)", word
						if unused {
							declaration, extent = "func Value(p *byte,unused bool)", word+1
						}
						var source strings.Builder
						fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\n", extent, move)
						if control != "unknown address" && control != "numeric address" {
							fmt.Fprintf(&source, "%s p+0(FP),BX\n", move)
						}
						if control == "numeric address" || control == "lost pointer" {
							source.WriteString("MOVL $1,BX\n")
						}
						if control != "unknown mask" {
							source.WriteString("MOVL $5,CX\nKMOVD CX,K1\n")
						}
						source.WriteString("VPXORQ Z0,Z0,Z0\nVPXORQ Z1,Z1,Z1\n")
						if control != "unknown merge" && control != "unknown stored bytes" {
							source.WriteString("VPXORQ Z2,Z2,Z2\n")
						}
						for _, value := range code[index] {
							fmt.Fprintf(&source, "BYTE $%d\n", value)
						}
						source.WriteString("VMOVDQU64 Z2,(DI)\nRET\n")
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("raw move borrowed missing numerical/mask/address inputs for Void", api, err)
							}
						}
					})
				}
			}
		}
	}
}
