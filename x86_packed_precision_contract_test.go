package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent lane/carrier directory. Narrowing X has eight active output
// bytes in an X carrier; zeroing that tail is not a read of the old carrier.
type x86PackedPrecisionOracleRow struct {
	op, source, control, mode string
	inputBits, outputBits     int
	input, output, carrier    int
	vector, broadcast         bool
}

func x86PackedPrecisionBaseRows() []x86PackedPrecisionOracleRow {
	return []x86PackedPrecisionOracleRow{
		{op: "CVTPS2PD", inputBits: 32, outputBits: 64, input: 8, output: 16, carrier: 16},
		{op: "CVTPD2PS", inputBits: 64, outputBits: 32, input: 16, output: 8, carrier: 16},
		{op: "VCVTPS2PD", inputBits: 32, outputBits: 64, input: 8, output: 16, carrier: 16, vector: true},
		{op: "VCVTPS2PD", inputBits: 32, outputBits: 64, input: 16, output: 32, carrier: 32, vector: true},
		{op: "VCVTPS2PD", inputBits: 32, outputBits: 64, input: 32, output: 64, carrier: 64, vector: true},
		{op: "VCVTPD2PSX", inputBits: 64, outputBits: 32, input: 16, output: 8, carrier: 16, vector: true},
		{op: "VCVTPD2PSY", inputBits: 64, outputBits: 32, input: 32, output: 16, carrier: 16, vector: true},
		{op: "VCVTPD2PS", inputBits: 64, outputBits: 32, input: 64, output: 32, carrier: 32, vector: true},
	}
}

// Orthogonal axes, not their object-compilation Cartesian product. Each
// legal source, mask, scalar broadcast and SAE/ER control occurs at least once.
func x86PackedPrecisionOracleRows() []x86PackedPrecisionOracleRow {
	var rows []x86PackedPrecisionOracleRow
	for _, base := range x86PackedPrecisionBaseRows() {
		for _, source := range []string{"register", "native", "FP"} {
			row := base
			row.source = source
			rows = append(rows, row)
		}
		if !base.vector {
			continue
		}
		for _, mode := range []string{"merge", "zero"} {
			row := base
			row.source, row.mode = "register", mode
			rows = append(rows, row)
		}
		for _, mode := range []string{"", "zero"} {
			row := base
			row.source, row.mode, row.broadcast = "native", mode, true
			rows = append(rows, row)
		}
		if base.op == "VCVTPS2PD" && base.carrier == 64 {
			row := base
			row.source, row.control = "register", "SAE"
			rows = append(rows, row)
		}
		if base.op == "VCVTPD2PS" {
			for _, control := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				row := base
				row.source, row.control = "register", control
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func (row x86PackedPrecisionOracleRow) sourceBytes() int {
	if row.broadcast {
		return row.inputBits / 8
	}
	return row.input
}

func (row x86PackedPrecisionOracleRow) registers() (source, destination string) {
	sourceWidth := 16
	if row.input > 16 {
		sourceWidth = row.input
	}
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
	return bank[sourceWidth] + "0", bank[row.carrier] + "1"
}

func (row x86PackedPrecisionOracleRow) instruction() string {
	source, destination := row.registers()
	if row.source == "native" {
		source = "(BX)"
	} else if row.source == "FP" {
		source = "value+0(FP)"
	}
	op := row.op
	if row.broadcast {
		op += ".BCST"
	} else if row.control != "" {
		op += "." + row.control
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	mask := ""
	if row.mode != "" {
		mask = "K1,"
	}
	return op + " " + source + "," + mask + destination
}

func TestX86PackedPrecisionCompleteTypedSourceAndControlDirectory(t *testing.T) {
	rows := x86PackedPrecisionOracleRows()
	if len(rows) != 53 {
		t.Fatal("independent complete precision directory changed", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index, row := range rows {
			fmt.Fprintf(&source, "TEXT Row%d(SB),4,$0-128\n%s\nRET\n", index, row.instruction())
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("packed precision lacks its closed typed byte/FLAGS contract", known, err, effect)
				}
				reads, writes := make(map[int]bool), make(map[int]bool)
				for _, operand := range effect.operands {
					width := int64(row.carrier)
					if operand.index == 0 {
						width = int64(row.sourceBytes())
					} else if operand.operand.Reg == "K1" {
						width = 8
					}
					if operand.index < 0 || operand.index >= len(ins.Args) || operand.width != width ||
						!reflect.DeepEqual(operand.operand, ins.Args[operand.index]) {
						t.Fatal("source tuple, K or destination carrier differs from the independent directory", operand)
					}
					reads[operand.index] = reads[operand.index] || operand.read
					writes[operand.index] = writes[operand.index] || operand.write
				}
				last := len(ins.Args) - 1
				for index := range ins.Args {
					if reads[index] != (index < last || row.mode == "merge") || writes[index] != (index == last) {
						t.Fatal("precision acquired an old-destination input or lost a source/mask", index, reads, writes)
					}
				}
			})
		}
	}
}

func TestX86PackedPrecisionEveryInputByteAndIndependentAliases(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedPrecisionBaseRows() {
			for _, sourceKind := range []string{"register", "FP"} {
				row.source = sourceKind
				for missing := -1; missing < row.input; missing++ {
					t.Run(fmt.Sprintf("%s/%s/%d/%s/missing%d", arch, row.op, row.carrier, sourceKind, missing), func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, row.instruction())
						state := x86ResultState{fp: make([]bool, 64), flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						owned := make([]bool, 64)
						for at := range owned {
							state.fp[at], owned[at] = true, true
						}
						state.writeVector(0, 64, ^uint64(0), true)
						state.writeVector(1, 64, 0xa5a55a5af00f1234, true)
						state.pointerGP[3], state.callerAddressGP[7], state.masks[2] = true, true, true
						if missing >= 0 {
							if sourceKind == "FP" {
								state.fp[missing] = false
							} else {
								state.writeVector(0, 64, ^(uint64(1) << uint(missing)), true)
							}
						}
						before, want := state.clone(), state.clone()
						if missing < 0 {
							want.writeVector(1, row.carrier, x86CallerVectorByteMask(int64(row.carrier)), !row.vector)
						}
						if accepted := x86ResultTransfer(ins, &state, owned, 64, arch); accepted != (missing < 0) || !reflect.DeepEqual(state, want) {
							t.Fatal("packed precision invented input, lost forced zeros/aliases or changed another state", accepted, missing, before, state, want)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedPrecisionOverlappingCarriersReadBeforeWrite(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86PackedPrecisionBaseRows() {
			row.source = "register"
			t.Run(fmt.Sprintf("%s/%s/%d", arch, row.op, row.carrier), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				last := len(ins.Args) - 1
				ins.Args[last].Reg = Reg(string(ins.Args[last].Reg[:1]) + "0")
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.writeVector(0, 64, x86CallerVectorByteMask(int64(row.input)), true)
				before, want := state.clone(), state.clone()
				want.writeVector(0, row.carrier, x86CallerVectorByteMask(int64(row.carrier)), !row.vector)
				if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
					t.Fatal("same physical source/destination carrier lost input bytes or borrowed unknown upper aliases", before, state, want)
				}
			})
		}
	}
}
