package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Independent of the production shift directory. Uniform counts select their
// low qword; variable counts have one complete unsigned integer per data lane.
func x86ArithmeticShiftTestNames() []string {
	return []string{"PSRAW", "PSRAL", "VPSRAW", "VPSRAD", "VPSRAQ", "VPSRAVW", "VPSRAVD", "VPSRAVQ"}
}

func x86ArithmeticShiftTestBits(name string) int {
	switch name[len(name)-1] {
	case 'W':
		return 16
	case 'Q':
		return 64
	default:
		return 32
	}
}

func TestX86ArithmeticShiftSharedTypedResultGrammar(t *testing.T) {
	for _, name := range x86ArithmeticShiftTestNames() {
		for _, bank := range []string{"X", "Y", "Z"} {
			legacy := name[0] != 'V'
			if legacy && bank != "X" {
				continue
			}
			perLane := len(name) > 5 && name[5] == 'V'
			count := "X0"
			if perLane {
				count = bank + "0"
			}
			row := name + " " + count + "," + bank + "1," + bank + "2"
			if legacy {
				row = name + " X0,X1"
			}
			ins := x86ScalarLaneInstruction(t, row)
			for _, arch := range []string{"386", "amd64"} {
				form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
				if !known || err != nil || form.laneBits != x86ArithmeticShiftTestBits(name) {
					t.Errorf("complete arithmetic family missing from shared result grammar: %s/%s: %v", arch, row, err)
					continue
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.writeVector(0, 64, ^uint64(0), false)
				state.writeVector(1, 64, ^uint64(0), false)
				if accepted, known := x86ResultPackedShiftStep(ins, &state, nil, arch); !known || !accepted {
					t.Errorf("initialized arithmetic result rejected: %s/%s", arch, row)
				}
			}
		}
	}
}

// Enumerate individual bits rather than borrowing the interval implementation.
// Oversized arithmetic counts select the sign bit, never a constant zero.
func TestX86ArithmeticShiftEverySignBitDependency(t *testing.T) {
	for _, name := range x86ArithmeticShiftTestNames() {
		legacy := name[0] != 'V'
		perLane := len(name) > 5 && name[5] == 'V'
		for _, width := range []int{16, 32, 64} {
			if legacy && width != 16 {
				continue
			}
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			counts := []int{-1}
			if !perLane {
				counts = append(counts, 0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 255)
			}
			for _, count := range counts {
				if legacy && count == 255 {
					continue
				}
				countSource := "X0"
				if count >= 0 {
					countSource = fmt.Sprintf("$%d", count)
				} else if perLane {
					countSource = bank + "0"
				}
				row := name + " " + countSource + "," + bank + "1," + bank + "2"
				if legacy {
					row = name + " " + countSource + ",X1"
				}
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
				if !known || err != nil {
					t.Errorf("arithmetic dependency grammar missing: %s: %v", row, err)
					continue
				}
				bits := x86ArithmeticShiftTestBits(name)
				for output := 0; output < width; output++ {
					var data, counter uint64
					for bit := output * 8; bit < output*8+8; bit++ {
						first, end := count, count+1
						if count < 0 {
							first, end = 0, bits+1
						}
						for shift := first; shift < end; shift++ {
							from := bit%bits + shift
							if from >= bits {
								from = bits - 1
							}
							data |= uint64(1) << uint((bit/bits*bits+from)/8)
						}
					}
					if count < 0 {
						counter = 255
						if perLane {
							counter = x86CallerVectorByteMask(int64(bits/8)) << uint(output/(bits/8)*(bits/8))
						}
					}
					gotData, gotCount := x86PackedShiftByteInputs(form, output)
					if gotData != data || gotCount != counter {
						t.Fatalf("%s byte%d: dependencies %x/%x want %x/%x", row, output, gotData, gotCount, data, counter)
					}
				}
			}
		}
	}
}

func TestX86ArithmeticShiftWholeSourceInputBoundaries(t *testing.T) {
	for _, name := range x86ArithmeticShiftTestNames() {
		row, memory, destination := name+" X0,X1", name+" (AX),X1", "X1"
		if name[0] == 'V' {
			row, memory, destination = name+" X0,X1,X2", name+" (AX),X1,X2", "X2"
		}
		for _, api := range []string{"text", "module", "Go"} {
			// Partial numerical knowledge is intentional: an unobserved
			// pure register result need not initialize every output byte.
			// Observing an undefined byte must still fail, as must native
			// reads and unknown masks even when their results are dead.
			source := "TEXT ·view(SB),4,$0-4\n" + row + "\nPEXTRD $0," + destination + ",AX\nMOVL AX,ret+0(FP)\nRET\n"
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("undefined arithmetic result accepted: %s/%s: %v", row, api, err)
			}
			ir, err = x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-0\n"+memory+"\nRET\n",
				"func view()", "amd64", "x86_64-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("unbound dead native count accepted: %s/%s: %v", memory, api, err)
			}
			if name[0] == 'V' {
				masked := name + ".Z X0,X1,K1,X2"
				ir, err = x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-0\n"+masked+"\nRET\n",
					"func view()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("unknown dead mask accepted: %s/%s: %v", masked, api, err)
				}
			}
		}
	}
}

func TestX86ArithmeticShiftSignBytesMasksAndUpperAliases(t *testing.T) {
	for _, row := range []string{
		"PSRAW $127,X1", "PSRAL $127,X1", "VPSRAW $255,X1,X2",
		"VPSRAD $255,Y1,Y2", "VPSRAQ $255,Z1,Z2",
		"VPSRAW $255,X1,K1,X2", "VPSRAW.Z $255,X1,K1,X2",
		"VPSRAD $255,Y1,K1,Y2", "VPSRAQ.Z $255,Z1,K1,Z2",
	} {
		ins := x86ScalarLaneInstruction(t, row)
		form, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
		if !known || err != nil {
			t.Fatal(row, err)
		}
		var signs uint64
		for at := form.laneBits/8 - 1; at < form.byteWidth; at += form.laneBits / 8 {
			signs |= uint64(1) << uint(at)
		}
		for hole := -1; hole < form.byteWidth; hole++ {
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
			data := signs | 0xa55a000000000000
			if hole >= 0 {
				data &^= uint64(1) << uint(hole)
			}
			state.writeVector(1, 64, data, false)
			state.writeVector(2, 64, 0x55aa55aa55aa55aa, false)
			state.masks[1] = true
			before := state.clone()
			if !x86ResultTransfer(ins, &state, nil, 0, "amd64") {
				t.Fatal("partial arithmetic shift transfer rejected", row, hole)
			}
			var expected uint64
			for output := 0; output < form.byteWidth; output++ {
				sign := output/(form.laneBits/8)*(form.laneBits/8) + form.laneBits/8 - 1
				if before.vectorBytes(1)&(uint64(1)<<uint(sign)) != 0 {
					expected |= uint64(1) << uint(output)
				}
			}
			destination := 2
			if form.legacy {
				destination = 1
			}
			if form.mask >= 0 && !form.zeroing {
				expected &= before.vectorBytes(destination)
			}
			want := before.clone()
			want.writeVector(destination, form.byteWidth, expected, form.legacy)
			if !reflect.DeepEqual(state, want) {
				t.Fatal("sign dependency, mask, upper alias or unrelated state changed", row, hole)
			}
		}
	}
	for _, row := range []string{"VPSRAQ $-1,X1,X2", "VPSRAD $1.0,X1,X2", "VPSRAW $undefined,X1,X2"} {
		ins := x86ScalarLaneInstruction(t, row)
		if _, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64"); !known || err == nil {
			t.Fatal("invalid integer count acquired arithmetic grammar", row, err)
		}
	}
}
