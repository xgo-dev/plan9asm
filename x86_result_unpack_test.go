package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// An independent byte-array oracle follows each 128-bit interleave lane.
// It deliberately does not call the production dependency calculation.
func x86ResultUnpackExpected(op string, width int, first, second uint64) uint64 {
	bytes := x86UnpackTestLaneBytes(op)
	high := strings.Contains(op, "UNPCKH")
	var result uint64
	for output := 0; output < width; output++ {
		group := output / 16 * 16
		lane := output % 16 / bytes
		input := group + lane/2*bytes + output%bytes
		if high {
			input += 8
		}
		known := second
		if lane%2 != 0 {
			known = first
		}
		if known>>uint(input)&1 != 0 {
			result |= uint64(1) << uint(output)
		}
	}
	return result
}

func TestX86ResultPackedUnpackCompleteRegisterByteRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86CallerUnpackOpcodes() {
			vector := strings.HasPrefix(op, "V")
			for _, bank := range []string{"X", "Y", "Z"} {
				if !vector && bank != "X" {
					continue
				}
				for _, mask := range []string{"", "K1", "K1.Z"} {
					if mask != "" && (!vector || arch == "386") {
						continue
					}
					name := op
					row := op + " X0,X1"
					if vector {
						if mask == "K1.Z" {
							name += ".Z"
						}
						args := []string{bank + "0", bank + "1"}
						if mask != "" {
							args = append(args, "K1")
						}
						args = append(args, bank+"2")
						row = name + " " + strings.Join(args, ",")
					}
					t.Run(arch+"/"+row, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, row)
						form, known, err := x86PackedUnpackProperties(ins, arch)
						if !known || err != nil || form.mmx {
							t.Fatal("official typed register row lost", known, err)
						}
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.masks[1] = true
						patterns := []uint64{0x915ac30ef047268b, 0xe315a49c7026b8fd, 0x693ca517f0d24b8e}
						for i, bits := range patterns {
							state.xmm[i], state.vectorUpper[i] = uint16(bits), bits&^0xffff
						}
						first, second := patterns[0], patterns[1]
						destination := form.destination
						index, _ := amd64VectorRegisterIndex(ins.Args[destination].Reg, form.byteWidth)
						old := state.vectorBytes(index)
						want := x86ResultUnpackExpected(op, form.byteWidth, first, second)
						if mask == "K1" {
							want &= old
						}
						active := x86CallerVectorByteMask(int64(form.byteWidth))
						if form.legacy {
							want |= old &^ active
						} else {
							want |= ^active
						}
						if !x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("typed interleave has no numerical-byte transfer")
						}
						if got := state.vectorBytes(index); got != want || state.flags != x86ByteFlagsAll {
							t.Fatalf("got=%016x want=%016x flags=%x", got, want, state.flags)
						}
					})
				}
			}
		}
	}
}

func TestX86ResultPackedUnpackSparseByteBroadcast(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			state := x86ResultState{}
			// Only byte zero of the incoming GP is numerical. Go's AMD64
			// MOVD source alias is MOVQ, independently clearing X bytes8..15;
			// the legal mode32 spelling is MOVL and clears X bytes4..15.
			state.xmm[0] = 0xff01
			if arch == "386" {
				state.xmm[0] = 0xfff1
			}
			for _, row := range []string{"PUNPCKLBW X0,X0", "PUNPCKLBW X0,X0", "PSHUFL $0,X0,X0"} {
				if !x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, arch) {
					t.Fatal("sparse broadcast cannot compose", row)
				}
			}
			if state.xmm[0] != 0xffff || state.vectorUpper[0] != 0 {
				t.Fatalf("dead GP bytes became required, or wider aliases were invented: %04x/%016x", state.xmm[0], state.vectorUpper[0])
			}
		})
	}
}

func TestX86ResultPackedUnpackMemoryRolesDoNotShrink(t *testing.T) {
	for _, op := range x86CallerUnpackOpcodes() {
		if !strings.HasPrefix(op, "V") {
			continue
		}
		for _, broadcast := range []bool{false, true} {
			if broadcast && x86UnpackTestLaneBytes(op) < 4 {
				continue
			}
			name := op + ".Z"
			if broadcast {
				name = op + ".BCST.Z"
			}
			row := name + " a+0(FP),Z1,K1,Z2"
			t.Run(row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86PackedUnpackProperties(ins, "amd64")
				if !known || err != nil {
					t.Fatal(known, err)
				}
				for missing := -1; missing < form.memoryBytes; missing++ {
					state := x86ResultState{fp: make([]bool, form.memoryBytes)}
					owned := make([]bool, form.memoryBytes)
					state.masks[1], state.xmm[1], state.vectorUpper[1] = true, 0xffff, ^uint64(0xffff)
					for i := range owned {
						owned[i], state.fp[i] = true, i != missing
					}
					accepted := x86ResultTransfer(ins, &state, owned, int64(len(owned)), "amd64")
					if accepted != (missing == -1) {
						t.Fatalf("full E4NF extent %d, missing byte %d: accepted=%t", form.memoryBytes, missing, accepted)
					}
				}
				// Initialized address bits and a mask do not prove pointee bytes.
				native := x86ScalarLaneInstruction(t, strings.Replace(row, "a+0(FP)", "(AX)", 1))
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.gp[0], state.masks[1], state.xmm[1], state.vectorUpper[1] = 0xff, true, 0xffff, ^uint64(0xffff)
				if x86ResultTransfer(native, &state, nil, 0, "amd64") {
					t.Fatal("native memory acquired permission from initialized address or numerical mask")
				}
			})
		}
	}
	for _, row := range []string{"PUNPCKLBW a+0(FP),X0", "PUNPCKHBW a+0(FP),X0", "PUNPCKLBW M0,M1"} {
		t.Run(fmt.Sprintf("legacy/%s", row), func(t *testing.T) {
			state := x86ResultState{fp: make([]bool, 16)}
			owned := make([]bool, 16)
			for i := range owned {
				owned[i], state.fp[i] = true, true
			}
			state.xmm[0] = 0xffff
			if x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, owned, 16, "amd64") {
				t.Fatal("logical bytes invented legacy alignment or the disjoint physical MMX bank")
			}
		})
	}
}

func TestX86ResultPackedUnpackRejectsUnboundOperandRoles(t *testing.T) {
	for _, row := range []struct{ arch, source string }{
		{"amd64", "VPUNPCKLBW.Z X0,X1,K1,X2"}, // Unknown mask is not an inactive-lane proof.
		{"amd64", "PUNPCKLBW X0,X1,X2"},
		{"amd64", "VPUNPCKLBW X0,Y1,Y2"},
		{"amd64", "VPUNPCKLBW.BCST (AX),X1,X2"},
		{"amd64", "VUNPCKLPD.Z X0,X1,X2"},
		{"386", "VPUNPCKLBW X8,X1,X2"},
		{"386", "VPUNPCKLBW X0,X1,K1,X2"},
	} {
		t.Run(row.arch+"/"+row.source, func(t *testing.T) {
			state := x86ResultState{flags: x86ByteFlagsAll}
			for i := range state.xmm {
				state.xmm[i], state.vectorUpper[i] = 0xffff, ^uint64(0xffff)
			}
			before := state.clone()
			if x86ResultTransfer(x86ScalarLaneInstruction(t, row.source), &state, nil, 0, row.arch) {
				t.Fatal("initialized operands invented a missing mask, format or mode role")
			}
			for i := range state.xmm {
				if state.vectorBytes(i) != before.vectorBytes(i) {
					t.Fatal("failed form changed a physical register")
				}
			}
			if state.flags != before.flags {
				t.Fatal("failed form changed flags")
			}
		})
	}
}
