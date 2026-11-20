package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent ymm/yxm_q4 and _yvandnpd families, including each opcode's
// separate N4 broadcast attribute. Neither inventory reads production specs.
func x86NarrowValueRows(arch string) []struct{ op, bank, mode string } {
	rows := x86FixedBinaryValueRows(arch, []string{
		"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB",
		"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB",
	})
	broadcast := x86FixedBinaryValueRows(arch, []string{"VPACKSSDW", "VPACKUSDW"})
	for _, row := range broadcast {
		row.op += ".BCST"
		rows = append(rows, row)
	}
	return rows
}

func TestX86PackedNarrowValueCompleteFamilyFiveTargetsThreeAPIs(t *testing.T) {
	for batch := 0; batch < 2; batch++ {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			x86FixedBinaryCompleteFamilyObjects(t, func(arch string) []struct{ op, bank, mode string } {
				rows := x86NarrowValueRows(arch)
				want := 58
				if arch == "386" {
					want = 22
				}
				if len(rows) != want {
					t.Fatal("complete independent narrow denominator changed", len(rows), want)
				}
				return rows[batch*want/2 : (batch+1)*want/2]
			}, 29, 11)
		})
	}
}

// Discarded numerical bytes may stay unknown. An actual native address,
// mask or result byte still cannot be borrowed from implementation slots.
func TestX86PackedNarrowVoidCannotInventMaskOrMemoryInputs(t *testing.T) {
	for _, row := range x86NarrowValueRows("amd64") {
		source, declaration := x86FixedBinaryValueFixture("amd64", row.op, row.bank, row.mode, false)
		variants := map[string]string{
			"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
			"unknown-index":   strings.Replace(source, "MOVL $1,DX\n", "", 1),
		}
		if row.mode != "plain" {
			variants["unknown-mask"] = strings.Replace(source, "KMOVQ CX,K1\n", "", 1)
		}
		for name, changed := range variants {
			t.Run(row.op+"/"+row.bank+"/"+row.mode+"/"+name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
						t.Fatal("complete independent Void control rejected", api, err)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Error("Void narrow acquired a missing native address or mask", api, err)
					}
				}
			})
		}
	}
}

func TestX86PackedNarrowNativeInputsStayIndependent(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, x86NarrowValueRows)
}

func TestX86PackedNarrowResultEveryOutputByteKeepsExactDependencies(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86NarrowValueRows(arch) {
			if strings.Contains(row.op, ".") {
				continue // Broadcast's complete memory tuple has its own matrix.
			}
			op, operands := row.op, "X0,X1"
			legacy := !strings.HasPrefix(op, "V")
			if !legacy {
				operands = row.bank + "0," + row.bank + "1,"
				if row.mode != "plain" {
					operands += "K1,"
				}
				operands += row.bank + "2"
				if row.mode == "zero" {
					op += ".Z"
				}
			}
			t.Run(arch+"/"+op+" "+operands, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" "+operands)
				width, destination := amd64VectorByteWidth(Reg(row.bank+"0")), 2
				if legacy {
					destination = 1
				}
				inputBytes := 2
				if strings.HasSuffix(row.op, "DW") || row.op == "PACKSSLW" {
					inputBytes = 4
				}
				for _, first := range []uint64{0, 1, 3, 15, 0xffff, 0xff00ff00ff00ff00, ^uint64(0)} {
					for _, second := range []uint64{0, 7, 0xffff, 0x5555555555555555, ^uint64(0)} {
						old := uint64(0xaaaaaaaaaaaaaaaa)
						state := x86ResultState{flags: x86ByteFlagsAll}
						for index, bits := range []uint64{first, second, old} {
							state.xmm[index], state.vectorUpper[index] = uint16(bits), bits&^0xffff
						}
						state.masks[1] = true
						if legacy {
							old = second
						}
						// An output element depends on every byte of exactly one
						// signed input element, independently in each 128-bit lane.
						var want uint64
						for output := 0; output < width; output += inputBytes / 2 {
							chunk, local := output/16*16, output%16
							input, source := chunk+(local%8)/(inputBytes/2)*inputBytes, second
							if local >= 8 {
								source = first
							}
							needed := uint64(1<<uint(inputBytes)-1) << uint(input)
							if source&needed == needed {
								want |= uint64(1<<uint(inputBytes/2)-1) << uint(output)
							}
						}
						if row.mode == "merge" {
							want &= old
						}
						active := x86CallerVectorByteMask(int64(width))
						if legacy {
							want |= old &^ active
						} else {
							want |= ^active
						}
						if !x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("complete typed narrow has no result dependency consumer")
						}
						if got := state.vectorBytes(destination); got != want || state.flags != x86ByteFlagsAll {
							t.Fatalf("first=%x second=%x got=%x want=%x flags=%x", first, second, got, want, state.flags)
						}
					}
				}
			})
		}
	}
}
