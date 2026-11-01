package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// This inventory is independent of the implementation dispatch maps. Complete
// encoder attributes remain owned by the scalar-lane and PS Go-table oracles.
func x86ScalarLaneNativeStoreRows(arch string) []struct {
	op       string
	width    int
	selector int
} {
	var rows []struct {
		op       string
		width    int
		selector int
	}
	for _, vector := range []bool{false, true} {
		for index, width := range []int{1, 2, 4, 8} {
			if arch == "386" && !vector && width == 8 {
				continue // The independent Go-table oracle owns this rejected row.
			}
			op := "PEXTR" + []string{"B", "W", "D", "Q"}[index]
			if vector {
				op = "V" + op
			}
			if arch == "386" && width == 8 {
				width = 4 // Physical VEX.WIG, not a qword store then truncation.
			}
			rows = append(rows, struct {
				op       string
				width    int
				selector int
			}{op, width, 255})
		}
		op, selector := "EXTRACTPS", 3
		if vector {
			op, selector = "VEXTRACTPS", 255
		}
		rows = append(rows, struct {
			op       string
			width    int
			selector int
		}{op, 4, selector})
	}
	return rows
}

func TestX86ScalarLaneNativeStoresSelectedBytesAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86ScalarLaneNativeStoreRows(arch)
		if len(rows) != map[string]int{"amd64": 10, "386": 9}[arch] {
			t.Fatal("incomplete independent scalar native store inventory", arch, len(rows))
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,X1,-1(BX)(CX*2)", row.op, row.selector))
				selected := x86CallerVectorByteMask(int64(row.width)) << uint(16-row.width)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.pointerGP[3] = true
				state.gp[1] = uint8(1)<<uint(x86ResultPointerWord(arch)) - 1
				state.writeVector(1, 64, selected, false)
				before := state.clone()
				accepted, known := x86ResultScalarLaneStepWithRead(ins, &state, nil, 0, arch, true)
				if !accepted || !known || !reflect.DeepEqual(state, before) {
					t.Fatal("paired scalar store must consume only selected bytes without creating state", accepted, known)
				}
				if accepted, _ := x86ResultScalarLaneStep(ins, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone observer acquired native store permission")
				}
				for missing := 0; missing < 16; missing++ {
					changed := before.clone()
					changed.writeVector(1, 64, selected&^(uint64(1)<<uint(missing)), false)
					original := changed.clone()
					accepted, known := x86ResultScalarLaneStepWithRead(ins, &changed, nil, 0, arch, true)
					if !known || accepted != (missing < 16-row.width) || !reflect.DeepEqual(changed, original) {
						t.Fatal("selected-byte dependency widened or missing input was invented", missing, accepted, known)
					}
				}
				for _, mutation := range []string{"pointer", "index", "pointer-index", "encoded", "raw", "address", "unbound-address", "segment", "raw-return", "float", "unresolved"} {
					changed, input := ins, before.clone()
					changed.Args = append([]Operand(nil), ins.Args...)
					switch mutation {
					case "pointer":
						input.pointerGP[3] = false
					case "index":
						input.gp[1] >>= 1
					case "pointer-index":
						input.pointerGP[1] = true
						input.gp[1] = 0 // An actual opaque-pointer import revokes NUM bytes.
					case "encoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "address":
						changed.x86AddressBits = 32
					case "unbound-address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "raw-return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "float":
						changed.Args[0].ImmIsFloat = true
					case "unresolved":
						changed.Args[0].ImmRaw = "UNKNOWN"
					}
					original := input.clone()
					if accepted, _ := x86ResultScalarLaneStepWithRead(changed, &input, nil, 0, arch, true); accepted || !reflect.DeepEqual(input, original) {
						t.Fatal("unproved origin/address/selector acquired a native store", mutation)
					}
				}
			})
		}
	}
}

func TestX86ScalarLaneNativeStoresFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			var source, declarations strings.Builder
			counts := make(map[int]int)
			for index, row := range x86ScalarLaneNativeStoreRows(target.arch) {
				name := fmt.Sprintf("Store%d", index)
				fmt.Fprintf(&declarations, "func %s(out,input *byte)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),BX\n%s input+%d(FP),DX\nMOVL $1,CX\nMOVUPS (DX),X1\n%s $%d,X1,-1(BX)(CX*2)\n%s $%d,X1,-1(BX)(CX*2)\nRET\n",
					name, 2*word, move, move, word, row.op, row.selector, row.op, row.selector)
				counts[row.width] += 2
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original scalar store family rejected", err)
					}
					for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for width, count := range counts {
							if strings.Count(input, fmt.Sprintf("store volatile i%d ", width*8)) != count {
								t.Fatal("exact overwritten native stores were removed or widened", width, count)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "scalar-native-stores.ll", "scalar-native-stores.o", input)
					}
				})
			}
		})
	}
}

func TestX86ScalarLaneNativeStoreVoidRequiresSelectedInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		for _, row := range x86ScalarLaneNativeStoreRows(target.arch) {
			for _, unused := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused-bool=%t", target.triple, row.op, unused), func(t *testing.T) {
					declaration, extent := "func Value(out *byte)", word
					if unused {
						declaration, extent = "func Value(out *byte,unused bool)", word+1
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),BX\n%s $%d,X1,(BX)\nRET\n", extent, move, row.op, row.selector)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void or unused bool invented selected vector bytes", api, err)
						}
					}
				})
			}
		}
	}
}
