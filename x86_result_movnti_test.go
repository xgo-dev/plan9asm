package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86MOVNTIPairedStoreReadsEveryByteAndPreservesState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			name  string
			width int64
		}{{"MOVNTIL", 4}, {"MOVNTIQ", 8}} {
			if arch == "386" && row.width == 8 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.name+" AX,-1(DX)(CX*2)")
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
					valueStack: &x86ResultValueStack{bytes: []uint8{255, 255, 255, 255, 255, 255, 255, 255}, id: true}}
				value, _, _ := x86ResultGP(AX, row.width, arch)
				base, _, _ := x86ResultGP(DX, x86ResultPointerWord(arch), arch)
				index, _, _ := x86ResultGP(CX, x86ResultPointerWord(arch), arch)
				state.gp[value], state.gp[index], state.pointerGP[base] = 0xff, 0xff, true
				state.fp, state.auto = []bool{true, false}, []bool{false, true}
				before := state.clone()
				if accepted, known := x86LoweredMOVNTIResultStep(ins, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("MOVNTI created bytes, memory, pointers or FLAGS facts")
				}
				for missing := int64(0); missing < row.width; missing++ {
					current := before.clone()
					current.gp[value] &^= 1 << uint(missing)
					initial := current.clone()
					if accepted, known := x86LoweredMOVNTIResultStep(ins, &current, nil, arch); !known || accepted || !reflect.DeepEqual(current, initial) {
						t.Fatal("MOVNTI consumed a missing source byte", missing)
					}
				}
				for _, change := range []string{"pointer", "numeric base", "index", "pointer data", "raw", "encoded", "address size", "address override", "segment prefix"} {
					t.Run(change, func(t *testing.T) {
						changed, current := ins, before.clone()
						switch change {
						case "pointer", "numeric base":
							current.pointerGP[base] = false
							if change == "numeric base" {
								current.gp[base] = 0xff
							}
						case "index":
							current.gp[index] = 0
						case "pointer data":
							current.gp[value], current.pointerGP[value] = 0, true
						case "raw":
							changed.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
						case "encoded":
							changed.x86Encoded = true
						case "address size":
							changed.x86AddressBits = 16
						case "address override":
							changed.x86UnboundAddressOverride = true
						case "segment prefix":
							changed.x86SegmentPrefix = 0x64
						}
						initial := current.clone()
						if accepted, known := x86LoweredMOVNTIResultStep(changed, &current, nil, arch); !known || accepted || !reflect.DeepEqual(current, initial) {
							t.Fatal("MOVNTI borrowed unrelated source or memory authority", fmt.Sprint(change))
						}
					})
				}
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("standalone result query borrowed the paired native store")
				}
			})
		}
	}
}
