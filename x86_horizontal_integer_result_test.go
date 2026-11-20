package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86HorizontalIntegerResultInputsAndUpperAliases(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range x86HorizontalIntegerOpcodes {
			for _, bank := range []string{"legacy", "X", "Y"} {
				row, width, destination := opcode+" X0,X1", 16, 1
				if bank != "legacy" {
					row, destination = "V"+opcode+" "+bank+"0,"+bank+"1,"+bank+"2", 2
					if bank == "Y" {
						width = 32
					}
				}
				ins := x86YMMReadSource(t, row)
				for input := 0; input < 2; input++ {
					for hole := -1; hole < width; hole++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
						for index := 0; index < 3; index++ {
							mask := x86CallerVectorByteMask(int64(width))
							state.writeVector(index, 64, mask|0xa55aa55aa55aa55a, false)
						}
						if hole >= 0 {
							state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(hole)), false)
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						if accepted != (hole < 0) || !accepted && !reflect.DeepEqual(state, before) {
							t.Fatalf("%s/%s input%d hole%d: accepted=%t", arch, row, input, hole, accepted)
						}
						if accepted {
							want := before.clone()
							want.writeVector(destination, width, x86CallerVectorByteMask(int64(width)), bank == "legacy")
							if !reflect.DeepEqual(state, want) {
								t.Fatal("horizontal result changed unrelated state or upper aliases", arch, row)
							}
						}
					}
				}
			}
		}
	}
}

func TestX86HorizontalIntegerVoidInputsThreeAPIs(t *testing.T) {
	for _, opcode := range x86HorizontalIntegerOpcodes {
		for _, bank := range []string{"legacy", "X", "Y"} {
			row := opcode + " X0,X1"
			if bank != "legacy" {
				row = "V" + opcode + " " + bank + "0," + bank + "1," + bank + "2"
			}
			for _, api := range []string{"text", "module", "Go"} {
				source := "TEXT ·view(SB),4,$0-0\n" + row + "\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("uninitialized horizontal inputs accepted: %s/%s: %v", row, api, err)
				}
			}
		}
	}
}

func TestX86HorizontalIntegerInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var assembly, declarations strings.Builder
	index := 0
	for _, opcode := range x86HorizontalIntegerOpcodes {
		for _, bank := range []string{"legacy", "X", "Y"} {
			row := opcode + " X0,X1"
			if bank != "legacy" {
				row = "V" + opcode + " " + bank + "0," + bank + "1," + bank + "2"
			}
			name := fmt.Sprintf("horizontal%d", index)
			index++
			fmt.Fprintf(&declarations, "func %s(value [32]byte)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-32\nVMOVDQU value+0(FP),Y0\nVMOVDQU value+0(FP),Y1\n%s\nRET\n", name, row)
		}
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}
