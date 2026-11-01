package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ByteShuffleIndependentResultConsumers(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const data = "DATA control<>+0(SB)/8,$0x0001020304050607\nDATA control<>+8(SB)/8,$0x08090a0b0c0d0e0f\nGLOBL control<>(SB),8,$16\n"
	for _, row := range []string{
		"PSHUFB X0,X1", "VPSHUFB X0,X1,X1",
		"PSHUFB control<>(SB),X1", "VPSHUFB control<>(SB),X1,X1",
	} {
		t.Run(row, func(t *testing.T) {
			source := data + "TEXT ·view(SB),4,$0-20\nMOVQ a+0(FP),X0\nMOVQ b+8(FP),X1\n" + row + "\nPEXTRD $0,X1,AX\nMOVL AX,ret+16(FP)\nRET\n"
			for _, target := range x86RawReturnTargets {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(a,b uint64) uint32\n", target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s/%s complete numerical shuffle has no result consumer: %v", target.triple, api, err)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, "byte-shuffle-result-"+api)
				}
			}
		})
	}
}

func TestX86ByteShuffleDeadMemoryRetainsOriginalAccess(t *testing.T) {
	for _, row := range []struct {
		body  string
		width int
	}{
		{"PSHUFB (DX),X0", 16},
		{"VPSHUFB (DX),X0,X1", 16},
		{"VPSHUFB (DX),Y0,Y1", 32},
		{"VPSHUFB (DX),Z0,Z1", 64},
		{"VPSHUFB.Z (DX),Z0,K1,Z1", 64},
	} {
		t.Run(row.body, func(t *testing.T) {
			source := "TEXT ·view(SB),4,$0-8\nMOVQ p+0(FP),DX\nVPXORQ Z0,Z0,Z0\nMOVL $0,AX\nKMOVW AX,K1\n" + row.body + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte)\n", "amd64", "x86_64-unknown-linux-gnu", "Go")
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				want := fmt.Sprintf("load volatile <%d x i8>", row.width)
				if !strings.HasPrefix(row.body, "V") {
					want = "asm sideeffect \"pshufb "
				}
				if !strings.Contains(text, want) {
					t.Errorf("dead shuffle lost its full native read/alignment effect: want %s", want)
				}
			}
		})
	}
}

func TestX86ByteShuffleSparseResultAndCallerBytes(t *testing.T) {
	for _, width := range []int{16, 32, 64} {
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
		for _, legacy := range []bool{false, true} {
			if legacy && width != 16 {
				continue
			}
			for masking := 0; masking < 3; masking++ {
				if legacy && masking != 0 {
					continue
				}
				row, dst := "VPSHUFB", 2
				if legacy {
					row, dst = "PSHUFB", 1
				}
				if masking == 2 {
					row += ".Z"
				}
				row += " " + bank + "0," + bank + "1"
				if masking != 0 {
					row += ",K1"
				}
				if !legacy {
					row += "," + bank + "2"
				}
				ins := x86ScalarLaneInstruction(t, row)
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						initial := [3]uint64{^uint64(0), ^uint64(0), ^uint64(0)}
						if missing >= 0 {
							initial[input] &^= uint64(1) << uint(missing)
						}
						result := x86ResultState{flags: 0x3f}
						caller := x86SourceStackState{vectors: map[Reg]uint64{}, masks: map[Reg]bool{"K1": true}}
						for i, value := range initial {
							result.writeVector(i, 64, value, false)
							caller.vectors[Reg(fmt.Sprintf("Z%d", i))] = value
						}
						result.masks[1] = true
						if !x86ResultTransfer(ins, &result, nil, 0, "amd64") || !x86CallerVectorMoveStep(&ins, &caller, nil) {
							t.Fatal("missing byte consumer", row)
						}
						var want uint64
						for output := 0; output < 64; output++ {
							known := !legacy || initial[dst]>>uint(output)&1 != 0
							if output < width {
								known = initial[0]>>uint(output)&1 != 0
								for selected := 0; selected < 16; selected++ {
									known = known && initial[1]>>uint(output/16*16+selected)&1 != 0
								}
								if masking == 1 {
									known = known && initial[dst]>>uint(output)&1 != 0
								}
							}
							if known {
								want |= uint64(1) << uint(output)
							}
						}
						if result.vectorBytes(dst) != want || caller.vectors[Reg(fmt.Sprintf("Z%d", dst))] != want || result.flags != 0x3f {
							t.Fatalf("%s input=%d missing=%d: result=%x caller=%x want=%x", row, input, missing, result.vectorBytes(dst), caller.vectors[Reg(fmt.Sprintf("Z%d", dst))], want)
						}
					}
				}
			}
		}
	}
}

func TestX86ByteShuffleResultMemoryAndMaskBoundaries(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
		row := "VPSHUFB.Z value+0(FP)," + bank + "1,K1," + bank + "2"
		ins := x86ScalarLaneInstruction(t, row)
		for missing := -1; missing < 64; missing++ {
			for _, maskKnown := range []bool{false, true} {
				state := x86ResultState{fp: make([]bool, 64)}
				owned := make([]bool, 64)
				for i := range owned {
					owned[i], state.fp[i] = true, i != missing
				}
				state.writeVector(1, 64, ^uint64(0), false)
				state.masks[1] = maskKnown
				accepted := x86ResultTransfer(ins, &state, owned, 64, "amd64")
				want := maskKnown && (missing < 0 || missing >= width)
				if accepted != want || accepted && state.vectorBytes(2) != ^uint64(0) || len(ins.x86CallerMemory) != 0 {
					t.Fatal("mask/tuple observation invented bytes or caller permission", row, missing, maskKnown, accepted)
				}
			}
		}
	}
	for _, source := range []string{"(AX)", "·unknown(SB)", "value-1(FP)"} {
		ins := x86ScalarLaneInstruction(t, "VPSHUFB.Z "+source+",X1,K1,X2")
		state := x86ResultState{}
		state.xmm[1], state.masks[1], state.pointerGP[0] = 0xffff, true, true
		if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
			t.Fatal("unproved memory acquired numerical authority", source)
		}
	}
}
