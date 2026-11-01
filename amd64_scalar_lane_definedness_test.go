package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarLaneDefinedBytesSharedConsumers(t *testing.T) {
	for _, prefix := range []string{"", "V"} {
		for _, size := range []struct {
			name string
			bits int
		}{{"B", 8}, {"W", 16}, {"D", 32}, {"Q", 64}} {
			for lane := 0; lane < 128/size.bits; lane++ {
				t.Run(fmt.Sprintf("%s%s/%d", prefix, size.name, lane), func(t *testing.T) {
					row := fmt.Sprintf("%sPINSR%s $%d,AX,X0", prefix, size.name, lane)
					if prefix != "" {
						row += ",X1"
					}
					ins := x86ScalarLaneInstruction(t, row)
					form, known, err := x86ScalarLaneProperties(ins, "amd64")
					if !known || err != nil {
						t.Fatal(form, err)
					}
					state := x86ResultState{}
					state.gp[0] = 0xff
					if ok, known := x86ResultScalarLaneStep(ins, &state, nil, 0, "amd64"); !known || !ok {
						t.Fatal("initialized scalar source rejected")
					}
					index := 0
					if prefix != "" {
						index = 1
					}
					want := uint16((uint64(1)<<uint(size.bits/8) - 1) << uint(lane*size.bits/8))
					if state.xmm[index] != want {
						t.Fatalf("unknown old lanes were washed: %04x/%04x", state.xmm[index], want)
					}
					caller := x86SourceStackState{known: map[Reg]uint8{AX: 0xff}, vectors: map[Reg]uint64{"Z0": 0, "Z1": 0}, callers: map[Reg]x86CallerPointerValue{}}
					if !x86CallerScalarLaneStep(&ins, form, &caller, nil) || uint16(caller.vectors[Reg(fmt.Sprintf("Z%d", index))]) != want {
						t.Fatal("caller/result effect drift")
					}
					upper := caller.vectors[Reg(fmt.Sprintf("Z%d", index))] >> 16
					if prefix == "" && upper != 0 || prefix != "" && upper != ^uint64(0)>>16 {
						t.Fatal("encoding upper-alias effect drift")
					}
					for _, extractPrefix := range []string{"", "V"} {
						for selected := 0; selected < 128/size.bits; selected++ {
							extract := x86ScalarLaneInstruction(t, fmt.Sprintf("%sPEXTR%s $%d,X%d,BX", extractPrefix, size.name, selected, index))
							copyState := state
							ok, known := x86ResultScalarLaneStep(extract, &copyState, nil, 0, "amd64")
							if !known || ok != (selected == lane) {
								t.Fatal("extraction consumed unselected/unknown lane", extract, ok)
							}
						}
					}
					for _, taint := range []string{"undefined-GP", "incoming-pointer"} {
						bad := state
						if taint == "undefined-GP" {
							bad.gp[0] = 0
						} else {
							bad.pointerGP[0] = true
						}
						if ok, _ := x86ResultScalarLaneStep(ins, &bad, nil, 0, "amd64"); ok {
							t.Fatal("scalar insert granted unknown/pointer source", taint)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarLaneResultAPIMustInitializeOnlyObservedBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, tc := range []struct {
			name, body string
			good       bool
		}{
			{"selected-only", "MOVL k+0(FP),AX\nPINSRD $0,AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+8(FP)\n", true},
			{"unknown-selected", "MOVL k+0(FP),AX\nPINSRD $1,AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+8(FP)\n", false},
			{"unknown-old-low", "PINSRD $1,k+0(FP),X0\nMOVL X0,ret+8(FP)\n", false},
			{"unknown-GP", "PINSRD $0,AX,X0\nMOVL X0,ret+8(FP)\n", false},
			{"uninitialized-result-read", "PINSRD $0,ret+8(FP),X0\nMOVL X0,ret+8(FP)\n", false},
			{"input-store", "MOVL k+0(FP),X0\nPEXTRD $0,X0,k+0(FP)\nMOVL X0,ret+8(FP)\n", false},
			{"partial-join", "MOVL k+0(FP),AX\nCMPL AX,$0\nJE skip\nPINSRD $0,AX,X0\nskip:\nMOVL X0,ret+8(FP)\n", false},
			// The memory-to-X MOVL defines all 16 bytes (zeroing bytes 4..15).
			// Once AES has registered byte effects, this complete input is a
			// positive control, not an unknown-instruction rejection.
			{"registered-AES-complete-input", "MOVL k+0(FP),X0\nPINSRD $1,k+0(FP),X0\nAESENC X0,X0\nMOVL X0,ret+8(FP)\n", true},
			// Inserting only lane 1 leaves bytes 0..3 and 8..15 undefined.
			// Registering AES must not grant those potential result inputs.
			{"registered-AES-missing-input-bytes", "PINSRD $1,k+0(FP),X0\nAESENC X0,X0\nMOVL X0,ret+8(FP)\n", false},
		} {
			t.Run(target.triple+"/"+tc.name, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-12\n" + tc.body + "RET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(k,h uint32) uint32\n", target.arch, target.triple, api)
					if (err == nil) != tc.good || !tc.good && ir != "" {
						t.Fatalf("%s result domain: %v / %q", api, err, ir)
					}
					if tc.good {
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "selected.ll", "selected.o", ir)
					}
				}
			})
		}
	}
}

func TestX86ScalarPSLaneResultSelectors(t *testing.T) {
	for _, op := range []string{"INSERTPS", "VINSERTPS"} {
		for immediate := 0; immediate < 256; immediate++ {
			row := fmt.Sprintf("%s $%d,X0,X1", op, immediate)
			if op[0] == 'V' {
				row += ",X2"
			}
			ins := x86ScalarLaneInstruction(t, row)
			state := x86ResultState{}
			state.xmm[0] = 0xf << uint((immediate>>6)*4)
			state.xmm[1] = 0xf0
			if ok, known := x86ResultScalarLaneStep(ins, &state, nil, 0, "amd64"); !known || !ok {
				t.Fatal(op, immediate)
			}
			want := uint16(0xf0)&^(uint16(0xf)<<uint((immediate>>4&3)*4)) | uint16(0xf)<<uint((immediate>>4&3)*4)
			for lane := 0; lane < 4; lane++ {
				if immediate&(1<<lane) != 0 {
					want |= uint16(0xf) << uint(lane*4)
				}
			}
			dst := 1
			if op[0] == 'V' {
				dst = 2
			}
			if state.xmm[dst] != want {
				t.Fatal("PS source/target/zero-mask mismatch", op, immediate, state.xmm[dst], want)
			}
		}
	}
	for _, op := range []string{"EXTRACTPS", "VEXTRACTPS"} {
		for lane := 0; lane < 4; lane++ {
			ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,X0,AX", op, lane))
			state := x86ResultState{}
			state.xmm[0] = 0xf << uint(lane*4)
			if ok, known := x86ResultScalarLaneStep(ins, &state, nil, 0, "amd64"); !known || !ok || state.gp[0] != 0xff {
				t.Fatal("selected PS bytes rejected")
			}
			state.xmm[0] &= ^uint16(1 << uint(lane*4))
			if ok, _ := x86ResultScalarLaneStep(ins, &state, nil, 0, "amd64"); ok {
				t.Fatal("PS unknown byte was initialized")
			}
		}
	}
}

func TestX86ScalarLaneCallerMemoryShapeExactWidths(t *testing.T) {
	for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ", "PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ"} {
		width := map[byte]int64{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[op[len(op)-1]]
		row, index := op+" $1,(AX),X1", 1
		if strings.Contains(op, "EXTR") {
			row, index = op+" $1,X1,(AX)", 2
		} else if op[0] == 'V' {
			row += ",X2"
		}
		ins := x86ScalarLaneInstruction(t, row)
		actual, write, valid := x86InstructionMemoryShape(ins, index, "amd64")
		if !valid || actual != width || write != strings.Contains(op, "EXTR") {
			t.Fatal("memory role widened", op, actual, write, valid)
		}
		if _, _, valid = x86InstructionMemoryShape(ins, 0, "amd64"); valid {
			t.Fatal("immediate acquired memory role", op)
		}
	}
}
