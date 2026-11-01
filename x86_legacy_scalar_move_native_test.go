package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// These are initialized programs, independently of reciprocal arithmetic.
// The complete original Go source observes both low-X clearing and Y aliases.
func TestX86LegacyScalarMoveNativeInputsWidthsAndUpperAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			op, scalar string
			width      int
		}{{"MOVSS", "uint32", 32}, {"MOVSD", "uint64", 64}} {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
				if arch == "386" {
					word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
				}
				source := fmt.Sprintf("TEXT ·ScalarMove(SB),4,$0-%d\n%s out+0(FP),DI\n%s p+%d(FP),AX\n"+
					"%s old+%d(FP),BX\nVMOVUPS (BX),Y2\nSTC\n%s (AX),X2\nVMOVUPS Y2,(DI)\nSETCS 32(DI)\nSTMXCSR 36(DI)\nRET\n",
					3*word, move, move, word, move, 2*word, row.op)
				declaration := fmt.Sprintf("func ScalarMove(out *[40]byte,p *%s,old *[32]byte)\n", row.scalar)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil {
							t.Fatal("initialized legacy scalar native source rejected", err)
						}
						if strings.Count(ir, fmt.Sprintf("load volatile i%d, ptr", row.width)) != 1 {
							t.Fatal("native scalar read lost its exact width or mandatory volatile effect")
						}
						missing := strings.Replace(source, fmt.Sprintf("%s p+%d(FP),AX\n", move, word), "", 1)
						if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar native source supplied its own address", err)
						}
					})
				}
			})
		}
	}
}

func TestX86LegacyScalarMoveRegisterAndMemoryByteRules(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			op    string
			width int
		}{{"MOVSS", 4}, {"MOVSD", 8}} {
			for _, source := range []string{"X0", "value+0(FP)"} {
				t.Run(arch+"/"+row.op+"/"+source, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" "+source+",X2")
					initial := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll,
						direction: x86ResultDirectionBackward}
					initial.xmm[0], initial.xmm[2], initial.vectorUpper[2] = 0xffff, 0x5450, 0x55aa00ff00000000
					initial.pointerGP[7] = true
					owned := make([]bool, len(initial.fp))
					for index := range initial.fp {
						initial.fp[index] = true
						owned[index] = true
					}
					mask := uint16(1)<<uint(row.width) - 1
					expected := initial.clone()
					expected.xmm[2] |= mask
					if source != "X0" {
						expected.xmm[2] = 0xffff
					}
					state := initial.clone()
					if !x86ResultTransfer(ins, &state, owned, 0, arch) || !reflect.DeepEqual(state, expected) {
						t.Fatal("legacy scalar copy lost low width, memory upper-zero or old Y/Z preservation", state, expected)
					}
					if source != "X0" {
						state = initial.clone()
						if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, initial) {
							t.Fatal("FP scalar source acquired its missing independent owned layout", state)
						}
					}
				})
			}
		}
	}
}
