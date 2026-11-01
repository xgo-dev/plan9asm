package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86AESDeadRegisterResultsStayUnknownWithoutChangingFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range x86AESOracleNames {
			row, destination := x86AESOracleRow(name, "X0", "X")
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
			state.xmm[1], state.vectorUpper[destination] = 0xffff, 0x12340000
			state.pointerGP[6], state.gp[3], state.masks[2] = true, 0x55, true
			want := state.clone()
			want.writeVector(destination, 16, 0, !strings.HasPrefix(name, "V"))
			accepted, known := x86LoweredAESResultStep(x86ScalarLaneInstruction(t, row), &state, nil, arch)
			if !known || !accepted || !reflect.DeepEqual(state, want) {
				t.Fatal("dead nontrapping AES result must remain unknown without erasing independent FLAGS", arch, row)
			}
		}
	}
}

func TestX86AESUnknownRegisterResultsCannotBecomeObservableValues(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range x86AESOracleNames {
			row, destination := x86AESOracleRow(name, "X0", "X")
			for _, raw := range []bool{false, true} {
				instruction := row
				if raw {
					instruction = x86RawNumericalInstruction(t, target.arch, row)
				}
				for _, observe := range []bool{false, true} {
					body := "MOVL $1,AX\nMOVL AX,X1\n" + instruction + "\n"
					if observe {
						body += fmt.Sprintf("MOVL X%d,AX\nTESTL AX,AX\nSETEQ CX\n", destination)
					}
					source := "TEXT ·Value(SB),4,$0-1\n" + body + "RET\n"
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(unused bool)", target.arch, target.triple, api)
						if observe {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown AES data escaped through a numerical/control use", target, name, raw, api, err)
							}
						} else if err != nil || ir == "" {
							t.Fatal("dead register AES invented an obligation unrelated to its observable source effects", target, name, raw, api, err)
						}
					}
				}
			}
		}
	}
}
