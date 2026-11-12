package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86YmlYrlYrlOrderedInputBytesAndDistinctStatus(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			width, flags := 4, uint8(x86ByteFlagsAll)
			if arch == "amd64" && strings.HasSuffix(op, "Q") {
				width = 8
			}
			if strings.HasPrefix(op, "ANDN") {
				flags = x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagSF | x86ByteFlagZF
			}
			for _, destination := range []struct {
				reg   string
				index int
			}{{"CX", 1}, {"AX", 0}, {"BX", 3}} {
				ins := x86YMMReadSource(t, op+" AX,BX,"+destination.reg)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 3 || !effect.requiresResultProof {
					t.Fatal("complete source grammar lacks its ordered numerical effect", arch, op, known, err)
				}
				for ordinal, operand := range effect.operands {
					if operand.index != ordinal || operand.width != int64(width) || operand.read != (ordinal < 2) || operand.write != (ordinal == 2) || !reflect.DeepEqual(operand.operand, ins.Args[ordinal]) {
						t.Fatal("source read/overwrite or mode32 WIG width differs", arch, op, operand)
					}
				}
				for missing := -1; missing < width*2; missing++ {
					t.Run(fmt.Sprintf("%s/%s/%s/missing=%d", arch, op, destination.reg, missing), func(t *testing.T) {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.gp[3] = 0xff, 0xff
						if missing >= 0 {
							index := 0
							if missing >= width {
								index = 3
							}
							state.gp[index] &^= 1 << uint(missing%width)
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						if accepted != (missing < 0) || !accepted && !reflect.DeepEqual(before, state) {
							t.Fatal("aliased write hid missing input or changed rejected state", accepted)
						}
						if accepted {
							before.gp[destination.index], before.flags = 0xff, flags
							if !reflect.DeepEqual(before, state) {
								t.Fatal("ternary GP effect changed unrelated state or undefined status knowledge")
							}
						}
					})
				}
			}
		}
	}
}
