package plan9asm

import (
	"strconv"
	"strings"
	"testing"
)

func TestGoAMD64FrameADXMachineBoundaries(t *testing.T) {
	for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
		for _, source := range []string{"AX", "8(SP)", "128(BX)(CX*4)"} {
			t.Run(op+"/"+source, func(t *testing.T) {
				assembly := "TEXT value(SB),4,$64-0\n" + op + " " + source + ",DX\nRET\n"
				listing := x86InsertExtractGoListing(t, "amd64", assembly)
				fn := goAMD64FrameFunction{positions: make(map[int]string)}
				adxPC := -1
				for _, line := range strings.Split(string(listing), "\n") {
					fn.code = append(fn.code, x86InsertExtractListedBytes(line)...)
					row := goAMD64FrameRow.FindStringSubmatch(line)
					if row == nil || strings.HasPrefix(row[3], "TEXT") || strings.HasPrefix(row[3], "PCDATA") {
						continue
					}
					pc, err := strconv.ParseInt(row[1], 16, 64)
					if err != nil {
						t.Fatal(err)
					}
					fn.positions[int(pc)] = row[3]
					if strings.HasPrefix(row[3], op) {
						adxPC = int(pc)
					}
				}
				if adxPC < 0 {
					t.Fatal("original Go listing lost ADX")
				}
				if err := goAMD64FrameMachineShape(fn, 64); err != nil {
					t.Error("ordinary ADX must retain its original instruction boundary", err)
				}
				for _, mutation := range []string{"missing position", "interior position", "bad prefix", "truncated", "unbound CALL"} {
					t.Run(mutation, func(t *testing.T) {
						changed := fn
						changed.code = append([]byte(nil), fn.code...)
						changed.positions = make(map[int]string, len(fn.positions))
						for pc, position := range fn.positions {
							changed.positions[pc] = position
						}
						switch mutation {
						case "missing position":
							delete(changed.positions, adxPC)
						case "interior position":
							changed.positions[adxPC+1] = "not an instruction boundary"
						case "bad prefix":
							changed.code[adxPC] = 0xf2
						case "truncated":
							changed.code = changed.code[:adxPC+3]
						case "unbound CALL":
							copy(changed.code[adxPC:], []byte{0xe8, 0, 0, 0, 0})
						}
						if err := goAMD64FrameMachineShape(changed, 64); err == nil {
							t.Fatal("ADX boundary observation granted invalid machine shape")
						}
					})
				}
			})
		}
	}
}
