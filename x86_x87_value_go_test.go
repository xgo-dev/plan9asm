package plan9asm

import (
	"bytes"
	"fmt"
	"testing"
)

type x86X87GoByteCase struct {
	instruction string
	want        []byte
}

// This tool-backed owner is deliberately separate from the in-process value
// tests. It observes actual selected-Go bytes, not manufactured wrapper TEXT
// or a claim about the software x87 stack. In particular yfmvd's Yrf,Yf0 row
// precedes Yf0,Yrf, so F0,F0 is a load/push, not a store/no-push.
func TestX86X87FloatingMoveActualGoRowsAndPriority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var rows []x86X87GoByteCase
		for _, row := range []struct {
			instruction string
			first, last byte
		}{
			{"FMOVD 0(AX),F0", 0xdd, 0x00},
			{"FMOVD F0,0(AX)", 0xdd, 0x10},
			{"FMOVDP F0,0(AX)", 0xdd, 0x18},
			{"FMOVF 0(AX),F0", 0xd9, 0x00},
			{"FMOVF F0,0(AX)", 0xd9, 0x10},
			{"FMOVFP F0,0(AX)", 0xd9, 0x18},
		} {
			rows = append(rows, x86X87GoByteCase{row.instruction, []byte{row.first, row.last, 0xc3}})
		}
		for lane := 0; lane < 8; lane++ {
			for _, row := range []struct {
				instruction string
				first, last byte
			}{
				{fmt.Sprintf("FMOVD F%d,F0", lane), 0xd9, 0xc0 + byte(lane)},
				{fmt.Sprintf("FMOVDP F0,F%d", lane), 0xdd, 0xd8 + byte(lane)},
				{fmt.Sprintf("FXCHD F0,F%d", lane), 0xd9, 0xc8 + byte(lane)},
			} {
				rows = append(rows, x86X87GoByteCase{row.instruction, []byte{row.first, row.last, 0xc3}})
			}
			// F0,F0 has already selected the earlier load row above.
			if lane != 0 {
				rows = append(rows, x86X87GoByteCase{fmt.Sprintf("FMOVD F0,F%d", lane), []byte{0xdd, 0xd0 + byte(lane), 0xc3}})
				rows = append(rows, x86X87GoByteCase{fmt.Sprintf("FXCHD F%d,F0", lane), []byte{0xd9, 0xc8 + byte(lane), 0xc3}})
			}
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				source := "TEXT probe(SB),4,$0-0\n" + row.instruction + "\nRET\n"
				got := x86OrderingHintGoBytes(t, arch, source)
				if !bytes.Equal(got, row.want) {
					t.Fatalf("selected Go x87 row bytes=%x, independent expected=%x", got, row.want)
				}
			})
		}
	}
}
