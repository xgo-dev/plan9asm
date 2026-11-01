package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestGoAMD64FrameMachineStackAdjustment(t *testing.T) {
	for _, frame := range []int64{64, 120, 128, 136, 256} {
		t.Run(fmt.Sprint(frame), func(t *testing.T) {
			assembly := fmt.Sprintf("TEXT value(SB),4,$%d-0\nNOP\nRET\n", frame)
			listing := x86InsertExtractGoListing(t, "amd64", assembly)
			fn := goAMD64FrameFunction{positions: make(map[int]string)}
			for _, line := range strings.Split(string(listing), "\n") {
				fn.code = append(fn.code, x86InsertExtractListedBytes(line)...)
			}
			var starts []int
			for pc := 0; pc < len(fn.code); {
				ins, err := x86asm.Decode(fn.code[pc:], 64)
				if err != nil || ins.Len <= 0 {
					t.Fatal("independent Go object cannot be decoded", err)
				}
				starts = append(starts, pc)
				// This unit test exercises machine shape only. Full capture
				// tests independently bind real listing/source positions.
				fn.positions[pc] = "machine-shape unit fixture"
				pc += ins.Len
			}
			if len(starts) != 6 {
				t.Fatalf("unexpected original Go prologue/epilogue: %x", fn.code)
			}
			if err := goAMD64FrameMachineShape(fn, frame); err != nil {
				t.Fatal("original Go stack adjustment", err)
			}
			for _, index := range []int{2, 3} {
				for _, mutation := range []string{"width", "register", "operation", "amount"} {
					t.Run(fmt.Sprintf("instruction%d/%s", index, mutation), func(t *testing.T) {
						changed := fn
						changed.code = append([]byte(nil), fn.code...)
						pc, end := starts[index], starts[index+1]
						switch mutation {
						case "width":
							changed.code[pc] = 0x40 // REX without W: ESP, not RSP.
						case "register":
							changed.code[pc+2] &^= 7 // Same operation on AX.
						case "operation":
							changed.code[pc+2] ^= 0x28 // Exchange ADD and SUB.
						case "amount":
							changed.code[end-1] ^= 1
						}
						if err := goAMD64FrameMachineShape(changed, frame); err == nil {
							t.Fatal("altered automatic frame adjustment accepted")
						}
					})
				}
			}
		})
	}
}
