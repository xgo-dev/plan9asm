package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestGoAMD64FrameReturnBeforeFinalLocalBranch(t *testing.T) {
	for _, frame := range []int64{64, 128, 160} {
		t.Run(fmt.Sprint(frame), func(t *testing.T) {
			assembly := fmt.Sprintf("TEXT value(SB),4,$%d-0\nMOVQ $1,AX\nloop:\nTESTQ AX,AX\nJNE work\nRET\nwork:\nXORQ AX,AX\nJMP loop\n", frame)
			listing := x86InsertExtractGoListing(t, "amd64", assembly)
			fn := goAMD64FrameFunction{positions: make(map[int]string)}
			for _, line := range strings.Split(string(listing), "\n") {
				fn.code = append(fn.code, x86InsertExtractListedBytes(line)...)
			}
			last := 0
			var starts []int
			returnIndex := -1
			for pc := 0; pc < len(fn.code); {
				ins, err := x86asm.Decode(fn.code[pc:], 64)
				if err != nil || ins.Len <= 0 {
					t.Fatal("original Go machine fixture", err)
				}
				// Machine-only unit fixture; the public API matrix separately
				// captures actual original source and object positions.
				fn.positions[pc] = "machine-shape unit fixture"
				if ins.Op == x86asm.RET {
					returnIndex = len(starts)
				}
				starts = append(starts, pc)
				last = pc
				pc += ins.Len
			}
			if len(fn.code)-last != 2 || fn.code[last] != 0xeb {
				t.Fatalf("expected original short local JMP, got %x", fn.code[last:])
			}
			if err := goAMD64FrameMachineShape(fn, frame); err != nil {
				t.Error("conventional RET may precede a closed local backedge", err)
			}
			if returnIndex < 2 {
				t.Fatal("original fixture has no complete return epilogue")
			}
			for _, target := range []int{0, 1, starts[1], starts[2], starts[returnIndex-1], starts[returnIndex],
				last + 1, len(fn.code), len(fn.code) + 1, -1} {
				changed := fn
				changed.code = append([]byte(nil), fn.code...)
				changed.code[last+1] = byte(target - len(fn.code))
				if err := goAMD64FrameMachineShape(changed, frame); err == nil {
					t.Errorf("terminal branch to prologue/nonboundary/outside target %d accepted", target)
				}
			}
			changed := fn
			changed.code = append([]byte(nil), fn.code...)
			changed.code[last] = 0x75 // JNE has an unclosed fallthrough after the function.
			if err := goAMD64FrameMachineShape(changed, frame); err == nil {
				t.Error("terminal conditional branch accepted an escaping fallthrough")
			}
			changed = fn
			changed.code = append([]byte(nil), fn.code...)
			changed.code[last+1] = byte(starts[returnIndex-2] - len(fn.code))
			if err := goAMD64FrameMachineShape(changed, frame); err != nil {
				t.Error("branch to the complete automatic epilogue entry rejected", err)
			}
			for _, mutation := range []string{"no RET", "wrong POP", "wrong adjustment"} {
				changed := fn
				changed.code = append([]byte(nil), fn.code...)
				switch mutation {
				case "no RET":
					changed.code[starts[returnIndex]] = 0x90
				case "wrong POP":
					changed.code[starts[returnIndex-1]] = 0x5b
				case "wrong adjustment":
					changed.code[starts[returnIndex-1]-1] ^= 1
				}
				if err := goAMD64FrameMachineShape(changed, frame); err == nil {
					t.Errorf("terminal local JMP accepted %s", mutation)
				}
			}
		})
	}
}
