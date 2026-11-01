package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestARM64DecoderExtendedShiftBoundariesMatchGo(t *testing.T) {
	// x/arch prints reserved machine encodings too. Go rejects extended
	// register shifts above four; a decoder spelling is not a Go format.
	// Check every ADD/SUB W/X and flags alias and every extension, including
	// all five legal shifts, against the actual invoked Go assembler.
	for _, op := range []string{"ADD", "ADDS", "ADDW", "ADDSW", "SUB", "SUBS", "SUBW", "SUBSW"} {
		for _, extension := range []string{"UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"} {
			for shift := 0; shift <= 7; shift++ {
				instruction := fmt.Sprintf("%s R4.%s<<%d,R5,R9", op, extension, shift)
				t.Run(instruction, func(t *testing.T) {
					source := "TEXT decoder_shift(SB),516,$0-0\n" + instruction + "\nRET\n"
					dir := t.TempDir()
					path := filepath.Join(dir, "source.s")
					if err := os.WriteFile(path, []byte(source), 0600); err != nil {
						t.Fatal(err)
					}
					output, goErr := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-o", filepath.Join(dir, "source.o"), path)
					accepted := shift <= 4
					if (goErr == nil) != accepted {
						t.Fatalf("actual Go extended shift accepted=%t: %v\n%s", accepted, goErr, output)
					}
					file, err := Parse(ArchARM64, source)
					if err != nil {
						t.Fatal(err)
					}
					probeErr := ProbeInstruction(ArchARM64, "arm64", file.Funcs[0].Instrs[1])
					if (probeErr == nil) != accepted {
						t.Fatalf("probe differs from actual Go extended shift accepted=%t: %v", accepted, probeErr)
					}
				})
			}
		}
	}
}
