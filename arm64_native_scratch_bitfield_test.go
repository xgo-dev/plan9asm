package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64NativeScratchBitfieldGoEncodingRows(t *testing.T) {
	// Independent source witnesses follow Go's obj7 cases 42, 43 and 45,
	// plus the immediate shifts encoded as bitfields by case 8. The expected
	// effects come from each source operation, not the translator decoder.
	type witness struct {
		name, instruction string
		merge             bool
	}
	var witnesses []witness
	for _, op := range []string{"SBFM", "BFM", "UBFM"} {
		for _, suffix := range []string{"", "W"} {
			witnesses = append(witnesses, witness{
				op + suffix, op + suffix + " $1,R1,$17,R4", op == "BFM",
			})
		}
	}
	for _, op := range []string{"BFI", "BFXIL", "SBFIZ", "SBFX", "UBFIZ", "UBFX"} {
		for _, suffix := range []string{"", "W"} {
			witnesses = append(witnesses, witness{
				op + suffix, op + suffix + " $3,R1,$7,R4", op == "BFI" || op == "BFXIL",
			})
		}
	}
	for _, op := range []string{
		"SXTB", "SXTBW", "SXTH", "SXTHW", "SXTW",
		"UXTB", "UXTBW", "UXTH", "UXTHW", "UXTW",
		"MOVB", "MOVH", "MOVW", "MOVBU", "MOVHU", "MOVWU",
	} {
		witnesses = append(witnesses, witness{op, op + " R1,R4", false})
	}
	for _, op := range []string{"ASR", "LSL", "LSR"} {
		for _, suffix := range []string{"", "W"} {
			witnesses = append(witnesses, witness{op + suffix, op + suffix + " $3,R1,R4", false})
		}
	}
	var assembly strings.Builder
	for _, witness := range witnesses {
		fmt.Fprintf(&assembly, "TEXT %s(SB),516,$0-0\n%s\nRET\n", witness.name, witness.instruction)
	}
	directory := t.TempDir()
	input, object := filepath.Join(directory, "bitfields_arm64.s"), filepath.Join(directory, "original.o")
	if err := os.WriteFile(input, []byte(assembly.String()), 0600); err != nil {
		t.Fatal(err)
	}
	listing, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", object, input)
	if err != nil {
		t.Fatalf("original Go bitfield family: %v\n%s", err, listing)
	}
	disassembly, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "objdump", object)
	if err != nil {
		t.Fatalf("actual original Go bitfield object: %v\n%s", err, disassembly)
	}
	bodies, err := arm64ScratchObjectBodies(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	for _, witness := range witnesses {
		t.Run(witness.name, func(t *testing.T) {
			body, present := bodies[witness.name]
			if !present || len(body.code) < 2 || body.code[1] != 0xd65f03c0 || len(body.relocs) != 0 {
				t.Fatal("original Go bitfield instruction/return identity missing")
			}
			var bytes [4]byte
			binary.LittleEndian.PutUint32(bytes[:], body.code[0])
			instruction, err := arm64asm.Decode(bytes[:])
			if err != nil {
				t.Fatal(err)
			}
			reads := uint64(1 << 1)
			if witness.merge {
				reads |= 1 << 4
			}
			want := arm64ScratchInputEffect{reads: reads, writes: 1 << 4}
			got, valid := arm64ScratchNativeInputEffect(instruction, false)
			if !valid || got != want {
				t.Fatalf("Go encoding %08x %v: native bitfield effect=%+v registered=%v, want %+v",
					body.code[0], instruction, got, valid, want)
			}
		})
	}
}

func TestARM64NativeScratchBitfieldCompleteEffectDomain(t *testing.T) {
	// The encoding constructor is the independent fixture used by the original
	// raw-bitfield tests. This exhaustive metadata test is not a Go object or
	// runtime certificate for each synthetic word; actual Go rows are above.
	for opc := uint32(0); opc < 3; opc++ {
		for _, width := range []int{32, 64} {
			for immr := 0; immr < width; immr++ {
				for imms := 0; imms < width; imms++ {
					for _, registers := range [][2]int{
						{1, 4}, {4, 4}, {27, 1}, {1, 27}, {31, 4},
						{1, 31}, {31, 31}, {30, 4}, {1, 30},
					} {
						word := encodeARM64RawBitfield(opc, width, immr, imms, registers[0], registers[1])
						var bytes [4]byte
						binary.LittleEndian.PutUint32(bytes[:], word)
						instruction, err := arm64asm.Decode(bytes[:])
						if err != nil {
							t.Fatalf("valid physical bitfield %08x: %v", word, err)
						}
						var reads, writes uint64
						if registers[0] != 31 {
							reads = 1 << uint(registers[0])
						}
						if registers[1] != 31 {
							writes = 1 << uint(registers[1])
							if opc == 1 {
								reads |= writes
							}
						}
						got, valid := arm64ScratchNativeInputEffect(instruction, false)
						if (reads|writes)&(1<<30) != 0 {
							if valid {
								t.Fatalf("native LR numerical effect admitted: %08x", word)
							}
						} else if !valid || got != (arm64ScratchInputEffect{reads: reads, writes: writes}) {
							t.Fatalf("bitfield %08x input effect=%+v valid=%v", word, got, valid)
						}
						r27, valid := arm64ScratchNativeEffect(instruction)
						wantR27 := arm64ScratchEffect{reads: reads&(1<<27) != 0, defines: writes&(1<<27) != 0}
						if !valid || r27 != wantR27 {
							t.Fatalf("bitfield %08x R27 effect=%+v valid=%v", word, r27, valid)
						}
						gp, known := arm64RawPoolGPWrites(word)
						if !known || gp != uint32(writes) || !arm64RawPoolInstructionPreservesNZCV(instruction) {
							t.Fatalf("bitfield %08x disagrees with GP/NZCV consumers", word)
						}
					}
				}
			}
		}
	}
}
