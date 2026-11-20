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

func TestARM64NativeScratchShiftedZeroGoEncodingRows(t *testing.T) {
	// Go's obj7 cases 3 and 27 independently supply the complete shifted
	// arithmetic/logical and extended arithmetic source operand families.
	// Expected zero-register effects do not depend on a mnemonic alias or
	// on the translator's operand reader.
	type witness struct {
		name, instruction string
		flags, comparison bool
	}
	var witnesses []witness
	arithmetic := []struct {
		op                string
		flags, comparison bool
	}{
		{"ADD", false, false}, {"ADDS", true, false},
		{"SUB", false, false}, {"SUBS", true, false},
		{"CMP", true, true}, {"CMN", true, true},
	}
	appendRow := func(op, operand, name string, flags, comparison bool) {
		instruction := op + " " + operand + ",R1"
		if !comparison {
			instruction += ",R4"
		}
		witnesses = append(witnesses, witness{name, instruction, flags, comparison})
	}
	for _, suffix := range []string{"", "W"} {
		width := 64
		if suffix == "W" {
			width = 32
		}
		for _, operation := range arithmetic {
			op := operation.op + suffix
			for _, extension := range []string{"UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"} {
				for shift := 0; shift <= 4; shift++ {
					operand := fmt.Sprintf("ZR.%s<<%d", extension, shift)
					appendRow(op, operand, fmt.Sprintf("%s_%s_%d", op, extension, shift),
						operation.flags, operation.comparison)
				}
			}
			for _, shift := range []string{"<<", ">>", "->"} {
				for _, amount := range []int{0, 1, width - 1} {
					operand := fmt.Sprintf("ZR%s%d", shift, amount)
					appendRow(op, operand, fmt.Sprintf("%s_shift_%d", op, len(witnesses)),
						operation.flags, operation.comparison)
				}
			}
		}
		for _, operation := range []struct {
			op                string
			flags, comparison bool
		}{
			{"AND", false, false}, {"BIC", false, false},
			{"ORR", false, false}, {"ORN", false, false},
			{"EOR", false, false}, {"EON", false, false},
			{"ANDS", true, false}, {"BICS", true, false}, {"TST", true, true},
		} {
			op := operation.op + suffix
			for _, shift := range []string{"<<", ">>", "->", "@>"} {
				for _, amount := range []int{0, 1, width - 1} {
					operand := fmt.Sprintf("ZR%s%d", shift, amount)
					appendRow(op, operand, fmt.Sprintf("%s_shift_%d", op, len(witnesses)),
						operation.flags, operation.comparison)
				}
			}
		}
	}
	var assembly strings.Builder
	for _, row := range witnesses {
		fmt.Fprintf(&assembly, "TEXT %s(SB),516,$0-0\n%s\nRET\n", row.name, row.instruction)
	}
	directory := t.TempDir()
	input, object := filepath.Join(directory, "shifted_zero_arm64.s"), filepath.Join(directory, "original.o")
	if err := os.WriteFile(input, []byte(assembly.String()), 0600); err != nil {
		t.Fatal(err)
	}
	listing, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-o", object, input)
	if err != nil {
		t.Fatalf("original Go shifted/extended operand families: %v\n%s", err, listing)
	}
	disassembly, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "objdump", object)
	if err != nil {
		t.Fatalf("original Go shifted/extended object: %v\n%s", err, disassembly)
	}
	bodies, err := arm64ScratchObjectBodies(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range witnesses {
		t.Run(row.name, func(t *testing.T) {
			body, present := bodies[row.name]
			if !present || len(body.code) < 2 || body.code[1] != 0xd65f03c0 || len(body.relocs) != 0 {
				t.Fatal("original Go instruction/return identity missing")
			}
			var code [4]byte
			binary.LittleEndian.PutUint32(code[:], body.code[0])
			instruction, err := arm64asm.Decode(code[:])
			if err != nil {
				t.Fatal(err)
			}
			want := arm64ScratchInputEffect{reads: 1 << 1}
			if !row.comparison {
				want.writes = 1 << 4
			}
			if row.flags {
				want.writes |= 15 << 31
			}
			got, valid := arm64ScratchNativeInputEffect(instruction, false)
			if !valid || got != want {
				t.Fatalf("Go encoding %08x %v: shifted zero effect=%+v registered=%v, want %+v",
					body.code[0], instruction, got, valid, want)
			}
			scratch, valid := arm64ScratchNativeEffect(instruction)
			if !valid || scratch != (arm64ScratchEffect{}) {
				t.Fatalf("shifted zero invented an incoming R27 effect: %+v valid=%v", scratch, valid)
			}
			gp, known := arm64RawPoolGPWrites(body.code[0])
			if !known || gp != uint32(want.writes&0x7fffffff) ||
				arm64RawPoolInstructionPreservesNZCV(instruction) != !row.flags {
				t.Fatal("original scalar operand row disagrees with GP/NZCV consumers")
			}
			// Rm is field 20:16 in both Go encoding classes. Independently
			// vary real GP, R27, LR and zero roles while retaining the actual
			// source's operation/width/shift. This metadata control is not a
			// new original-object or runtime certificate for the changed word.
			for _, register := range []uint32{0, 1, 27, 30, 31} {
				word := body.code[0]&^(31<<16) | register<<16
				binary.LittleEndian.PutUint32(code[:], word)
				changed, err := arm64asm.Decode(code[:])
				if err != nil {
					t.Fatal(err)
				}
				got, valid := arm64ScratchNativeInputEffect(changed, false)
				if register == 30 {
					if valid {
						t.Fatal("shifted native LR acquired an input contract")
					}
					continue
				}
				control := want
				if register != 31 {
					control.reads |= 1 << register
				}
				if !valid || got != control {
					t.Fatalf("shifted register %d effect=%+v valid=%v, want %+v", register, got, valid, control)
				}
				scratch, valid := arm64ScratchNativeEffect(changed)
				if !valid || scratch != (arm64ScratchEffect{reads: register == 27}) {
					t.Fatalf("shifted register %d R27 role differs: %+v valid=%v", register, scratch, valid)
				}
			}
		})
	}
}

func TestARM64NativeScratchExtendedZeroSourceClosure(t *testing.T) {
	for _, extension := range []string{"UXTB", "UXTH", "UXTW", "UXTX", "SXTB", "SXTH", "SXTW", "SXTX"} {
		t.Run(extension, func(t *testing.T) {
			operation := "ADD ZR." + extension + "<<1,R1,R1"
			assembly := strings.Replace(arm64ScratchSelectedSource, "ADD $3,R1", operation, 1)
			_, pkg, _, _, source := arm64ScratchActualBoundSourceWithAssembly(
				t, "linux", "aarch64-unknown-linux-gnu", assembly)
			// Closure is an actual original input/R27 observation, not a
			// pointee bound, numerical result or external-runtime certificate.
			if _, closed := source.closed[pkg.Path+".Value"]; !closed {
				t.Fatal("Go-accepted zero extension failed actual native input closure")
			}
		})
	}
}
