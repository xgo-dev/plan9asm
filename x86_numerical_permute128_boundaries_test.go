package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// These are orthogonal physical-PC witnesses, not another selector matrix.
// The independent family root already owns both complete Go rows and every
// imm8. Neither measuring a native boundary nor seeing RIP supplies a read.
func TestX86NumericalPermute128CompletePhysicalBoundaries(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required for independent mode32 VPERM2 boundaries")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var rows []string
			for _, member := range x86Permute128Members {
				for _, operands := range []string{
					"$0,Y0,Y1,Y2", "$255,Y7,Y7,Y7", "$136,(AX),Y1,Y2",
					"$33,127(AX)(CX*4),Y1,Y2", "$33,-129(AX)(CX*8),Y1,Y2",
					"$255,2147483647(BX),Y1,Y2", "$0,-2147483648(BX),Y1,Y2",
				} {
					rows = append(rows, member.op+" "+operands)
				}
				if arch == "amd64" {
					rows = append(rows, member.op+" $255,Y13,Y14,Y15",
						member.op+" $136,-129(R11)(R9*4),Y13,Y12")
				}
			}
			want := map[string]int{"386": 14, "amd64": 18}[arch]
			if len(rows) != want {
				t.Fatal("independent complete physical-axis denominator changed", len(rows), want)
			}
			// Go's named mode32 four-operand syntax is not a physical ISA
			// witness. Obtain exact named AMD64 PCs, then independently check
			// all low-bank mode32 bytes with LLVM and the real Go BYTE object.
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64",
				strings.Join(rows, "\n")+"\nCMPL AX,$1\nRET")
			if len(pcs) != len(rows)+2 {
				t.Fatal("actual Go expanded or omitted a boundary witness", len(pcs), len(rows))
			}
			mode := 64
			if arch == "386" {
				mode = 32
				for index, row := range rows {
					observed := x86PackedShiftRawSingleMC(t, mc, "i386-unknown-linux-gnu", code[pcs[index]:pcs[index+1]])
					mnemonic := strings.ToLower(strings.Fields(row)[0])
					if strings.Contains(observed, "warning") || strings.Contains(observed, "invalid") ||
						strings.Count(observed, mnemonic) != 1 {
						t.Fatal("independent LLVM rejected a complete low-bank mode32 witness", row, observed)
					}
				}
				actual, _ := x86NumericalBoundaryGoBytes(t, arch, x86RawDisplacementDirectives(code))
				if !bytes.Equal(actual, code) {
					t.Fatal("actual mode32 Go object changed the independently checked physical bytes")
				}
			}
			x86CheckNumericalFloatingBoundaries(t, code, pcs, mode, len(rows))
		})
	}
	for _, member := range x86Permute128Members {
		for _, control := range []string{"W1", "L0", "pp", "missing-imm", "mode32-high-vvvv"} {
			t.Run(member.op+"/"+control, func(t *testing.T) {
				code := encodeX86RawVPERM2X128(member.opcode, 0x21, 0, 1, 2)
				mode := 64
				switch control {
				case "W1":
					code[2] |= 0x80
				case "L0":
					code[2] &^= 4
				case "pp":
					code[2] &^= 3
				case "missing-imm":
					code = code[:len(code)-1]
				case "mode32-high-vvvv":
					mode = 32
					code = encodeX86RawVPERM2X128(member.opcode, 0x21, 0, 8, 2)
					if !x86NumericalVectorPrefix(code, mode) {
						t.Fatal("mode32 negative became a legacy LES/LDS sequence")
					}
				}
				for _, prefix := range [][]byte{nil, {0x90, 0xc3}, {0xeb, 0x7f}} {
					whole := append(append([]byte(nil), prefix...), code...)
					boundaries, scalar, err := x86NumericalNativeBoundaries(whole, mode)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatal("malformed or unreachable VPERM2 retained a partial observation", control, err)
					}
				}
			})
		}
	}
}

func TestX86NumericalPermute128RIPBoundaryIsNotSourceNUM(t *testing.T) {
	for _, member := range x86Permute128Members {
		for _, offset := range []int{-17, 17} {
			t.Run(fmt.Sprintf("%s/RIP%+d", member.op, offset), func(t *testing.T) {
				row := fmt.Sprintf("%s $33,table%+d(SB),Y1,Y2", member.op, offset)
				code, pcs, listing := x86NumericalBoundaryGoBytesAndListing(t, "amd64", row+"\nRET")
				expected := []byte{0xc4, 0xe3, 0x75, member.opcode, 0x15, 0, 0, 0, 0, 0x21, 0xc3}
				// The trailing imm8 is after disp32: cmd/asm subtracts one
				// from the R_PCREL addend, relative to the relocation's end.
				if !bytes.Equal(code, expected) || !reflect.DeepEqual(pcs, []int64{0, 10}) {
					t.Fatalf("actual Go RIP bytes/PCs/relocation prerequisite changed: %x %v\n%s", code, pcs, listing)
				}
				x86NumericalRequirePCRelListing(t, listing, 5, offset-1)
				if _, _, known, err := decodedX86Permute128Instruction(code, 64); !known || err == nil ||
					!strings.Contains(err.Error(), "RIP-relative") {
					t.Fatal("default raw decoder acquired a source RIP/literal role", known, err)
				}
				boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
				if err != nil || len(boundaries) != 2 || boundaries[0].PC != 0 || boundaries[0].Length != 10 ||
					boundaries[1].PC != 10 || boundaries[1].Length != 1 || len(scalar) != 1 || scalar[10].Op != x86asm.RET {
					t.Fatal("physical RIP must supply only the complete native boundary", boundaries, scalar, err)
				}
				for cut := 0; cut < 10; cut++ {
					boundaries, scalar, err := x86NumericalNativeBoundaries(code[:cut], 64)
					if !errors.Is(err, ErrProbeNeedsContext) || boundaries != nil || scalar != nil {
						t.Fatal("truncated RIP/imm8 acquired a partial observation", cut, err)
					}
				}
				reads, err := numericalNativeReads(code, 64)
				if err != nil || len(reads) != 0 {
					t.Fatal("boundary-only VPERM2 invented an SDK symbolic-read/NUM owner", reads, err)
				}
			})
		}
		t.Run(member.op+"/no-DATA-or-vector-permission", func(t *testing.T) {
			const table = "GLOBL table(SB),8,$64\n"
			source := "TEXT ·Value(SB),4,$0-0\n" + member.op + " $33,table+17(SB),Y1,Y2\nRET\n" + table
			for offset := 0; offset < 64; offset += 8 {
				source += fmt.Sprintf("DATA table+%d(SB)/8,$0\n", offset)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("complete Go DATA/source observation created missing vector or literal permissions", api, err)
				}
			}
		})
	}
}
