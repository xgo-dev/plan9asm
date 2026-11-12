package plan9asm

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fixedLocalLogicalLiteralCase struct {
	opcode string
	mode   int // Independent oracle: AND, ANDNOT, OR, XOR.
	width  int
	vex    bool
}

func fixedLocalLogicalLiteralCases() []fixedLocalLogicalLiteralCase {
	var rows []fixedLocalLogicalLiteralCase
	for mode, names := range [][3]string{
		{"PAND", "ANDPS", "ANDPD"},
		{"PANDN", "ANDNPS", "ANDNPD"},
		{"POR", "ORPS", "ORPD"},
		{"PXOR", "XORPS", "XORPD"},
	} {
		for _, name := range names {
			rows = append(rows, fixedLocalLogicalLiteralCase{name, mode, 16, false})
			for _, width := range []int{16, 32} {
				rows = append(rows, fixedLocalLogicalLiteralCase{"V" + name, mode, width, true})
			}
		}
	}
	return rows
}

func fixedLocalLogicalLiteralSource(row fixedLocalLogicalLiteralCase, annihilate bool) string {
	mask := make([]byte, row.width)
	for index := range mask {
		switch row.mode {
		case 0, 1:
			if !annihilate && index >= 12 && index < 16 {
				mask[index] = 255
			}
		case 2:
			if annihilate || index < 12 || index >= 16 {
				mask[index] = 255
			}
		case 3:
			mask[index] = byte(index*13 + 7)
		}
	}
	var assembly strings.Builder
	for offset := 0; offset < row.width; offset += 8 {
		fmt.Fprintf(&assembly, "DATA mask<>+%d(SB)/8,$%#x\n", offset, binary.LittleEndian.Uint64(mask[offset:]))
	}
	fmt.Fprintf(&assembly, "GLOBL mask<>(SB),8,$%d\n", row.width)
	assembly.WriteString("TEXT ·Value(SB),4,$32-16\nMOVQ input+0(FP),DI\nMOVQ output+8(FP),SI\n")
	bank, move := "X", "MOVOU"
	if row.vex {
		move = "VMOVDQU"
		if row.width == 32 {
			bank = "Y"
		}
	}
	if row.mode == 3 {
		fmt.Fprintf(&assembly, "%s (DI),%s5\n", move, bank)
	} else if !annihilate {
		// The other physical vector bytes deliberately remain undefined in
		// the source proof. No full-register zero idiom precedes this insert.
		assembly.WriteString("PINSRD $3,(DI),X5\n")
	}
	destination := bank + "5"
	if row.vex {
		destination = bank + "6"
		fmt.Fprintf(&assembly, "%s mask<>(SB),%s5,%s\n", row.opcode, bank, destination)
	} else {
		fmt.Fprintf(&assembly, "%s mask<>(SB),%s\n", row.opcode, destination)
	}
	fmt.Fprintf(&assembly, "%s %s,0(SP)\n%s 0(SP),%s\n%s %s,(SI)\nRET\n",
		move, destination, move, destination, move, destination)
	return assembly.String()
}

// This is an independent byte oracle, not a call to a production operation.
func fixedLocalLogicalLiteralByte(mode int, first, second byte) byte {
	switch mode {
	case 0:
		return first & second
	case 1:
		return first & ^second
	case 2:
		return first | second
	case 3:
		return first ^ second
	default:
		panic("unknown test operation")
	}
}

func TestX86PackedLogicalConstantByteDependencies(t *testing.T) {
	for mode, operation := range []amd64PackedLogicalMode{
		amd64PackedLogicalAnd, amd64PackedLogicalAndNot, amd64PackedLogicalOr, amd64PackedLogicalXor,
	} {
		for first := 0; first < 256; first++ {
			actual := x86PackedLogicalSecondBits(operation, byte(first))
			for second := 0; second < 256; second++ {
				base := fixedLocalLogicalLiteralByte(mode, byte(first), byte(second))
				for bit := 0; bit < 8; bit++ {
					changed := fixedLocalLogicalLiteralByte(mode, byte(first), byte(second)^(1<<uint(bit)))
					if (base != changed) != (actual&(1<<uint(bit)) != 0) {
						t.Fatalf("mode=%d first=%x second=%x bit=%d dependency=%x", mode, first, second, bit, actual)
					}
				}
			}
		}
	}
}

func TestGoAMD64FixedLocalLogicalLiteralPlanProjection(t *testing.T) {
	for _, row := range fixedLocalLogicalLiteralCases() {
		for _, annihilate := range []bool{false, true} {
			if annihilate && row.mode == 3 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d/constant=%t", row.opcode, row.width, annihilate), func(t *testing.T) {
				assembly := fixedLocalLogicalLiteralSource(row, annihilate)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				// Internal dependency projection only. Public owner and source
				// validity are independently exercised by actual-Go captures.
				literal := x86ShiftLiteral{width: uint8(row.width)}
				for _, datum := range file.Data {
					payload, err := dataStmtPayload(datum)
					if err != nil {
						t.Fatal(err)
					}
					copy(literal.bytes[datum.Off:], payload)
				}
				binding := &x86FixedLocalBinding{literalData: map[string]x86FixedLocalData{
					"mask<>": {size: int64(row.width), alignment: 16,
						literals: map[int64]x86ShiftLiteral{0: literal}},
				}}
				var logical Instr
				for _, ins := range file.Funcs[0].Instrs {
					if string(ins.Op) == row.opcode {
						logical = ins
					}
				}
				effect, known, err := fixedLocalVectorByteEffect(logical)
				if !known || err != nil {
					t.Fatal("existing complete typed form rejected", known, err)
				}
				original := effect
				original.operands = append([]x86TypedByteOperand(nil), effect.operands...)
				projected := fixedLocalLogicalLiteralEffect(logical, effect, binding)
				if !reflect.DeepEqual(effect, original) {
					t.Fatal("projection mutated its caller's shared operand slice")
				}
				want := uint64(0xf000)
				if annihilate {
					want = 0
				}
				if row.mode == 3 {
					want = x86CallerVectorByteMask(int64(row.width))
				}
				if len(projected.operands) != len(effect.operands) ||
					!reflect.DeepEqual(projected.operands[0], original.operands[0]) || !projected.operands[0].read {
					t.Fatal("constant dependency removed or changed the complete memory read")
				}
				register := projected.operands[1]
				required := register.requiredBytes
				if register.read && required == 0 {
					required = x86CallerVectorByteMask(register.width)
				}
				if required != want || register.read != (want != 0) ||
					register.write != original.operands[1].write || projected.vector != original.vector ||
					projected.flagsRead != original.flagsRead || projected.flagsDefined != original.flagsDefined ||
					projected.flagsKilled != original.flagsKilled {
					t.Fatal("projection changed required bytes, aliases or FLAGS", required, want, projected)
				}
				state := x86FixedLocalState{flags: x86ByteFlagsAll, vectors: map[Reg]uint64{
					"Z5": want | 1<<40, "Z6": 1 << 50,
				}}
				proof := &x86FixedLocalProof{binding: binding, frame: 32}
				if err := fixedLocalTypedByteStep(&logical, &state, FuncSig{}, proof, 0, projected); err != nil {
					t.Fatal("exact required input bytes failed the unchanged typed evaluator", err)
				}
				if state.flags != x86ByteFlagsAll {
					t.Fatal("logical operation changed FLAGS")
				}
				if row.vex {
					if state.vectors["Z6"] != ^uint64(0) || state.vectors["Z5"] != want|1<<40 {
						t.Fatal("VEX output failed to zero upper aliases or changed the source")
					}
				} else if state.vectors["Z5"] != 0xffff|1<<40 || state.vectors["Z6"] != 1<<50 {
					t.Fatal("legacy output changed upper aliases or unrelated registers")
				}
				for _, invalid := range []*x86FixedLocalBinding{
					nil, {}, {literalData: map[string]x86FixedLocalData{
						"mask<>": {size: int64(row.width), alignment: 16},
					}},
				} {
					if got := fixedLocalLogicalLiteralEffect(logical, effect, invalid); !reflect.DeepEqual(got, original) {
						t.Fatal("missing actual literal tuple acquired a constant dependency")
					}
				}
			})
		}
	}
}
