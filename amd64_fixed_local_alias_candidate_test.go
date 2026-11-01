package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalPrivateAddressRoles(t *testing.T) {
	for _, row := range []struct {
		name, body string
		want       bool
	}{
		{"private base", "LEAQ 8(SP),SI\nMOVQ AX,(SI)\nMOVQ (SI),AX", true},
		{"private alias", "MOVQ SP,SI\nLEAQ 8(SI),SI\nMOVQ AX,(SI)\nMOVQ (SI),AX", true},
		{"constant index", "MOVQ $2,CX\nLEAQ (SP)(CX*8),SI\nMOVQ AX,(SI)\nMOVQ (SI),AX", true},
		{"logical displacement", "LEAQ tmp-8(SP),SI\nMOVQ AX,(SI)\nMOVQ (SI),AX", true},
		{"uninitialized memory", "LEAQ 8(SP),SI\nMOVQ (SI),AX", false},
		{"narrow pointer", "LEAL 8(SP),SI\nMOVQ AX,(SI)", false},
		{"stack mutation", "LEAQ 8(SP),SP", false},
		{"unknown index", "LEAQ (SP)(CX*8),SI\nMOVQ AX,(SI)", false},
		{"pointer index", "MOVQ SP,CX\nLEAQ (SP)(CX*1),SI\nMOVQ AX,(SI)", false},
		{"index overflow", "MOVQ $0x7fffffffffffffff,CX\nLEAQ (SP)(CX*8),SI", false},
		{"outside frame", "LEAQ 4096(SP),SI\nMOVQ AX,(SI)", false},
		{"before frame", "LEAQ -8(SP),SI\nMOVQ AX,(SI)", false},
		{"pointer is not NUM", "LEAQ 8(SP),AX\nADDQ AX,0(SP)", false},
		{"unknown base", "LEAQ 8(SI),SI\nMOVQ AX,(SI)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalGPFixture(t, row.body)
			_, err := proveX86FixedLocal(fn, sig)
			if row.want && err != nil || !row.want && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private address role = %v: %v", row.want, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPrivateAddressWidthAndFrame(t *testing.T) {
	fn, _, _ := fixedLocalGPFixture(t, "LEAQ 8(SP),SI")
	var address Instr
	for _, ins := range fn.Instrs {
		if ins.Op == "LEAQ" {
			address = ins
		}
	}
	for _, bits := range []int{0, 16, 32} {
		for _, proof := range []*x86FixedLocalProof{nil, {frame: 64}} {
			state := x86FixedLocalState{pointers: map[Reg]int64{SP: 0}, known: make(map[Reg]uint8)}
			ins := address
			ins.x86AddressBits = bits
			known, err := fixedLocalPrivateAddressStep(ins, &state, proof)
			want := bits == 0 && proof != nil
			if !known || want && err != nil || !want && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("address bits %d, frame %v: known=%v error=%v", bits, proof != nil, known, err)
			}
		}
	}
}

func TestGoAMD64FixedLocalAliasedFrameCandidates(t *testing.T) {
	var originals strings.Builder
	type example struct{ name, source string }
	var examples []example
	for _, register := range []Reg{AX, BX, CX, DX, SI, DI, BP, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		for _, address := range []string{"MOVQ SP,%s", "LEAQ 16(SP),%s"} {
			for _, access := range []string{"MOVQ 8(%s),AX", "MOVOU X0,8(%s)"} {
				name := fmt.Sprintf("Value%d", len(examples))
				source := fmt.Sprintf("TEXT ·%s(SB),4,$160-0\n", name) +
					fmt.Sprintf(address, register) + "\n" + fmt.Sprintf(access, register) + "\nRET\n"
				originals.WriteString(source)
				examples = append(examples, example{name, source})
			}
		}
	}
	requireX86GoAssemblerResult(t, "amd64", originals.String(), true)
	for _, row := range examples {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, row.source)
			if err != nil {
				t.Fatal(err)
			}
			if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Fatal("physical frame address through a GP register bypassed source observation")
			}
			if GoAMD64FixedLocalFrameBindingNeeded(file, "386") {
				t.Fatal("amd64 query selected another source mode")
			}
		})
	}
}

func TestGoAMD64FixedLocalAliasedCandidateSourceRoles(t *testing.T) {
	for _, row := range []struct {
		name, body string
		want       bool
	}{
		{"copy chain", "MOVQ SP,R14\nMOVQ R14,R15\nMOVQ 8(R15),AX", true},
		{"inverse register chain", "MOVQ SP,R15\nMOVQ R15,R14\nMOVQ R14,AX\nMOVQ 8(AX),BX", true},
		{"MOVD source alias", "MOVD SP,R14\nMOVQ 8(R14),AX", true},
		{"MOVDQ2Q source alias", "MOVDQ2Q SP,R14\nMOVQ 8(R14),AX", true},
		{"overwritten possible alias", "MOVQ SP,R14\nMOVQ SI,R14\nMOVQ 8(R14),AX", true},
		{"address chain", "MOVQ SP,R14\nLEAQ 16(R14),R15\nMOVQ 8(R15),AX", true},
		{"CFG order", "JMP define\nuse:\nMOVQ 8(R15),AX\nRET\ndefine:\nMOVQ SP,R14\nMOVQ R14,R15\nJMP use", true},
		{"index", "MOVQ SP,R14\nMOVQ (AX)(R14*1),BX", true},
		{"unrelated base", "LEAQ 16(SP),R14\nMOVQ 8(R15),AX", false},
		{"no memory", "LEAQ 16(SP),R14", false},
		{"address only", "MOVQ SP,R14\nLEAQ 16(R14),AX", false},
		{"sized NOP", "MOVQ SP,R14\nNOPL 16(R14)", false},
		{"logical AUTO", "LEAQ tmp-16(SP),R14\nMOVQ (R14),AX", false},
		{"partial copy", "MOVL SP,R14\nMOVQ (R14),AX", false},
		{"partial address", "LEAL 16(SP),R14\nMOVQ (R14),AX", false},
		{"different source", "MOVQ SI,R14\nMOVQ (R14),AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$160-0\n"+row.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if got := GoAMD64FixedLocalFrameBindingNeeded(file, "amd64"); got != row.want {
				t.Fatalf("source observation candidate = %v, want %v", got, row.want)
			}
		})
	}
}
