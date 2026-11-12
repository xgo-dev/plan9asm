package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// These are initialized source/object witnesses. Independent numerical/native
// owners retain their own scope; an object pass is not executed semantics.
func x86OfficialSpecialVectorStateAssembly(t *testing.T, cases []x86OfficialPackedCase) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	appendBody := func(fixture *x86OfficialPackedCase, body, declaration string) {
		found := 0
		for offset, line := range strings.Split(body, "\n") {
			if line == fixture.witness.Instruction {
				fixture.line = strings.Count(source.String(), "\n") + offset + 1
				found++
			}
		}
		if found != 1 {
			t.Fatal("fixture must contain its exact original source instruction once", fixture.row, fixture.witness.Instruction, found)
		}
		source.WriteString(body)
		declarations.WriteString(declaration)
	}
	for index := range cases {
		fixture := &cases[index]
		witness := fixture.witness
		fixture.symbol = fmt.Sprint("SpecialVector", index)
		opcode := strings.Split(strings.Fields(witness.Instruction)[0], ".")[0]
		if strings.HasPrefix(opcode, "V4FM") || strings.HasPrefix(opcode, "V4FNM") || strings.HasPrefix(opcode, "VP4DP") {
			first, err := strconv.Atoi(witness.Second[1:])
			if err != nil {
				t.Fatal(err)
			}
			destination, err := strconv.Atoi(witness.Destination[1:])
			if err != nil {
				t.Fatal(err)
			}
			mode := "plain"
			if witness.Masked {
				mode = "merge"
			}
			if witness.Zeroing {
				mode = "zero"
			}
			row := x86FourSourceOracleRow{op: opcode, first: first, dest: destination, scalar: strings.HasSuffix(opcode, "SS"), mode: mode}
			body, declaration := x86FourSourceInitializedSource(row, "amd64", fixture.symbol, false)
			appendBody(fixture, body, declaration)
			continue
		}
		declaration := fmt.Sprintf("func %s(out *[2048]byte,a *[64]byte,b *[256]byte,old *[64]byte,mask uint64,lengthA,lengthB int64)\n", fixture.symbol)
		var body strings.Builder
		fmt.Fprintf(&body, "TEXT ·%s(SB),4,$0-56\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ old+24(FP),DX\n", fixture.symbol)
		zero := opcode == "VZEROALL" || opcode == "VZEROUPPER"
		state := opcode == "VLDMXCSR" || opcode == "VSTMXCSR"
		flagOnly := strings.HasPrefix(opcode, "VCOMI") || strings.HasPrefix(opcode, "VUCOMI") ||
			opcode == "VPTEST" || opcode == "VTESTPD" || opcode == "VTESTPS"
		packedString := strings.HasPrefix(opcode, "VPCMPESTR") || strings.HasPrefix(opcode, "VPCMPISTR")
		if zero {
			// Four affected full aliases are caller-supplied and observed. The existing
			// whole-bank runtime owner separately checks every register and view.
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&body, "VMOVUPS %d(BX),Z%d\n", register*64, register)
			}
		} else if !state {
			instruction := x86ScalarLaneInstruction(t, witness.Instruction)
			last := len(instruction.Args) - 1
			seeded := make(map[int]bool)
			seed := 0
			for at, operand := range instruction.Args {
				if operand.Kind != OpReg || at == last && !flagOnly && !packedString {
					continue
				}
				number, valid := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
				if !valid || seeded[number] {
					continue
				}
				seeded[number] = true
				pointer, displacement := "AX", 0
				if seed > 0 {
					pointer, displacement = "BX", (seed-1)*64
				}
				fmt.Fprintf(&body, "VMOVUPS %d(%s),Z%d\n", displacement, pointer, number)
				seed++
			}
			if witness.Masked {
				body.WriteString("MOVQ mask+32(FP),R9\nKMOVQ R9,K1\n")
				if !witness.Zeroing && !witness.MaskResult {
					destination, valid := amd64VectorRegisterIndex(Reg(witness.Destination), amd64VectorByteWidth(Reg(witness.Destination)))
					if !valid {
						t.Fatal("masked vector output is not a vector carrier", witness)
					}
					if !seeded[destination] {
						fmt.Fprintf(&body, "VMOVUPS (DX),Z%d\n", destination)
					}
				}
			}
			if packedString {
				// BX is the source pointer before EAX/EDX become independent numerical
				// lengths. No pointer bit is borrowed as an implicit integer input.
				body.WriteString("MOVQ AX,BX\n")
				if strings.HasPrefix(opcode, "VPCMPESTR") {
					body.WriteString("MOVQ lengthA+40(FP),AX\nMOVQ lengthB+48(FP),DX\n")
				}
			}
		}
		if opcode == "VSTMXCSR" {
			body.WriteString("MOVQ DI,AX\n")
		}
		body.WriteString("MOVL $5,R8\nCMPL R8,$3\n")
		body.WriteString(witness.Instruction + "\n")
		switch {
		case zero:
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&body, "VMOVUPS Z%d,%d(DI)\n", register, register*64)
			}
		case state:
			body.WriteString("STMXCSR 64(DI)\n")
		case packedString:
			if strings.HasSuffix(opcode, "M") {
				body.WriteString("VMOVUPS Z0,0(DI)\n")
			} else {
				body.WriteString("MOVQ CX,0(DI)\n")
			}
		case flagOnly:
			// The following masked PUSHF observation is the actual result.
		case witness.MaskResult:
			fmt.Fprintf(&body, "KMOVQ %s,R9\nMOVQ R9,0(DI)\n", witness.Destination)
		default:
			destination, valid := amd64VectorRegisterIndex(Reg(witness.Destination), amd64VectorByteWidth(Reg(witness.Destination)))
			if !valid {
				t.Fatal("ordinary output lost its vector carrier", witness)
			}
			fmt.Fprintf(&body, "VMOVUPS Z%d,0(DI)\n", destination)
		}
		body.WriteString("PUSHFQ\nPOPQ R8\nANDL $0x8d5,R8\nMOVL R8,320(DI)\nSTMXCSR 324(DI)\nRET\n")
		appendBody(fixture, body.String(), declaration)
	}
	return source.String(), declarations.String()
}

func TestX86OfficialSpecialVectorStateRowsInitializedThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	// The independent per-row source/control count excludes controls belonging
	// to other encoding blocks in the same opcode payload. The original 1052
	// whole-payload projection is retained as a failed preparation observation.
	x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86SpecialVectorStateRows, 237, 886, 0,
		func(cases []x86OfficialPackedCase) (string, string) {
			return x86OfficialSpecialVectorStateAssembly(t, cases)
		}, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}
