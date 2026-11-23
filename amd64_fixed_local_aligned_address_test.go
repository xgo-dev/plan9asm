package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The Go corpus only assembles each instruction. Give its unchanged address
// a legal complete frame on every possible SP residue. Use a separate aligned
// base for initialization and result observation.
func fixedLocalAlignedAddressAssembly(t *testing.T, name, operation, setup string) string {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, operation)
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$256-16\nMOVQ a+0(FP),AX\n", name)
	source.WriteString("MOVQ SP,R11\nLEAQ 64(SP),CX\nANDQ $-64,CX\n")
	for offset := 64; offset < 192; offset += 8 {
		fmt.Fprintf(&source, "MOVQ AX,%d(CX)\nNOTQ AX\n", offset)
	}
	source.WriteString("VMOVUPS 64(CX),Z0\n")
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || arg.Reg == "Z0" {
			continue
		}
		if amd64IsKOperand(arg) {
			fmt.Fprintf(&source, "KMOVQ AX,%s\n", arg.Reg)
		} else if amd64VectorByteWidth(arg.Reg) != 0 {
			fmt.Fprintf(&source, "VMOVUPS Z0,%s\n", x86CallerVectorRoot(arg.Reg))
		}
	}
	source.WriteString(setup)
	fmt.Fprintln(&source, operation)
	source.WriteString("MOVQ R11,SP\n")
	last := ins.Args[len(ins.Args)-1]
	if last.Kind == OpReg {
		fmt.Fprintf(&source, "VMOVUPS %s,64(CX)\nMOVQ 64(CX),AX\n", last.Reg)
	} else {
		source.WriteString("MOVQ 128(CX),AX\n")
	}
	source.WriteString("MOVQ AX,ret+8(FP)\nRET\n")
	return source.String()
}

func TestGoAMD64FixedLocalAlignedOriginalAddresses(t *testing.T) {
	rows := []struct{ operation, setup string }{
		{"VMOVAPD X3, K1, (SP)", "LEAQ 128(CX),R10\nMOVQ R10,SP\n"},
		{"VMOVAPD -17(BP), K5, Y26", "LEAQ 145(CX),BP\n"},
		{"VMOVAPD -17(BP)(SI*1), K7, Z6", "LEAQ 144(CX),BP\nMOVQ $1,SI\n"},
		{"VMOVAPD -17(BP)(SI*1), K7, Z14", "LEAQ 144(CX),BP\nMOVQ $1,SI\n"},
		{"VMOVAPS Y22, K7, 17(SP)(BP*2)", "LEAQ 109(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVAPS (BP), K4, Y3", "LEAQ 128(CX),BP\n"},
		{"VMOVDQA32 X3, K4, -17(BP)(SI*1)", "LEAQ 144(CX),BP\nMOVQ $1,SI\n"},
		{"VMOVDQA32 Z27, K3, -17(BP)(SI*2)", "LEAQ 143(CX),BP\nMOVQ $1,SI\n"},
		{"VMOVDQA32 Z15, K3, -17(BP)(SI*2)", "LEAQ 143(CX),BP\nMOVQ $1,SI\n"},
		{"VMOVDQA64 17(SP)(BP*1), K1, X0", "LEAQ 110(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVDQA64 17(SP)(BP*4), K1, Y30", "LEAQ 107(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVDQA64 17(SP)(BP*8), K1, Y30", "LEAQ 103(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVNTPS Z6, 17(SP)(BP*4)", "LEAQ 107(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVNTPS Z6, 17(SP)(BP*8)", "LEAQ 103(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVNTPS Z16, 17(SP)(BP*4)", "LEAQ 107(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VMOVNTPS Z16, 17(SP)(BP*8)", "LEAQ 103(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalAlignedAddressAssembly(t, name, row.operation, row.setup))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalAlignedAddressRejectsMisalignmentAndOverrun(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name      string
		offset    int
		operation string
	}{
		{"unaligned X", 129, "VMOVAPD X3,K1,(SP)"},
		{"unaligned indexed Y", 108, "VMOVAPS Y22,K7,17(SP)(BP*2)"},
		{"unaligned indexed Z", 102, "VMOVNTPS Z6,17(SP)(BP*8)"},
		{"aligned Z past frame", 167, "VMOVNTPS Z6,17(SP)(BP*8)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			setup := fmt.Sprintf("LEAQ %d(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n", row.offset)
			source := fixedLocalAlignedAddressAssembly(t, "Value", row.operation, setup)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "crosses storage or has residue-dependent native alignment") {
				t.Fatal("a bad aligned-memory address acquired a private-frame certificate", err)
			}
		})
	}
}
