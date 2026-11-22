package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fixedLocalVSIBFixture struct {
	op    string
	setup string
	save  string
}

func fixedLocalVSIBOriginalStackFixtures() []fixedLocalVSIBFixture {
	return []fixedLocalVSIBFixture{
		{
			"VPGATHERQQ X0, 16(SP)(X1*1), X2",
			"VPXOR X0,X0,X0\nVPCMPEQD X0,X0,X0\nVPXOR X1,X1,X1\nVMOVUPS (SP),X2\n",
			"VMOVUPS X2,128(SP)\nMOVQ 128(SP),AX\n",
		},
		{
			"VGATHERDPD (SP)(X4*2), K7, Y22",
			"VPXOR Y4,Y4,Y4\nMOVQ $-1,CX\nKMOVQ CX,K7\nVMOVUPS (SP),Y22\n",
			"VMOVUPS Y22,128(SP)\nMOVQ 128(SP),AX\n",
		},
		{
			"VPSCATTERDD Y1, K3, (SP)(Y4*2)",
			"VPXOR Y4,Y4,Y4\nMOVQ $-1,CX\nKMOVQ CX,K3\nVMOVUPS (SP),Y1\n",
			"MOVQ (SP),AX\n",
		},
	}
}

func (row fixedLocalVSIBFixture) assembly(name string) string {
	var asm strings.Builder
	fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$192-16\nMOVQ a+0(FP),AX\n", name)
	for offset := 0; offset < 64; offset += 8 {
		fmt.Fprintf(&asm, "MOVQ AX,%d(SP)\n", offset)
	}
	asm.WriteString(row.setup)
	fmt.Fprintln(&asm, row.op)
	asm.WriteString(row.save)
	asm.WriteString("MOVQ AX,ret+8(FP)\nRET\n")
	return asm.String()
}

func TestGoAMD64FixedLocalVSIBStackObjects(t *testing.T) {
	fixedLocalVSIBStackObjects(t, "", fixedLocalVSIBOriginalStackFixtures())
}

func fixedLocalVSIBStackObjects(t *testing.T, literals string, rows []fixedLocalVSIBFixture) {
	t.Helper()
	var assembly, declarations strings.Builder
	assembly.WriteString(literals)
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(row.assembly(name))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalVSIBStackProof(t *testing.T) {
	_, _, signature, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range fixedLocalVSIBOriginalStackFixtures() {
		t.Run(row.op, func(t *testing.T) {
			source := row.assembly("Value")
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			proven, err := proveX86FixedLocal(file.Funcs[0], signature)
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range proven.Instrs {
				if index := fixedLocalVSIBOperand(ins); index >= 0 {
					access, found := ins.x86FixedLocalMemory[index]
					if !found || access.owner != proven.x86FixedLocal || access.width != 4 && access.width != 8 {
						t.Fatalf("one repeated lane requires one owned element interval: %#v", access)
					}
					return
				}
			}
			t.Fatal("VSIB instruction disappeared from the complete source")
		})
	}
}

func TestGoAMD64FixedLocalVSIBStackGuards(t *testing.T) {
	_, _, signature, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	row := fixedLocalVSIBOriginalStackFixtures()[0]
	original := row.assembly("Value")
	for _, change := range []struct {
		name string
		have string
		want string
	}{
		{"overwrite index alias", "VPXOR X1,X1,X1", "VPXOR X1,X1,X1\nVMOVUPS 0(SP),Y1"},
		{"uninitialized lane bytes", "16(SP)(X1*1)", "80(SP)(X1*1)"},
		{"out of frame", "16(SP)(X1*1)", "192(SP)(X1*1)"},
		{"uninitialized VEX mask", "VPXOR X0,X0,X0\nVPCMPEQD X0,X0,X0\n", ""},
		{"uninitialized gather destination", "VMOVUPS (SP),X2\n", ""},
	} {
		t.Run(change.name, func(t *testing.T) {
			source := strings.Replace(original, change.have, change.want, 1)
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], signature); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unsupported exact address or input gained a proof: %v", err)
			}
		})
	}
}
