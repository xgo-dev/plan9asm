package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalSADCompleteForms(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	count := 0
	for _, original := range x86SADRows("amd64") {
		if strings.Contains(original, "(SB)") || strings.Contains(original, "(FS)") || strings.Contains(original, "(GS)") {
			continue // Those sources have separate global/segment ownership.
		}
		address := "65(CX)"
		if !strings.HasPrefix(original, "V") {
			address = "128(CX)"
		}
		instruction := strings.NewReplacer("16(AX)(BX*2)", address, "(AX)", address).Replace(original)
		count++
		t.Run(instruction, func(t *testing.T) {
			assembly := fixedLocalAlignedAddressAssembly(t, "Value", instruction, "")
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Fatalf("initialized SAD form rejected: %v", err)
			}
		})
	}
	if count != 147 {
		t.Fatalf("private SAD matrix changed: %d forms", count)
	}
}

func TestGoAMD64FixedLocalSADMemoryAndAliases(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	maskZero := "MOVQ $0,AX\nKMOVQ AX,K1\n"
	for _, row := range []struct {
		instruction, setup, omit string
		accept                   bool
	}{
		{"PSADBW X2,X2", "", "VMOVUPS Z0,Z2\n", true},
		{"VPSADBW Y1,Y1,Y2", "", "VMOVUPS Z0,Z1\n", true},
		{"VMPSADBW $0,Y1,Y1,Y2", "", "VMOVUPS Z0,Z1\n", false},
		{"MPSADBW $0,65(CX),X2", "", "", false},
		{"VMPSADBW $0,160(CX),Y1,Y2", "", "", true},
		{"VMPSADBW $0,161(CX),Y1,Y2", "", "", false},
		{"VDBPSADBW.Z $0,128(CX),Z1,K1,Z2", maskZero, "VMOVUPS Z0,Z2\n", true},
		{"VDBPSADBW.Z $0,129(CX),Z1,K1,Z2", maskZero, "", false},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			assembly := fixedLocalAlignedAddressAssembly(t, "Value", row.instruction, row.setup)
			if row.omit != "" {
				if !strings.Contains(assembly, row.omit) {
					t.Fatal("fixture input unavailable")
				}
				assembly = strings.ReplaceAll(assembly, row.omit, "")
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private SAD memory or register dependency, accept=%t: %v", row.accept, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalSADOriginalObjects(t *testing.T) {
	rows := []struct{ instruction, setup string }{
		{"VDBPSADBW $127, 17(SP)(BP*1), Z5, K2, Z19", "LEAQ 108(CX),R10\nMOVQ R10,SP\nMOVQ $3,BP\n"},
		{"VPSADBW 17(SP)(BP*8), X3, X31", "LEAQ 106(CX),R10\nMOVQ R10,SP\nMOVQ $1,BP\n"},
		{"VPSADBW 65(CX),Y1,Y2", ""},
		{"VMPSADBW $37,65(CX),Y1,Y2", ""},
		{"PSADBW 128(CX),X2", ""},
		{"MPSADBW $0,128(CX),X2", ""},
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalAlignedAddressAssembly(t, name, row.instruction, row.setup))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
