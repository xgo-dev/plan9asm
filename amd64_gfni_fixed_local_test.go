package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalGFNICompleteForms(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86GFNIRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	count := 0
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			instruction := strings.Replace(witness.Instruction, "(AX)", "65(CX)", 1)
			count++
			t.Run(row.ID+"/"+instruction, func(t *testing.T) {
				assembly := fixedLocalAlignedAddressAssembly(t, "Value", instruction, "")
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
					t.Fatalf("initialized official GFNI form rejected: %v", err)
				}
			})
		}
	}
	if len(rows) != 24 || count != 84 {
		t.Fatalf("official GFNI matrix changed: %d rows, %d witnesses", len(rows), count)
	}
}

func TestGoAMD64FixedLocalGFNIMemoryAndMasks(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	maskZero := "MOVQ $0,AX\nKMOVQ AX,K1\n"
	for _, row := range []struct {
		instruction string
		drop        string
		accept      bool
	}{
		{"VGF2P8AFFINEQB.BCST.Z $7,184(CX),Z1,K1,Z2", "VMOVUPS Z0,Z2\n", true},
		{"VGF2P8AFFINEQB.BCST.Z $7,185(CX),Z1,K1,Z2", "", false},
		{"VGF2P8AFFINEQB.Z $7,184(CX),Z1,K1,Z2", "", false},
		{"VGF2P8AFFINEINVQB.BCST $7,184(CX),Z1,K1,Z2", "VMOVUPS Z0,Z2\n", false},
		{"VGF2P8MULB.Z 128(CX),Z1,K1,Z2", "VMOVUPS Z0,Z2\n", true},
		{"VGF2P8MULB.Z 129(CX),Z1,K1,Z2", "", false},
		{"VGF2P8MULB.Z 128(CX),Z1,K1,Z2", "VMOVUPS Z0,Z1\n", false},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			assembly := fixedLocalAlignedAddressAssembly(t, "Value", row.instruction, maskZero)
			if row.drop != "" {
				if !strings.Contains(assembly, row.drop) {
					t.Fatal("fixture input unavailable")
				}
				assembly = strings.Replace(assembly, row.drop, "", 1)
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private GFNI memory or mask dependency, accept=%t: %v", row.accept, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalGFNIOriginalObjects(t *testing.T) {
	rows := []struct{ instruction, setup string }{
		{"VGF2P8AFFINEINVQB $64, -17(BP), X31, K3, X26", "LEAQ 82(CX),BP\n"},
		{"VGF2P8AFFINEINVQB $27, -17(BP)(SI*1), Y20, K3, Y0", "LEAQ 81(CX),BP\nMOVQ $1,SI\n"},
		{"VGF2P8AFFINEQB $82, 17(SP)(BP*2), X21, K1, X15", "LEAQ 45(CX),R10\nMOVQ R10,SP\nMOVQ $2,BP\n"},
		{"VGF2P8AFFINEQB $94, -17(BP)(SI*8), Z19, K1, Z15", "LEAQ 74(CX),BP\nMOVQ $1,SI\n"},
		{"VGF2P8MULB (BP), X1, K7, X7", "LEAQ 65(CX),BP\n"},
		{"VGF2P8AFFINEQB.BCST.Z $255,184(CX),Z1,K1,Z2", ""},
		{"VGF2P8AFFINEINVQB  $0,65(CX),Y1,Y2", ""},
		{"VGF2P8MULB 65(CX),Y1,Y2", ""},
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalAlignedAddressAssembly(t, name, row.instruction, row.setup))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
