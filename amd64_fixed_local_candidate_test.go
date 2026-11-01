package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalScalarFrameCandidates(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, operation := range []string{
			"MOV%s AX,8(SP)", "MOV%s 8(SP),AX", "MOV%s $1,8(SP)",
			"ADD%s $1,8(SP)", "XOR%s AX,8(SP)", "NOT%s 8(SP)",
			"ROL%s $1,8(SP)", "CMP%s 8(SP),AX",
		} {
			instruction := fmt.Sprintf(operation, width)
			source := "TEXT ·Value(SB),4,$64-0\n" + instruction + "\nRET\n"
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
			count++
			t.Run(instruction, func(t *testing.T) {
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
					t.Fatal("scalar-only physical scratch never reaches the actual frame observer")
				}
				if GoAMD64FixedLocalFrameBindingNeeded(file, "386") {
					t.Fatal("amd64 source query changed a different source architecture")
				}
			})
		}
	}
	if count != 32 {
		t.Fatal("incomplete scalar family/width fixture", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, instruction := range []string{
		"MOVQ AX,tmp-8(SP)", "MOVQ tmp-8(SP),AX", "ADDQ $1,tmp-8(SP)",
		"MOVQ AX,(SI)", "MOVQ (SI),AX", "ADDQ $1,(SI)",
		"MOVQ AX,BX", "NOPL 8(SP)", "LEAQ 8(SP),AX", "MOVQ.Z AX,8(SP)",
	} {
		t.Run("not physical access/"+instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$64-0\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Fatal("candidate supplied a role to unrelated syntax")
			}
		})
	}
}

func TestGoAMD64FixedLocalFrameCandidateQueryCannotSupplyPermission(t *testing.T) {
	for _, operation := range []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDD 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
	} {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			source, sig, pkg := x86PrivateAlignedFrameAuditFixture(t, operation)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") || GoAMD64FixedLocalFrameBindingNeeded(file, "386") {
				t.Fatal("candidate query lost its exact native family/target role")
			}
			x86PrivateAlignedFrameAuditAPIs(t, source, sig, pkg, func(t *testing.T, err error) {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("query supplied a forged native permission: %v", err)
				}
			})
		})
	}
	for _, source := range []string{
		"TEXT ·Value(SB),4,$0-0\nPADDL 16(SP),X0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL X1,X0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nVPADDD X1,X2,X0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL (AX),M0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL X1\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL constant<>(SB),X0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL (AX),X0\nRET\n",
		"TEXT ·Value(SB),4,$160-0\nPADDL (AX)(CX*2),X0\nRET\n",
		"TEXT ·Value(SB),4,$160-16\nPADDL input+0(FP),X0\nRET\n",
	} {
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
			t.Fatalf("query widened unrelated source grammar: %s", source)
		}
	}
}
