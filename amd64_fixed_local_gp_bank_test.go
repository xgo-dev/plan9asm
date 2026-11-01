package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ABI0 does not give R14 an initialized g value. Nonzero original Go frames
// independently save/restore BP outside the body. Both registers can therefore
// hold explicitly defined virtual values, without exposing their entry state.
func TestGoAMD64FixedLocalDefinedGPBank(t *testing.T) {
	var original strings.Builder
	ordinal := 0
	for _, register := range []string{"AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			body := fmt.Sprintf("MOVQ AX,%s\nADD%s $1,%s\nMOVQ %s,AX", register, width, register, register)
			fn, sig, source := fixedLocalGPFixture(t, body)
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
			ordinal++
			t.Run(register+"/"+width, func(t *testing.T) {
				if _, err := proveX86FixedLocal(fn, sig); err != nil {
					t.Fatal("explicitly defined ABI0 register rejected", err)
				}
			})
		}
	}
	if ordinal != 60 {
		t.Fatal("incomplete independent GP bank/width matrix", ordinal)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, register := range []string{"BP", "R14"} {
		for index, body := range []string{
			"MOVQ " + register + ",AX",
			"MOVB $0," + register + "\nMOVQ " + register + ",AX",
			"MOVQ (" + register + "),AX",
			"MOVQ SP," + register + "\nMOVQ " + register + ",AX",
			"MOVQ $1," + register + "\nMOVQ (" + register + "),AX",
		} {
			t.Run(fmt.Sprintf("unbound/%s/%d", register, index), func(t *testing.T) {
				fn, sig, _ := fixedLocalGPFixture(t, body)
				if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("entry register or numerical bits gained pointer authority", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalDefinedGPBankRoles(t *testing.T) {
	var original strings.Builder
	ordinal := 0
	for _, register := range []string{"BP", "R14"} {
		for index, operation := range []string{
			"MOVQ AX,%s\nCMPQ AX,AX\nSETEQ %s\nMOVQ %s,AX",
			"MOVQ AX,%s\nCMPQ AX,AX\nCMOVQEQ AX,%s\nMOVQ %s,AX",
			"KMOVQ AX,K1\nKMOVQ K1,%s\nADDQ $1,%s\nMOVQ %s,AX",
		} {
			body := fmt.Sprintf(operation, register, register, register)
			fn, sig, source := fixedLocalGPFixture(t, body)
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
			ordinal++
			t.Run(fmt.Sprintf("%s/numeric/%d", register, index), func(t *testing.T) {
				if _, err := proveX86FixedLocal(fn, sig); err != nil {
					t.Fatal("defined register rejected by an independent effect consumer", err)
				}
			})
		}
		for index, operation := range []string{
			"MOVQ SI,%s\nADDQ AX,%s\nMOVQ (%s),AX",
			"LEAQ 8(SI),%s\nADDQ AX,%s\nMOVQ (%s),AX",
		} {
			body := fmt.Sprintf(operation, register, register, register)
			fn, sig, source := fixedLocalInputFixture(t, body)
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
			ordinal++
			t.Run(fmt.Sprintf("%s/input/%d", register, index), func(t *testing.T) {
				if _, err := proveX86FixedLocal(fn, sig); err != nil {
					t.Fatal("explicit typed input origin rejected", err)
				}
			})
		}
		pkg, _, file, options := fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
		source := strings.Replace(fixedLocalVoidAssembly(file), "MOVQ AX,16(SP)", "MOVQ AX,"+register+"\nMOVQ AX,16(SP)", 1)
		parsed, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(register+"/void", func(t *testing.T) {
			if _, err := proveX86FixedLocal(parsed.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
				t.Fatal("void source rejected a defined register", err)
			}
		})
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", ordinal), 1))
		ordinal++
	}
	if ordinal != 12 {
		t.Fatal("incomplete independent role matrix", ordinal)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
