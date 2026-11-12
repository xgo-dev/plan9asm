package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARMUnsignedParallelByteAddSubCompleteDecodedForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT parallelBytes(SB), $0-0\n\tCMP R0, R0\n")
	for condition := uint32(0); condition <= 14; condition++ {
		for _, base := range []uint32{0x06500f90, 0x06500ff0} {
			// Rd=R2, Rn=R3, Rm=R4. The decoder table defines one
			// three-register form for each of ARM's 15 executable conditions.
			word := condition<<28 | base | 3<<16 | 2<<12 | 4
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{
			"parallelBytes": {Name: "parallelBytes", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{"add <4 x i8>", "sub <4 x i8>"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("parallel byte semantics omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-parallel-byte.ll", "arm-parallel-byte.o", ir)
}

func TestARMUnsignedParallelByteAddSubRejectsNonExecutableCondition(t *testing.T) {
	for _, word := range []uint32{0xf6500f91, 0xf6500ff1} {
		t.Run(fmt.Sprintf("%#08x", word), func(t *testing.T) {
			source := fmt.Sprintf("TEXT invalid(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if _, err := Translate(file, Options{
				Goarch:       "arm",
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{
					"invalid": {Name: "invalid", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate() accepted reserved encoding %#08x", word)
			}
		})
	}
}

func TestARMUnsignedParallelByteAddSubRejectsNamedFormsOutsideDecoderShape(t *testing.T) {
	for _, instruction := range []string{
		"UADD8 R0, R1",
		"USUB8 $1, R0, R1",
		"UADD8.S R0, R1, R2",
		"USUB8 R0, R1, R2, R3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT invalid(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if _, err := Translate(file, Options{
				Goarch:       "arm",
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{
					"invalid": {Name: "invalid", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate() accepted invalid form %q", instruction)
			}
		})
	}
}
