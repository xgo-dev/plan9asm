package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEBitPermuteCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT svebitpermuteforms(SB),$0-0\n")
	for _, op := range []string{"ZBDEP", "ZBEXT", "ZBGRP"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEBitPermuteCompleteGo127Family(t *testing.T) {
	source := arm64SVEBitPermuteCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svebitpermuteforms": {Name: "svebitpermuteforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve-bitperm,+sve2"`,
				"@llvm.aarch64.sve.bdep.x.nxv16i8",
				"@llvm.aarch64.sve.bext.x.nxv8i16",
				"@llvm.aarch64.sve.bgrp.x.nxv4i32",
				"@llvm.aarch64.sve.bdep.x.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE bit-permute lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-bit-permute.ll", "arm64-sve-bit-permute.o", ll)
		})
	}
}

func TestTranslateARM64SVEBitPermuteRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZBDEP Z1.B, Z2.H, Z3.B",
		"ZBEXT Z1.S, Z2.S, Z3.D",
		"ZBGRP Z1.Q, Z2.Q, Z3.Q",
		"ZBDEP Z1.D, Z2.D",
		"ZBEXT.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvebitpermute(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvebitpermute": {Name: "badsvebitpermute", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE bit-permute forms", instruction)
			}
		})
	}
}
