package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEShiftNarrowCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveshiftnarrowforms(SB),$0-0\n")
	for _, op := range []string{"ZSHRNB", "ZSHRNT", "ZRSHRNB", "ZRSHRNT"} {
		for _, form := range []struct {
			source, destination string
			max                 int
		}{{"H", "B", 8}, {"S", "H", 16}, {"D", "S", 32}} {
			for _, shift := range []int{1, form.max} {
				fmt.Fprintf(&source, "\t%s $%d, Z1.%s, Z2.%s\n", op, shift, form.source, form.destination)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEShiftNarrowCompleteGo127Family(t *testing.T) {
	source := arm64SVEShiftNarrowCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveshiftnarrowforms": {Name: "sveshiftnarrowforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.shrnb.nxv8i16",
				"@llvm.aarch64.sve.shrnt.nxv4i32",
				"@llvm.aarch64.sve.rshrnb.nxv2i64",
				"@llvm.aarch64.sve.rshrnt.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE shift-narrow lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-shift-narrow.ll", "arm64-sve-shift-narrow.o", ll)
		})
	}
}

func TestTranslateARM64SVEShiftNarrowRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSHRNB $0, Z1.H, Z2.B",
		"ZSHRNB $1, Z1.S, Z2.B",
		"ZRSHRNT $1, Z1.Q, Z2.D",
		"ZSHRNB $1, Z1.H",
		"ZRSHRNT.Z $1, Z1.D, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "$", "imm").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveshiftnarrow(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveshiftnarrow": {Name: "badsveshiftnarrow", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE shift-narrow forms", instruction)
			}
		})
	}
}

func TestTranslateARM64SVEShiftNarrowRejectsGoAcceptedUnencodableShifts(t *testing.T) {
	// Go 1.27's shared tsz operand accepts shifts up to sourceBits-1 here,
	// although the architecture and LLVM narrowing intrinsics allow only
	// $1..$destinationBits. Reject these before they can crash LLVM selection.
	for _, instruction := range []string{
		"ZSHRNT $9, Z1.H, Z2.B",
		"ZRSHRNB $17, Z1.S, Z2.H",
		"ZRSHRNT $33, Z1.D, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "$", "imm").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveshiftnarrowrange(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveshiftnarrowrange": {Name: "badsveshiftnarrowrange", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted Go-assembler form %q that LLVM 22 cannot encode", instruction)
			}
		})
	}
}
