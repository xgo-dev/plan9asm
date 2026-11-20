package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86PackedUnsignedSignedByteMultiplyAddCompleteGoAssemblerForms(t *testing.T) {
	amd64Source := `TEXT packedmaddubswforms(SB),NOSPLIT,$0-0
	PMADDUBSW X0, X1
	PMADDUBSW (AX), X15
	VPMADDUBSW X0, X1, X2
	VPMADDUBSW (AX), X1, X2
	VPMADDUBSW Y0, Y1, Y2
	VPMADDUBSW (AX), Y1, Y2
	VPMADDUBSW Z0, Z1, Z2
	VPMADDUBSW (AX), Z1, Z2
	VPMADDUBSW X20, X21, X22
	VPMADDUBSW Y20, Y21, Y22
	VPMADDUBSW Z20, Z21, Z22
	VPMADDUBSW X20, X21, K1, X22
	VPMADDUBSW.Z (AX), X21, K2, X22
	VPMADDUBSW Y20, Y21, K3, Y22
	VPMADDUBSW.Z (AX), Y21, K4, Y22
	VPMADDUBSW Z20, Z21, K5, Z22
	VPMADDUBSW.Z (AX), Z21, K6, Z22
	RET
`
	ll := x86UnboundVoidScalarFormatObject(t, amd64Source, "packedmaddubswforms", "amd64", "x86_64-unknown-linux-gnu")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-maddubsw-amd64.ll", "packed-maddubsw-amd64.o", ll)

	source386 := `TEXT packedmaddubswforms386(SB),NOSPLIT,$0-0
	PMADDUBSW X0, X1
	PMADDUBSW (AX), X7
	VPMADDUBSW X0, X1, X2
	VPMADDUBSW (AX), X1, X2
	VPMADDUBSW Y0, Y1, Y2
	VPMADDUBSW (AX), Y1, Y2
	VPMADDUBSW Z0, Z1, Z7
	VPMADDUBSW (AX), Z6, Z7
	RET
`
	ll386 := x86UnboundVoidScalarFormatObject(t, source386, "packedmaddubswforms386", "386", "i386-unknown-linux-gnu")
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-maddubsw-386.ll", "packed-maddubsw-386.o", ll386)
}

func TestTranslateX86PackedUnsignedSignedByteMultiplyAddRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PMADDUBSW.Z X0, X1",
		"PMADDUBSW X0",
		"PMADDUBSW M0, M1",
		"PMADDUBSW Y0, Y1",
		"PMADDUBSW X0, (AX)",
		"VPMADDUBSW X0, X1",
		"VPMADDUBSW X0, Y1, Y2",
		"VPMADDUBSW X0, X1, (AX)",
		"VPMADDUBSW.BCST (AX), X1, X2",
		"VPMADDUBSW.Z X0, X1, X2",
		"VPMADDUBSW X0, X1, K0, X2",
		"VPMADDUBSW X0, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PMADDUBSW/VPMADDUBSW tables", instruction)
			}
		})
	}

	for _, instruction := range []string{
		"PMADDUBSW X8, X0",
		"PMADDUBSW X0, X8",
		"VPMADDUBSW Z8, Z1, Z2",
		"VPMADDUBSW Z0, Z1, Z8",
		"VPMADDUBSW X0, X1, K1, X2",
		"VPMADDUBSW.Z X0, X1, K1, X2",
	} {
		file, err := Parse(ArchAMD64, "TEXT bad386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			return
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad386": {Name: "bad386", Ret: Void}},
		}); err == nil {
			t.Fatalf("386 Translate accepted architecture-restricted %q", instruction)
		}
	}
}
