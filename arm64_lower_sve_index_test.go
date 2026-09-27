package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEIndexCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveindexforms(SB),$0-0\n")
	for _, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tZINDEX R1, R2, Z3.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEX ZR, $15, Z4.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEX $-16, R5, Z6.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEX $1, $11, Z7.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEXW R8, R9, Z10.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEXW ZR, $-16, Z11.%s\n", width)
		fmt.Fprintf(&source, "\tZINDEXW $15, R12, Z13.%s\n", width)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEIndexCompleteGo127Family(t *testing.T) {
	source := arm64SVEIndexCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveindexforms": {Name: "sveindexforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.index.nxv16i8",
				"@llvm.aarch64.sve.index.nxv8i16",
				"@llvm.aarch64.sve.index.nxv4i32",
				"@llvm.aarch64.sve.index.nxv2i64",
				"@llvm.aarch64.sve.index.nxv4i32(i32 11, i32 1)",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE INDEX lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			// Go's ZINDEX scalar forms always set the D size bits, even when
			// their accepted destination spelling carries B/H/S.
			if got := strings.Count(ll, "@llvm.aarch64.sve.index.nxv2i64"); got < 13 {
				t.Fatalf("%s ZINDEX scalar forms did not preserve Go's forced-D encoding: got %d i64 references\n%s", triple, got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-index.ll", "arm64-sve-index.o", ll)
		})
	}
}

func TestTranslateARM64SVEIndexRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZINDEXW $1, $2, Z0.S",
		"ZINDEX $-17, R0, Z0.D",
		"ZINDEX $16, R0, Z0.D",
		"ZINDEX RSP, R0, Z0.D",
		"ZINDEX R0, RSP, Z0.D",
		"ZINDEX R0, R1, Z0",
		"ZINDEX R0, R1, Z0.Q",
		"ZINDEX R0, R1, V0.D",
		"ZINDEX.Z R0, R1, Z0.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveindex(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveindex": {Name: "badsveindex", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE INDEX forms", instruction)
			}
		})
	}
}
