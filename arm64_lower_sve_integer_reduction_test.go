package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEIntegerReductionCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveintreduceforms(SB),$0-0\n")
	for _, base := range []string{"ZANDV", "ZEORV", "ZORV"} {
		for predicate, sourceWidth := range []string{"B", "H", "S", "D"} {
			// Go's generated reduction rows use a generic Zn.T operand for each
			// VB/VH/VS/VD spelling. Cover the full 4x4 encoder matrix; the
			// effective hardware width is the bitwise union of both size fields.
			for _, opcodeWidth := range []string{"B", "H", "S", "D"} {
				source.WriteString("\t" + base + opcodeWidth + " Z1." + sourceWidth + ", P" + string(rune('0'+predicate)) + ", V2\n")
			}
		}
	}
	for _, op := range []string{"ZADDQV", "ZANDQV", "ZEORQV", "ZORQV"} {
		for predicate, width := range []string{"B", "H", "S", "D"} {
			arrangement := map[string]string{"B": "B16", "H": "H8", "S": "S4", "D": "D2"}[width]
			source.WriteString("\t" + op + " Z3." + width + ", P" + string(rune('4'+predicate)) + ", V5." + arrangement + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEIntegerReductionCompleteGo127Family(t *testing.T) {
	source := arm64SVEIntegerReductionCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveintreduceforms": {Name: "sveintreduceforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.andv.nxv16i8",
				"@llvm.aarch64.sve.eorv.nxv8i16",
				"@llvm.aarch64.sve.orv.nxv4i32",
				"@llvm.aarch64.sve.addqv.v2i64.nxv2i64",
				"@llvm.aarch64.sve.andqv.v16i8.nxv16i8",
				"@llvm.aarch64.sve.eorqv.v8i16.nxv8i16",
				"@llvm.aarch64.sve.orqv.v4i32.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE integer reduction lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-integer-reduction.ll", "arm64-sve-integer-reduction.o", ll)
		})
	}
}

func TestTranslateARM64SVEIntegerReductionRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZANDVB Z1.H, P0.M, V2",
		"ZEORVH Z1.H, P8, V2",
		"ZORVS Z1.S, P0, V2.S4",
		"ZADDQV Z1.S, P0, V2.H8",
		"ZANDQV Z1.H, P0, V2",
		"ZEORQV Z1.D, P0.M, V2.D2",
		"ZORQV Z1.Q, P0, V2.B16",
		"ZADDQV.Z Z1.B, P0, V2.B16",
		"ZANDVB Z1.B, P0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveintreduce(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveintreduce": {Name: "badsveintreduce", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE integer reduction forms", instruction)
			}
		})
	}
}
