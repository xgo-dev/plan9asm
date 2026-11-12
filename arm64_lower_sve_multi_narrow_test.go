package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEMultiNarrowCompleteGo127Family(t *testing.T) {
	const source = `TEXT svemultinarrow(SB),$0-0
	ZSQCVTN [Z0.S-Z1.S], Z2.H
	ZSQCVTUN [Z14.S-Z15.S], Z16.H
	ZUQCVTN [Z30.S-Z31.S], Z0.H
	ZSQRSHRN $1, [Z0.H-Z1.H], Z2.B
	ZSQRSHRN $8, [Z30.H-Z31.H], Z3.B
	ZSQRSHRN $1, [Z2.S-Z3.S], Z4.H
	ZSQRSHRN $16, [Z28.S-Z29.S], Z5.H
	ZSQRSHRUN $1, [Z4.H-Z5.H], Z6.B
	ZSQRSHRUN $8, [Z26.H-Z27.H], Z7.B
	ZSQRSHRUN $1, [Z6.S-Z7.S], Z8.H
	ZSQRSHRUN $16, [Z24.S-Z25.S], Z9.H
	ZUQRSHRN $1, [Z8.H-Z9.H], Z10.B
	ZUQRSHRN $8, [Z22.H-Z23.H], Z11.B
	ZUQRSHRN $1, [Z10.S-Z11.S], Z12.H
	ZUQRSHRN $16, [Z20.S-Z21.S], Z13.H
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemultinarrow": {Name: "svemultinarrow", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.sqcvtn.x2.nxv4i32",
				"@llvm.aarch64.sve.sqcvtun.x2.nxv4i32",
				"@llvm.aarch64.sve.uqcvtn.x2.nxv4i32",
				"@llvm.aarch64.sve.sqrshrn.x2.nxv4i32",
				"@llvm.aarch64.sve.sqrshrun.x2.nxv4i32",
				"@llvm.aarch64.sve.uqrshrn.x2.nxv4i32",
				"sext <vscale x 8 x i16>",
				"zext <vscale x 8 x i16>",
				"icmp slt <vscale x 8 x i32>",
				"icmp ugt <vscale x 8 x i32>",
				"@llvm.vector.interleave2.nxv16i8",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s multi-vector narrow lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-multi-narrow.ll", "arm64-sve-multi-narrow.o", ll)
		})
	}
}

func TestTranslateARM64SVEMultiNarrowRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSQCVTN [Z1.S-Z2.S], Z3.H",
		"ZSQCVTUN [Z2.S, Z3.S], Z4.H",
		"ZUQCVTN [Z2.H-Z3.H], Z4.B",
		"ZSQRSHRN $0, [Z2.H-Z3.H], Z4.B",
		"ZSQRSHRN $9, [Z2.H-Z3.H], Z4.B",
		"ZSQRSHRUN $17, [Z2.S-Z3.S], Z4.H",
		"ZUQRSHRN $1, [Z2.D-Z3.D], Z4.S",
		"ZUQRSHRN $1, [Z2.H-Z5.H], Z6.B",
		"ZUQRSHRN.Z $1, [Z2.H-Z3.H], Z4.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemultinarrow(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemultinarrow": {Name: "badsvemultinarrow", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's multi-vector narrowing forms", instruction)
			}
		})
	}
}
