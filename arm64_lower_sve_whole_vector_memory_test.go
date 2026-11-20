package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEWholeVectorMemoryCompleteGo127Family(t *testing.T) {
	const source = `
TEXT svewholevectormemoryforms(SB),$0-0
	ZLDR (-VL*256)(R0), Z0
	ZLDR (VL*255)(RSP), Z31
	ZSTR Z30, (-VL*256)(R1)
	ZSTR Z1, (VL*255)(ZR)
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svewholevectormemoryforms": {Name: "svewholevectormemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve"`, "load <vscale x 16 x i8>", "store <vscale x 16 x i8>", "@llvm.vscale.i64()"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE whole-vector memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-whole-vector-memory.ll", "arm64-sve-whole-vector-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVEWholeVectorMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLDR (-VL*257)(R0), Z1",
		"ZLDR (VL*256)(R0), Z1",
		"ZLDR (VL*1)(R0), Z1.B",
		"ZSTR Z1.B, (VL*1)(R0)",
		"ZSTR Z32, (VL*1)(R0)",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvewholevectormemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvewholevectormemory": {Name: "badsvewholevectormemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE whole-vector memory forms", instruction)
			}
		})
	}
}
