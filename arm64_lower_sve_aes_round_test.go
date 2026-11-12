package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEAESRoundCompleteGo127Family(t *testing.T) {
	const source = `
TEXT sveaessingle(SB),$0-0
	ZAESD Z1.B, Z2.B, Z2.B
	ZAESE Z3.B, Z4.B, Z4.B
	RET
TEXT sveaesmulti(SB),$0-0
	ZAESD Z5.Q[0], [Z6.B-Z7.B], [Z6.B-Z7.B]
	ZAESD Z31.Q[3], [Z28.B-Z31.B], [Z28.B-Z31.B]
	ZAESDIMC Z8.Q[1], [Z10.B-Z11.B], [Z10.B-Z11.B]
	ZAESDIMC Z9.Q[2], [Z24.B-Z27.B], [Z24.B-Z27.B]
	ZAESE Z10.Q[3], [Z12.B-Z13.B], [Z12.B-Z13.B]
	ZAESE Z11.Q[0], [Z20.B-Z23.B], [Z20.B-Z23.B]
	ZAESEMC Z12.Q[2], [Z14.B-Z15.B], [Z14.B-Z15.B]
	ZAESEMC Z13.Q[1], [Z16.B-Z19.B], [Z16.B-Z19.B]
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"sveaessingle": {Name: "sveaessingle", Ret: Void},
		"sveaesmulti":  {Name: "sveaesmulti", Ret: Void},
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve2-aes"`,
				`"target-features"="+sve,+sve-aes2"`,
				"@llvm.aarch64.sve.aesd(",
				"@llvm.aarch64.sve.aese(",
				"@llvm.aarch64.sve.aesd.lane.x2",
				"@llvm.aarch64.sve.aesd.lane.x4",
				"@llvm.aarch64.sve.aesdimc.lane.x2",
				"@llvm.aarch64.sve.aesdimc.lane.x4",
				"@llvm.aarch64.sve.aese.lane.x2",
				"@llvm.aarch64.sve.aese.lane.x4",
				"@llvm.aarch64.sve.aesemc.lane.x2",
				"@llvm.aarch64.sve.aesemc.lane.x4",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE AES round lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-aes-round.ll", "arm64-sve-aes-round.o", ll)
		})
	}
}

func TestTranslateARM64SVEAESRoundRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZAESD Z1.B, Z2.B, Z3.B",
		"ZAESE Z1.H, Z2.H, Z2.H",
		"ZAESDIMC Z1.B, Z2.B, Z2.B",
		"ZAESD Z1.Q[4], [Z2.B-Z3.B], [Z2.B-Z3.B]",
		"ZAESE Z1.Q[0], [Z1.B-Z2.B], [Z1.B-Z2.B]",
		"ZAESDIMC Z1.Q[0], [Z4.B-Z6.B], [Z4.B-Z6.B]",
		"ZAESEMC Z1.Q[0], [Z4.B-Z5.B], [Z6.B-Z7.B]",
		"ZAESD Z1.Q[0], [Z4.B, Z5.B], [Z4.B, Z5.B]",
		"ZAESE.Z Z1.B, Z2.B, Z2.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_", "[", "", "]", "").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveaesround(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveaesround": {Name: "badsveaesround", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE AES round forms", instruction)
			}
		})
	}
}
