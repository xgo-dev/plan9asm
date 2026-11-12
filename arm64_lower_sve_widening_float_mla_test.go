package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEWideningFloatMLACompleteGo127Family(t *testing.T) {
	const source = `TEXT svefmlhalf(SB),$0-0
	ZFMLALB Z0.H, Z1.H, Z2.S
	ZFMLALB Z7.H[7], Z3.H, Z4.S
	ZFMLALT Z5.H, Z6.H, Z7.S
	ZFMLALT Z0.H[0], Z8.H, Z9.S
	ZFMLSLB Z10.H, Z11.H, Z12.S
	ZFMLSLB Z7.H[7], Z13.H, Z14.S
	ZFMLSLT Z15.H, Z16.H, Z17.S
	ZFMLSLT Z0.H[0], Z18.H, Z19.S
	RET
TEXT svefmlfp8(SB),$0-0
	ZFMLALB Z20.B, Z21.B, Z22.H
	ZFMLALB Z7.B[15], Z23.B, Z24.H
	ZFMLALT Z25.B, Z26.B, Z27.H
	ZFMLALT Z0.B[0], Z28.B, Z29.H
	ZFMLALLBB Z1.B, Z2.B, Z3.S
	ZFMLALLBB Z7.B[15], Z4.B, Z5.S
	ZFMLALLBT Z6.B, Z7.B, Z8.S
	ZFMLALLBT Z0.B[0], Z9.B, Z10.S
	ZFMLALLTB Z11.B, Z12.B, Z13.S
	ZFMLALLTB Z7.B[15], Z14.B, Z15.S
	ZFMLALLTT Z16.B, Z17.B, Z18.S
	ZFMLALLTT Z0.B[0], Z19.B, Z20.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{
				"svefmlhalf": {Name: "svefmlhalf", Ret: Void},
				"svefmlfp8":  {Name: "svefmlfp8", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				`"target-features"="+fp8,+ssve-fp8fma,+sve,+sve2,+sve2p2"`,
				"@llvm.aarch64.sve.fmlalb.nxv4f32",
				"@llvm.aarch64.sve.fmlalb.lane.nxv4f32",
				"@llvm.aarch64.sve.fmlalt.nxv4f32",
				"@llvm.aarch64.sve.fmlalt.lane.nxv4f32",
				"@llvm.aarch64.sve.fmlslb.nxv4f32",
				"@llvm.aarch64.sve.fmlslb.lane.nxv4f32",
				"@llvm.aarch64.sve.fmlslt.nxv4f32",
				"@llvm.aarch64.sve.fmlslt.lane.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlalb.nxv8f16",
				"@llvm.aarch64.sve.fp8.fmlalb.lane.nxv8f16",
				"@llvm.aarch64.sve.fp8.fmlalt.nxv8f16",
				"@llvm.aarch64.sve.fp8.fmlalt.lane.nxv8f16",
				"@llvm.aarch64.sve.fp8.fmlallbb.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlallbb.lane.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlallbt.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlallbt.lane.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlalltb.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlalltb.lane.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlalltt.nxv4f32",
				"@llvm.aarch64.sve.fp8.fmlalltt.lane.nxv4f32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s widening floating MLA lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-widening-fml.ll", "arm64-sve-widening-fml.o", ll)
		})
	}
}

func TestTranslateARM64SVEWideningFloatMLARejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFMLALB Z8.H[0], Z2.H, Z3.S",
		"ZFMLALT Z7.H[8], Z2.H, Z3.S",
		"ZFMLSLB Z1.B, Z2.B, Z3.H",
		"ZFMLSLT Z1.H, Z2.H, Z3.H",
		"ZFMLALB Z8.B[0], Z2.B, Z3.H",
		"ZFMLALT Z7.B[16], Z2.B, Z3.H",
		"ZFMLALLBB Z8.B[0], Z2.B, Z3.S",
		"ZFMLALLBT Z7.B[16], Z2.B, Z3.S",
		"ZFMLALLTB Z1.B, Z2.H, Z3.S",
		"ZFMLALLTT Z1.B, Z2.B, Z3.H",
		"ZFMLALB.Z Z1.H, Z2.H, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefml(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefml": {Name: "badsvefml", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's widening floating MLA forms", instruction)
			}
		})
	}
}
