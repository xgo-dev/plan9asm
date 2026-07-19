//go:build !llgo
// +build !llgo

package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64BranchMinus(t *testing.T) {
	src := `
TEXT branchminus(SB),NOSPLIT,$0-0
loop:
	SUBS $32, R2
	BMI complete
	SUBS $32, R2
	BPL loop
complete:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"branchminus": {Name: "branchminus", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "br i1") {
		t.Fatalf("BMI did not lower to a conditional branch:\n%s", ll)
	}
}

func TestTranslateARM64RawFlagWords(t *testing.T) {
	src := `
TEXT rawflags(SB),NOSPLIT,$0-0
	MOVD $2, R0
	WORD $0xea00001f // TST X0, X0
	BEQ done
loop:
	WORD $0xf1000400 // SUBS X0, X0, #1
	BNE loop
done:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawflags": {Name: "rawflags", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "sub i64") || strings.Count(ll, "br i1") != 2 {
		t.Fatalf("raw TST/SUBS flag words did not lower as expected:\n%s", ll)
	}
}

func TestTranslateARM64TST(t *testing.T) {
	src := `
TEXT testflags(SB),NOSPLIT,$0-0
	MOVD $1, R0
	TST R0, R0
	BEQ done
done:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"testflags": {Name: "testflags", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "and i64") || !strings.Contains(ll, "br i1") {
		t.Fatalf("TST did not lower to flags and a conditional branch:\n%s", ll)
	}
}

func TestTranslateARM64FLDPQ(t *testing.T) {
	src := `
TEXT pairload(SB),NOSPLIT,$0-0
	MOVD $4096, R1
	FLDPQ (R1), (F0, F1)
	VMOVI $7, V2.B16
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"pairload": {Name: "pairload", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ll, "load <16 x i8>") != 2 || !strings.Contains(ll, "store <16 x i8>") || !strings.Contains(ll, "i8 7") {
		t.Fatalf("FLDPQ/VMOVI did not lower as expected:\n%s", ll)
	}
}

func TestTranslateARM64SHA3Families(t *testing.T) {
	src := `
TEXT sha3ops(SB),NOSPLIT,$0-0
	VEOR3	V20.B16, V15.B16, V10.B16, V25.B16
	VRAX1	V27.D2, V25.D2, V30.D2
	VXAR	$63, V30.D2, V1.D2, V25.D2
	VBCAX	V8.B16, V22.B16, V26.B16, V20.B16
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"sha3ops": {Name: "sha3ops", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64BarrierFamilies(t *testing.T) {
	src := `
TEXT barrierops(SB),NOSPLIT,$0-0
	DSB $7
	ISB $15
	DC ZVA, R0
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"barrierops": {Name: "barrierops", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64FeatureProbeMRS(t *testing.T) {
	src := `
TEXT featureprobe(SB),NOSPLIT,$0-0
	MRS ID_AA64ISAR0_EL1, R0
	MRS ID_AA64PFR0_EL1, R1
	MRS ID_AA64ZFR0_EL1, R2
	MRS MIDR_EL1, R3
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"featureprobe": {Name: "featureprobe", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64CompareWithExtendedRegister(t *testing.T) {
	src := `
TEXT countcmp(SB),NOSPLIT,$0-0
	CMP	R2.UXTB, R5
	CINC	EQ, R11, R11
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"countcmp": {Name: "countcmp", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}
