package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMMOVMPushPop(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·f(SB),NOSPLIT,$0-0
	MOVM.DB.W [R0,R1], (R13)
	MOVM.IA.W (R13), [R0,R1]
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.f": {Name: "example.f", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{"store i32", "load i32", "%reg_R13"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMSWI(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·raw(SB),NOSPLIT,$0-0
	MOVW $1, R7
	MOVW $2, R0
	SWI $0
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.raw": {Name: "example.raw", Ret: I32},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if !strings.Contains(ll, ".inst 0xef000000") {
		t.Fatalf("missing syscall call in output:\n%s", ll)
	}
}

func TestTranslateARMMOVDFloatSaveRestore(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·f(SB),NOSPLIT,$0-0
	MOVD F0, 8(R13)
	MOVD 8(R13), F1
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.f": {Name: "example.f", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{"%freg_F0 = alloca i64", "store i64", "load i64"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMMullu(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·mul(SB),NOSPLIT,$0-0
	MULLU R1, R0, (R2, R3)
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.mul": {Name: "example.mul", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{"mul i64", "lshr i64", "store i32"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
