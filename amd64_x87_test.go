//go:build !llgo

package plan9asm

import (
	"go/token"
	"go/types"
	"runtime"
	"strings"
	"testing"
)

// TestTranslateAMD64X87 verifies that x87 instructions encoded by Go's amd64
// assembler (FADDD, FSQRT, FLD1, FMOVDP, etc.) translate cleanly on GOARCH=amd64
// in both X87Hardware (native x86_64 codegen via llc) and X87Software (portable
// host execution) modes.
func TestTranslateAMD64X87(t *testing.T) {
	src := `
TEXT ·x87SqrtSum(SB),NOSPLIT,$0-24
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FADDD F1, F0
	FSQRT
	FMOVDP F0, ret+16(FP)
	FMOVDP F0, F0
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	f64 := LLVMType("double")
	sig := FuncSig{
		Name: "x87SqrtSum",
		Args: []LLVMType{f64, f64},
		Ret:  f64,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: f64, Index: 0, Field: -1},
				{Offset: 8, Type: f64, Index: 1, Field: -1},
			},
			Results: []FrameSlot{
				{Offset: 16, Type: f64, Index: 0},
			},
		},
	}

	// 1. Hardware x87 lowering on amd64 -> verify with opt + x86_64 llc.
	hwIR, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		X87Mode:      X87Hardware,
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"x87SqrtSum": sig},
	})
	if err != nil {
		t.Fatalf("Translate(amd64, X87Hardware) failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, hwIR, "x86_64-unknown-linux-gnu")

	// 2. Software x87 lowering on amd64 -> compile and execute on host!
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	swIR, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		X87Mode:      X87Software,
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"x87SqrtSum": sig},
	})
	if err != nil {
		t.Fatalf("Translate(amd64, X87Software) failed: %v", err)
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	mainC := `
#include <stdio.h>
extern double x87SqrtSum(double a, double b);
int main(void) {
    double got = x87SqrtSum(1.5, 2.5);
    if (got != 2.0) {
        fprintf(stderr, "x87SqrtSum(1.5, 2.5) = %.17g, want 2.0\n", got);
        return 1;
    }
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "amd64_x87_sw", triple, swIR, mainC, nil)
}

// TestTranslateGoModuleAMD64RejectsUnreachableResultInit ensures the Go module
// integration boundary rejects functions whose result slot write is skipped by
// control flow (e.g. JMP over MOVQ $1, ret+0(FP)) or only partially initializes
// a multi-byte result slot.
func TestTranslateGoModuleAMD64RejectsUnreachableResultInit(t *testing.T) {
	pkg := types.NewPackage("example.com/abi0cfg", "abi0cfg")
	res := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", types.Typ[types.Int64]))
	fn := types.NewFunc(token.NoPos, pkg, "f", types.NewSignatureType(nil, nil, nil, nil, res, false))
	pkg.Scope().Insert(fn)
	pkg.MarkComplete()

	gp := GoPackage{Path: pkg.Path(), Types: pkg}
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{
			name: "jmp skips result write",
			body: "JMP done\nMOVQ $1, ret+0(FP)\ndone:\nRET\n",
			ok:   false,
		},
		{
			name: "partial 1-byte write for i64 result",
			body: "MOVB $1, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "diamond initializes all bytes on both paths",
			body: "MOVQ $0, AX\nTESTQ AX, AX\nJE zero\nMOVQ $1, ret+0(FP)\nJMP done\nzero:\nMOVQ $2, ret+0(FP)\ndone:\nRET\n",
			ok:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Direct ABI0 result-initialization prover (non-physical $0-8 frame).
			directSrc := "TEXT ·f(SB),NOSPLIT,$0-8\n" + tc.body
			file, err := Parse(ArchAMD64, directSrc)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			sig := FuncSig{
				Name:  "example.com/abi0cfg.f",
				Ret:   I64,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
			}
			err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
			if tc.ok && err != nil {
				t.Fatalf("CheckX86ABI0ResultInitialization expected success, got: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("CheckX86ABI0ResultInitialization expected error for %s, got nil", tc.name)
			}

			// 2. End-to-end TranslateGoModule boundary on physical-frame ($16-8) function.
			physSrc := []byte("TEXT ·f(SB),NOSPLIT,$16-8\nMOVQ $0, 0(SP)\n" + tc.body)
			tr, err := TranslateGoModule(gp, physSrc, GoModuleOptions{
				GOOS:         "linux",
				GOARCH:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
			})
			if tr != nil {
				tr.Module.Dispose()
			}
			if tc.ok && err != nil {
				t.Fatalf("TranslateGoModule expected success, got: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("TranslateGoModule expected error for %s, got nil", tc.name)
			}
		})
	}
}
