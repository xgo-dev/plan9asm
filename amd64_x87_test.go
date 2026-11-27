//go:build !llgo

package plan9asm

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math"
	"os"
	"os/exec"
	"path/filepath"
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

	// 2. Software x87 lowering on amd64: without FINIT/FLDCW it must reject
	// uninitialized CW, and with FINIT it compiles and executes identically on host!
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		X87Mode:      X87Software,
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"x87SqrtSum": sig},
	}); err == nil {
		t.Fatalf("Translate(amd64, X87Software) without FINIT/FLDCW unexpectedly succeeded")
	}
	swSrc := strings.Replace(src, "\tFMOVD a+0(FP), F0", "\tFINIT\n\tFMOVD a+0(FP), F0", 1)
	swFile, err := Parse(ArchAMD64, swSrc)
	if err != nil {
		t.Fatalf("Parse(sw) failed: %v", err)
	}
	swIR, err := Translate(swFile, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		X87Mode:      X87Software,
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"x87SqrtSum": sig},
	})
	if err != nil {
		t.Fatalf("Translate(amd64, X87Software, with FINIT) failed: %v", err)
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	mainC := `
#include <stdio.h>
#if defined(_WIN32) && !defined(_MSC_VER)
int _fltused = 0;
#endif
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

// TestTranslateGoModuleAMD64RejectsUnreachableResultInit ensures BOTH the
// public ABI0 checker and TranslateGoModule enforce CFG + byte-level register,
// stack-slot, and FP initialization on BOTH ordinary ($0-8, no SP access) and
// physical-frame ($16-8) amd64 ABI0 functions.
func TestTranslateGoModuleAMD64RejectsUnreachableResultInit(t *testing.T) {
	pkg := types.NewPackage("example.com/abi0cfg", "abi0cfg")
	res := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", types.Typ[types.Int64]))
	fn := types.NewFunc(token.NoPos, pkg, "f", types.NewSignatureType(nil, nil, nil, nil, res, false))
	pkg.Scope().Insert(fn)
	pkg.MarkComplete()

	gp := GoPackage{Path: pkg.Path(), Types: pkg}
	sig := FuncSig{
		Name:  "example.com/abi0cfg.f",
		Ret:   I64,
		Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
	}

	cases := []struct {
		name         string
		body         string
		ordinaryOnly bool
		physicalOnly bool
		ok           bool
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
			name: "MOVB AL then MOVQ AX read",
			body: "MOVB $1, AL\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name:         "MOVB 0(SP) then MOVQ 0(SP) read",
			body:         "MOVB $1, 0(SP)\nMOVQ 0(SP), AX\nMOVQ AX, ret+0(FP)\nRET\n",
			physicalOnly: true,
			ok:           false,
		},
		{
			name: "MOVB ret+0(FP) then MOVQ ret+0(FP) read",
			body: "MOVB $1, ret+0(FP)\nMOVQ ret+0(FP), AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "diamond initializes all bytes on both paths",
			body: "MOVQ $0, AX\nTESTQ AX, AX\nJE zero\nMOVQ $1, ret+0(FP)\nJMP done\nzero:\nMOVQ $2, ret+0(FP)\ndone:\nRET\n",
			ok:   true,
		},
		{
			name: "MOVL zero-extends to 64-bit AX",
			body: "MOVL $42, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "dead scratch ADDQ DI (hash/crc32 ieeeCLMUL idiom)",
			body: "ADDQ $0x40, DI\nMOVQ $42, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "TESTQ uninit AX clears CF/OF for ADCXQ (math/big idiom)",
			body: "MOVQ $40, BX\nMOVQ $2, CX\nTESTQ AX, AX\nADCXQ CX, BX\nMOVQ BX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "STC sets CF only so ADCXQ succeeds",
			body: "MOVQ $40, AX\nMOVQ $2, BX\nSTC\nADCXQ BX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "STC does not initialize OF so ADOXQ is rejected",
			body: "MOVQ $40, AX\nMOVQ $2, BX\nSTC\nADOXQ BX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "CLC does not initialize OF so ADOXQ is rejected",
			body: "MOVQ $40, AX\nMOVQ $2, BX\nCLC\nADOXQ BX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "INCQ sets OF only so ADOXQ succeeds",
			body: "MOVQ $40, AX\nMOVQ $2, BX\nINCQ BX\nADOXQ BX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "INCQ preserves uninit CF so ADCXQ is rejected",
			body: "MOVQ $40, AX\nMOVQ $2, BX\nINCQ BX\nADCXQ BX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "MOVB AL then MOVL AX->BX then MOVQ BX",
			body: "MOVB $1, AL\nMOVL AX, BX\nMOVQ BX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "SHLQ $0 does not initialize CF (SETCS rejected)",
			body: "MOVQ $1, AX\nSHLQ $0, AX\nSETCS AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "SHLQ $64 masked count 0 does not initialize CF (SETCS rejected)",
			body: "MOVQ $1, AX\nSHLQ $64, AX\nSETCS AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "SHLL $32 masked count 0 does not initialize CF (SETCS rejected)",
			body: "MOVL $1, AX\nSHLL $32, AX\nSETCS AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "SHLQ $0 preserves defined OF for ADOXQ",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nSHLQ $0, AX\nADOXQ AX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "SHLQ $64 masked count 0 preserves defined OF for ADOXQ",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nSHLQ $64, AX\nADOXQ AX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "SHLQ $2 invalidates OF for ADOXQ",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nSHLQ $2, AX\nADOXQ AX, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "BTQ preserves ZF so SETEQ succeeds",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nBTQ $0, AX\nSETEQ AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "BTQ leaves SF undefined so SETS is rejected",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nBTQ $0, AX\nSETS AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "BTQ leaves OF undefined so SETO is rejected",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nBTQ $0, AX\nSETO AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "JE at function entry reads uninitialized ZF (rejected)",
			body: "JE alt\nMOVQ $1, ret+0(FP)\nRET\nalt:\nMOVQ $2, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "STC then JO reads uninitialized OF (rejected)",
			body: "STC\nJO alt\nMOVQ $1, ret+0(FP)\nRET\nalt:\nMOVQ $2, ret+0(FP)\nRET\n",
			ok:   false,
		},
		{
			name: "STC then JC reads initialized CF (accepted)",
			body: "STC\nJC alt\nMOVQ $1, ret+0(FP)\nRET\nalt:\nMOVQ $2, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "CMPQ then BTQ then JE reads preserved ZF (accepted)",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nBTQ $0, AX\nJE alt\nMOVQ $1, ret+0(FP)\nRET\nalt:\nMOVQ $2, ret+0(FP)\nRET\n",
			ok:   true,
		},
		{
			name: "CMPQ then BTQ then JL reads undefined SF/OF (rejected)",
			body: "MOVQ $1, AX\nCMPQ AX, AX\nBTQ $0, AX\nJL alt\nMOVQ $1, ret+0(FP)\nRET\nalt:\nMOVQ $2, ret+0(FP)\nRET\n",
			ok:   false,
		},
	}

	checkBoth := func(t *testing.T, label, header, body string, wantOK bool) {
		t.Helper()
		fullSrc := header + "\n" + body
		file, err := Parse(ArchAMD64, fullSrc)
		if err != nil {
			t.Fatalf("%s: Parse failed: %v", label, err)
		}
		err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
		if wantOK && err != nil {
			t.Fatalf("%s: CheckX86ABI0ResultInitialization expected success, got: %v", label, err)
		}
		if !wantOK && err == nil {
			t.Fatalf("%s: CheckX86ABI0ResultInitialization expected error, got nil", label)
		}

		tr, err := TranslateGoModule(gp, []byte(fullSrc), GoModuleOptions{
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
		})
		if tr != nil {
			tr.Module.Dispose()
		}
		if wantOK && err != nil {
			t.Fatalf("%s: TranslateGoModule expected success, got: %v", label, err)
		}
		if !wantOK && err == nil {
			t.Fatalf("%s: TranslateGoModule expected error, got nil", label)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.physicalOnly {
				checkBoth(t, "ordinary-$0-8", "TEXT ·f(SB),NOSPLIT,$0-8", tc.body, tc.ok)
			}
			if !tc.ordinaryOnly {
				body := tc.body
				if !strings.Contains(body, "(SP)") {
					body = "MOVQ $0, 8(SP)\n" + body
				}
				checkBoth(t, "physical-$16-8", "TEXT ·f(SB),NOSPLIT,$16-8", body, tc.ok)
			}
		})
	}
}

// TestTranslateGoModuleAMD64ABI0CallResultSemantics verifies that outgoing ABI0
// CALLs in TranslateGoModule:
//  1. Mark stack result slots initialized AND emit the stack store on (SP) even
//     for zero-parameter callees (e.g. g() int64, pair() (int64, int64), f64() float64,
//     flag() bool), verified end-to-end under LLVM 22 -O2 so caller folds to the
//     exact return value rather than undef.
//  2. Do NOT fabricate AX initialization after calling a void or ABI0-stack-return callee.
//  3. Reject callers that omit required outgoing ABI0 parameter bytes or rely on AX
//     surviving across an ABI0 CALL.
func TestTranslateGoModuleAMD64ABI0CallResultSemantics(t *testing.T) {
	pkg := types.NewPackage("example.com/abi0call", "abi0call")
	i64 := types.Typ[types.Int64]
	f64 := types.Typ[types.Float64]
	boolTy := types.Typ[types.Bool]
	resI64 := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", i64))
	resPair := types.NewTuple(
		types.NewVar(token.NoPos, pkg, "a", i64),
		types.NewVar(token.NoPos, pkg, "b", i64),
	)
	resF64 := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", f64))
	resBool := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", boolTy))
	argI64 := types.NewTuple(types.NewVar(token.NoPos, pkg, "x", i64))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "caller", types.NewSignatureType(nil, nil, nil, nil, resI64, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "g", types.NewSignatureType(nil, nil, nil, nil, resI64, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "pair", types.NewSignatureType(nil, nil, nil, nil, resPair, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "getf", types.NewSignatureType(nil, nil, nil, nil, resF64, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "getb", types.NewSignatureType(nil, nil, nil, nil, resBool, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "noop", types.NewSignatureType(nil, nil, nil, nil, nil, false)))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "inc", types.NewSignatureType(nil, nil, nil, argI64, resI64, false)))
	pkg.MarkComplete()

	gp := GoPackage{Path: pkg.Path(), Types: pkg}

	optimizeIR := func(t *testing.T, ir string) string {
		t.Helper()
		opt := findLLVM22Tool("opt")
		if opt == "" {
			t.Fatal("LLVM 22 opt not found")
		}
		cmd := exec.Command(opt, "-passes=default<O2>", "-S", "-")
		cmd.Stdin = strings.NewReader(ir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("opt -O2 failed: %v\n%s\nIR:\n%s", err, out, ir)
		}
		return string(out)
	}

	cases := []struct {
		name      string
		src       string
		ok        bool
		wantO2Ret string
	}{
		{
			name: "zero-param callee g() int64 initializes and writes 0(SP)",
			src: `TEXT ·g(SB),NOSPLIT,$0-8
	MOVQ $42, ret+0(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$8-8
	CALL ·g(SB)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok:        true,
			wantO2Ret: "ret i64 42",
		},
		{
			name: "zero-param multi-return callee pair() (int64, int64) writes 0(SP) and 8(SP)",
			src: `TEXT ·pair(SB),NOSPLIT,$0-16
	MOVQ $13, a+0(FP)
	MOVQ $29, b+8(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$16-8
	CALL ·pair(SB)
	MOVQ 0(SP), AX
	ADDQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok:        true,
			wantO2Ret: "ret i64 42",
		},
		{
			name: "zero-param float64 callee getf() float64 writes 0(SP)",
			src: `TEXT ·getf(SB),NOSPLIT,$0-8
	MOVQ $0x4045000000000000, AX
	MOVQ AX, X0
	MOVSD X0, ret+0(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$8-8
	CALL ·getf(SB)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok:        true,
			wantO2Ret: "ret i64 4631107791820423168",
		},
		{
			name: "zero-param bool callee getb() bool writes 0(SP)",
			src: `TEXT ·getb(SB),NOSPLIT,$0-1
	MOVB $1, ret+0(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$8-8
	CALL ·getb(SB)
	MOVBQZX 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok:        true,
			wantO2Ret: "ret i64 1",
		},
		{
			name: "zero-param callee g() int64 does not initialize AX",
			src: `TEXT ·g(SB),NOSPLIT,$0-8
	MOVQ $42, ret+0(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$8-8
	CALL ·g(SB)
	MOVQ AX, ret+0(FP)
	RET
`,
			ok: false,
		},
		{
			name: "void callee noop() does not initialize AX",
			src: `TEXT ·noop(SB),NOSPLIT,$0-0
	RET
TEXT ·caller(SB),NOSPLIT,$0-8
	CALL ·noop(SB)
	MOVQ AX, ret+0(FP)
	RET
`,
			ok: false,
		},
		{
			name: "void callee noop() clobbers prior AX",
			src: `TEXT ·noop(SB),NOSPLIT,$0-0
	RET
TEXT ·caller(SB),NOSPLIT,$0-8
	MOVQ $7, AX
	CALL ·noop(SB)
	MOVQ AX, ret+0(FP)
	RET
`,
			ok: false,
		},
		{
			name: "void callee noop() does not initialize 0(SP)",
			src: `TEXT ·noop(SB),NOSPLIT,$0-0
	RET
TEXT ·caller(SB),NOSPLIT,$8-8
	CALL ·noop(SB)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok: false,
		},
		{
			name: "one-param callee inc(x) int64 checks 0(SP) and writes 8(SP)",
			src: `TEXT ·inc(SB),NOSPLIT,$0-16
	MOVQ x+0(FP), AX
	ADDQ $1, AX
	MOVQ AX, ret+8(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$16-8
	MOVQ $41, 0(SP)
	CALL ·inc(SB)
	MOVQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok:        true,
			wantO2Ret: "ret i64 42",
		},
		{
			name: "one-param callee inc(x) int64 rejects uninitialized 0(SP) arg",
			src: `TEXT ·inc(SB),NOSPLIT,$0-16
	MOVQ x+0(FP), AX
	ADDQ $1, AX
	MOVQ AX, ret+8(FP)
	RET
TEXT ·caller(SB),NOSPLIT,$16-8
	CALL ·inc(SB)
	MOVQ 8(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
			ok: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TranslateGoModule(gp, []byte(tc.src), GoModuleOptions{
				GOOS:         "linux",
				GOARCH:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
			})
			var ir string
			if tr != nil {
				ir = tr.Module.String()
				tr.Module.Dispose()
			}
			if tc.ok && err != nil {
				t.Fatalf("TranslateGoModule expected success, got: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("TranslateGoModule expected error, got nil")
			}
			if tc.ok && tc.wantO2Ret != "" {
				verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")
				optIR := optimizeIR(t, ir)
				idx := strings.Index(optIR, `@"\C2\B7caller"`)
				if idx < 0 {
					idx = strings.Index(optIR, `@"example.com/abi0call.caller"`)
				}
				if idx < 0 {
					t.Fatalf("optimized IR missing caller definition:\n%s", optIR)
				}
				callerIR := optIR[idx:]
				if end := strings.Index(callerIR, "\n}"); end >= 0 {
					callerIR = callerIR[:end+2]
				}
				if strings.Contains(callerIR, "undef") || strings.Contains(callerIR, "poison") {
					t.Fatalf("caller optimized to undef/poison:\n%s\nraw IR:\n%s", callerIR, ir)
				}
				if !strings.Contains(callerIR, tc.wantO2Ret) {
					t.Fatalf("caller -O2 IR missing %q:\n%s\nraw IR:\n%s", tc.wantO2Ret, callerIR, ir)
				}
			}
		})
	}
}

// TestTranslateGoModuleAMD64ShiftZeroAndBTFlagSemantics verifies under LLVM 22
// -O2 that effective-count-zero shifts preserve OF and BTQ preserves ZF in the
// lowered LLVM IR (not only in static checking).
func TestTranslateGoModuleAMD64ShiftZeroAndBTFlagSemantics(t *testing.T) {
	pkg := types.NewPackage("example.com/flagsem", "flagsem")
	i64 := types.Typ[types.Int64]
	resI64 := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", i64))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "f", types.NewSignatureType(nil, nil, nil, nil, resI64, false)))
	pkg.MarkComplete()
	gp := GoPackage{Path: pkg.Path(), Types: pkg}

	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}

	cases := []struct {
		name      string
		src       string
		wantO2Ret string
	}{
		{
			name: "SHLQ $0 preserves OF=0 from CMPQ AX, AX into ADOXQ",
			src: `TEXT ·f(SB),NOSPLIT,$0-8
	MOVQ $21, AX
	CMPQ AX, AX
	SHLQ $0, AX
	ADOXQ AX, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2Ret: "ret i64 42",
		},
		{
			name: "SHLQ $64 preserves OF=1 from signed overflow CMPQ into ADOXQ",
			src: `TEXT ·f(SB),NOSPLIT,$0-8
	MOVQ $-9223372036854775808, AX
	MOVQ $1, BX
	CMPQ AX, BX
	MOVQ $20, CX
	SHLQ $64, CX
	ADOXQ CX, CX
	MOVQ CX, ret+0(FP)
	RET
`,
			wantO2Ret: "ret i64 41",
		},
		{
			name: "BTQ preserves ZF=1 from CMPQ AX, AX into SETEQ and JE",
			src: `TEXT ·f(SB),NOSPLIT,$0-8
	MOVQ $1, AX
	CMPQ AX, AX
	BTQ $0, AX
	SETEQ AL
	MOVBQZX AL, AX
	JE taken
	MOVQ $0, ret+0(FP)
	RET
taken:
	ADDQ $41, AX
	MOVQ AX, ret+0(FP)
	RET
`,
			wantO2Ret: "ret i64 42",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TranslateGoModule(gp, []byte(tc.src), GoModuleOptions{
				GOOS:         "linux",
				GOARCH:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
			})
			if err != nil {
				t.Fatalf("TranslateGoModule failed: %v", err)
			}
			ir := tr.Module.String()
			tr.Module.Dispose()
			verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")
			cmd := exec.Command(opt, "-passes=default<O2>", "-S", "-")
			cmd.Stdin = strings.NewReader(ir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("opt -O2 failed: %v\n%s", err, out)
			}
			optIR := string(out)
			if !strings.Contains(optIR, tc.wantO2Ret) {
				t.Fatalf("optimized IR missing %q:\n%s\nraw IR:\n%s", tc.wantO2Ret, optIR, ir)
			}
		})
	}
}

// TestTranslateGoModuleAMD64FlagProducerConsumerMatrix verifies end-to-end
// architectural RFLAGS values (CF, OF, ZF, SF, PF) across flag-producing
// instructions and Jcc/SETcc/CMOVcc consumers under LLVM 22 -O2.
// Every case is verified against the architectural x86-64 result so any mismatch
// between static flag-init approval and lowered LLVM IR fails immediately.
func TestTranslateGoModuleAMD64FlagProducerConsumerMatrix(t *testing.T) {
	pkg := types.NewPackage("example.com/flagmatrix", "flagmatrix")
	i64 := types.Typ[types.Int64]
	resI64 := types.NewTuple(types.NewVar(token.NoPos, pkg, "ret", i64))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "f", types.NewSignatureType(nil, nil, nil, nil, resI64, false)))
	pkg.MarkComplete()
	gp := GoPackage{Path: pkg.Path(), Types: pkg}

	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}

	type consumerExpect struct {
		cc   string // Plan 9 condition suffix (e.g. PS, PC, MI, PL, LT, GE, LE, GT, CS, CC, OS, OC, EQ, NE)
		want int64  // 1 if condition holds, 0 otherwise
	}

	cases := []struct {
		name   string
		setup  string
		checks []consumerExpect
	}{
		// --- Five exact Round-5 review counterexamples ---
		{
			name:  "TESTQ AX=3 even parity (PF=1)",
			setup: "MOVQ $3, AX\nTESTQ AX, AX",
			checks: []consumerExpect{
				{"PS", 1}, {"PC", 0}, {"EQ", 0}, {"MI", 0}, {"LT", 0}, {"CS", 0}, {"OS", 0},
			},
		},
		{
			name:  "TESTQ AX=1 odd parity (PF=0)",
			setup: "MOVQ $1, AX\nTESTQ AX, AX",
			checks: []consumerExpect{
				{"PS", 0}, {"PC", 1}, {"EQ", 0}, {"MI", 0},
			},
		},
		{
			name:  "CMPQ MinInt64, 1 signed overflow (SF=0, OF=1 -> JMI=0, JLT=1)",
			setup: "MOVQ $-9223372036854775808, AX\nMOVQ $1, BX\nCMPQ AX, BX",
			checks: []consumerExpect{
				{"MI", 0}, {"PL", 1}, {"LT", 1}, {"GE", 0}, {"LE", 1}, {"GT", 0}, {"OS", 1}, {"OC", 0}, {"CS", 0}, {"PS", 1},
			},
		},
		{
			name:  "SHLQ $1 (1<<62) signed overflow (SF=1, OF=1, CF=0 -> JMI=1, JLT=0)",
			setup: "MOVQ $4611686018427387904, AX\nSHLQ $1, AX",
			checks: []consumerExpect{
				{"LT", 0}, {"GE", 1}, {"MI", 1}, {"PL", 0}, {"OS", 1}, {"CS", 0}, {"EQ", 0}, {"PS", 1},
			},
		},
		{
			name:  "CLC then ROLQ $1 MinInt64 sets CF=1 and OF=1",
			setup: "CLC\nMOVQ $-9223372036854775808, AX\nROLQ $1, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"CC", 0}, {"OS", 1},
			},
		},
		{
			name:  "CLC then SHLW $1 0x8000 sets CF=1, OF=1, ZF=1, PF=1, SF=0",
			setup: "CLC\nMOVQ $0x8000, AX\nSHLW $1, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"CC", 0}, {"EQ", 1}, {"OS", 1}, {"MI", 0}, {"LT", 1}, {"PS", 1},
			},
		},
		// --- Adjacent arithmetic / overflow / parity producers ---
		{
			name:  "ADDQ MaxInt64 + 1 sets OF=1, SF=1, CF=0, PF=1 -> JMI=1, JLT=0",
			setup: "MOVQ $9223372036854775807, AX\nADDQ $1, AX",
			checks: []consumerExpect{
				{"MI", 1}, {"LT", 0}, {"GE", 1}, {"OS", 1}, {"CS", 0}, {"PS", 1},
			},
		},
		{
			name:  "SUBQ MinInt64 - 1 sets OF=1, SF=0, CF=0, PF=1 -> JMI=0, JLT=1",
			setup: "MOVQ $-9223372036854775808, AX\nSUBQ $1, AX",
			checks: []consumerExpect{
				{"MI", 0}, {"LT", 1}, {"GE", 0}, {"OS", 1}, {"CS", 0}, {"PS", 1},
			},
		},
		{
			name:  "ADDL 0x7fffffff + 1 sets OF=1, SF=1 -> JLT=0, JMI=1",
			setup: "MOVL $0x7fffffff, AX\nADDL $1, AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"CS", 0},
			},
		},
		{
			name:  "ADDW 0x7fff + 1 sets OF=1, SF=1 -> JLT=0, JMI=1",
			setup: "MOVQ $0x7fff, AX\nADDW $1, AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"CS", 0},
			},
		},
		{
			name:  "ADDB 0x7f + 1 sets OF=1, SF=1, PF=0 -> JLT=0, JMI=1",
			setup: "MOVQ $0x7f, AX\nADDB $1, AL",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"PS", 0}, {"CS", 0},
			},
		},
		{
			name:  "ADCQ with STC on MaxInt64 + 0 sets OF=1, SF=1, CF=0 -> JLT=0",
			setup: "STC\nMOVQ $9223372036854775807, AX\nADCQ $0, AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"CS", 0},
			},
		},
		{
			name:  "SBBQ with STC on MinInt64 - 0 sets OF=1, SF=0, CF=0 -> JLT=1",
			setup: "STC\nMOVQ $-9223372036854775808, AX\nSBBQ $0, AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 0}, {"LT", 1}, {"CS", 0},
			},
		},
		{
			name:  "INCQ MaxInt64 sets OF=1, SF=1 and preserves CF=1",
			setup: "STC\nMOVQ $9223372036854775807, AX\nINCQ AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"CS", 1},
			},
		},
		{
			name:  "DECQ MinInt64 sets OF=1, SF=0 and preserves CF=0",
			setup: "CLC\nMOVQ $-9223372036854775808, AX\nDECQ AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 0}, {"LT", 1}, {"CS", 0},
			},
		},
		{
			name:  "NEGQ MinInt64 sets OF=1, CF=1, SF=1 -> JLT=0",
			setup: "MOVQ $-9223372036854775808, AX\nNEGQ AX",
			checks: []consumerExpect{
				{"OS", 1}, {"CS", 1}, {"MI", 1}, {"LT", 0},
			},
		},
		// --- Shifts, double shifts, and rotates across widths ---
		{
			name:  "SHLB $1 0x80 sets CF=1, ZF=1, OF=1, PF=1",
			setup: "CLC\nMOVQ $0x80, AX\nSHLB $1, AL",
			checks: []consumerExpect{
				{"CS", 1}, {"EQ", 1}, {"OS", 1}, {"PS", 1},
			},
		},
		{
			name:  "SHRB $1 0x81 sets CF=1, OF=1, SF=0, PF=0",
			setup: "CLC\nMOVQ $0x81, AX\nSHRB $1, AL",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1}, {"MI", 0}, {"LT", 1}, {"PS", 0},
			},
		},
		{
			name:  "SARB $1 0x81 sets CF=1, OF=0, SF=1, PF=1",
			setup: "CLC\nMOVQ $0x81, AX\nSARB $1, AL",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 0}, {"MI", 1}, {"LT", 1}, {"PS", 1},
			},
		},
		{
			name:  "SHLL $1 (1<<30) sets SF=1, OF=1, CF=0 -> JLT=0",
			setup: "MOVL $0x40000000, AX\nSHLL $1, AX",
			checks: []consumerExpect{
				{"MI", 1}, {"OS", 1}, {"LT", 0}, {"CS", 0},
			},
		},
		{
			name:  "ROLB/ROLW/ROLL $1 MSB=1 set CF=1",
			setup: "CLC\nMOVL $0x80000000, AX\nROLL $1, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1},
			},
		},
		{
			name:  "RORQ $1 LSB=1 sets CF=1, OF=1",
			setup: "CLC\nMOVQ $1, AX\nRORQ $1, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1},
			},
		},
		{
			name:  "RORW $1 LSB=1 sets CF=1, OF=1",
			setup: "CLC\nMOVQ $1, AX\nRORW $1, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1},
			},
		},
		{
			name:  "SHLQ 3-op (SHLDQ) $1 MinInt64 sets CF=1, OF=1, ZF=1",
			setup: "CLC\nMOVQ $-9223372036854775808, AX\nMOVQ $0, BX\nSHLQ $1, BX, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1}, {"EQ", 1}, {"MI", 0}, {"LT", 1},
			},
		},
		{
			name:  "SHLW 3-op (SHLDW) $1 0x8000 sets CF=1, OF=1, ZF=1",
			setup: "CLC\nMOVQ $0x8000, AX\nMOVQ $0, BX\nSHLW $1, BX, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1}, {"EQ", 1},
			},
		},
		{
			name:  "Dynamic CL=0 on SHLW preserves prior CF=1",
			setup: "STC\nMOVQ $0, CX\nMOVQ $0, AX\nSHLW CL, AX",
			checks: []consumerExpect{
				{"CS", 1},
			},
		},
		{
			name:  "Dynamic CL=1 on ROLQ MinInt64 sets CF=1",
			setup: "CLC\nMOVQ $1, CX\nMOVQ $-9223372036854775808, AX\nROLQ CL, AX",
			checks: []consumerExpect{
				{"CS", 1},
			},
		},
		{
			name:  "Dynamic CL=1 on SHRQ 3-op (SHRDQ) sets CF=1 and SF=1",
			setup: "MOVQ $1, AX\nTESTQ AX, AX\nMOVQ $1, CX\nMOVQ $1, BX\nSHRQ CL, BX, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"MI", 1}, {"EQ", 0}, {"PS", 1},
			},
		},
		{
			name:  "SHRQ 3-op (SHRDQ) $1 sets CF=1, OF=1, SF=1 -> JLT=0",
			setup: "CLC\nMOVQ $1, AX\nMOVQ $1, BX\nSHRQ $1, BX, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1}, {"MI", 1}, {"LT", 0},
			},
		},
		{
			name:  "ROLQ $0 and SHRQ $0 preserve prior CF=1",
			setup: "STC\nMOVQ $0, AX\nROLQ $0, AX\nSHRQ $0, AX",
			checks: []consumerExpect{
				{"CS", 1},
			},
		},
		{
			name:  "ADCW with STC on 0x7fff + 0 sets OF=1, SF=1, CF=0",
			setup: "STC\nMOVQ $0x7fff, AX\nADCW $0, AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"CS", 0},
			},
		},
		{
			name:  "INCW 0x7fff and INCB 0x7f set OF=1, SF=1",
			setup: "MOVQ $0x7fff, AX\nINCW AX",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0},
			},
		},
		{
			name:  "INCB 0x7f sets OF=1, SF=1, PF=0",
			setup: "MOVQ $0x7f, AX\nINCB AL",
			checks: []consumerExpect{
				{"OS", 1}, {"MI", 1}, {"LT", 0}, {"PS", 0},
			},
		},
		// --- MUL / IMUL / POPCNT / BMI1 / UCOMISD / LAHF+SAHF ---
		{
			name:  "MULQ overflow sets CF=1 and OF=1",
			setup: "MOVQ $4294967296, AX\nMOVQ $4294967296, BX\nMULQ BX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1},
			},
		},
		{
			name:  "IMULQ signed overflow sets CF=1 and OF=1",
			setup: "MOVQ $9223372036854775807, AX\nMOVQ $2, BX\nIMULQ BX, AX",
			checks: []consumerExpect{
				{"CS", 1}, {"OS", 1},
			},
		},
		{
			name:  "POPCNTQ nonzero clears CF/OF/SF/PF and ZF=0",
			setup: "STC\nMOVQ $3, AX\nPOPCNTQ AX, BX",
			checks: []consumerExpect{
				{"EQ", 0}, {"CS", 0}, {"OS", 0}, {"MI", 0}, {"PS", 0},
			},
		},
		{
			name:  "UCOMISD NaN sets PF=1, ZF=1, CF=1, OF=0, SF=0",
			setup: "MOVQ $0x7ff8000000000000, AX\nMOVQ AX, X0\nUCOMISD X0, X0",
			checks: []consumerExpect{
				{"PS", 1}, {"PC", 0}, {"EQ", 1}, {"CS", 1}, {"OS", 0}, {"MI", 0},
			},
		},
		{
			name:  "LAHF and SAHF preserve PF=1 and SF=1 across TESTQ",
			setup: "MOVQ $-2, AX\nTESTQ AX, AX\nLAHF\nMOVQ $1, BX\nTESTQ BX, BX\nSAHF",
			checks: []consumerExpect{
				// -2 low byte is 0xfe (7 ones -> PF=0), SF=1, ZF=0, CF=0
				{"MI", 1}, {"PS", 0}, {"EQ", 0}, {"CS", 0},
			},
		},
	}

	runAndCheck := func(t *testing.T, label, src string, want int64, verifyLLC bool) {
		t.Helper()
		tr, err := TranslateGoModule(gp, []byte(src), GoModuleOptions{
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
		})
		if err != nil {
			t.Fatalf("%s: TranslateGoModule failed: %v\nsrc:\n%s", label, err, src)
		}
		ir := tr.Module.String()
		tr.Module.Dispose()
		if verifyLLC {
			verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")
		}
		cmd := exec.Command(opt, "-passes=default<O2>", "-S", "-")
		cmd.Stdin = strings.NewReader(ir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: opt -O2 failed: %v\n%s", label, err, out)
		}
		optIR := string(out)
		wantRet := "ret i64 0"
		if want != 0 {
			wantRet = "ret i64 1"
		}
		if strings.Contains(optIR, " undef") || strings.Contains(optIR, " poison") {
			t.Fatalf("%s: optimized IR contains undef/poison:\n%s", label, optIR)
		}
		if !strings.Contains(optIR, wantRet) {
			t.Fatalf("%s: optimized IR missing %q:\n%s", label, wantRet, optIR)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for ci, chk := range tc.checks {
				// 1. Jcc consumer
				jccSrc := "TEXT ·f(SB),NOSPLIT,$0-8\n" + tc.setup + "\nJ" + chk.cc + " taken\nMOVQ $0, ret+0(FP)\nRET\ntaken:\nMOVQ $1, ret+0(FP)\nRET\n"
				runAndCheck(t, "J"+chk.cc, jccSrc, chk.want, ci == 0)

				// 2. SETcc consumer
				setSrc := "TEXT ·f(SB),NOSPLIT,$0-8\n" + tc.setup + "\nSET" + chk.cc + " AL\nMOVBQZX AL, AX\nMOVQ AX, ret+0(FP)\nRET\n"
				runAndCheck(t, "SET"+chk.cc, setSrc, chk.want, false)

				// 3. CMOVQcc consumer
				cmovSrc := "TEXT ·f(SB),NOSPLIT,$0-8\n" + tc.setup + "\nMOVQ $0, R8\nMOVQ $1, R9\nCMOVQ" + chk.cc + " R9, R8\nMOVQ R8, ret+0(FP)\nRET\n"
				runAndCheck(t, "CMOVQ"+chk.cc, cmovSrc, chk.want, false)
			}
		})
	}
}

// TestTranslateGoModuleAMD64X87StackAndConstants verifies Round 10 P1 #1 and P2 #3
// plus full x87 family closure:
//  1. All 7 FLD* constants (FLD1, FLDZ, FLDPI, FLDL2E, FLDL2T, FLDLG2, FLDLN2)
//     translate via public TranslateGoModule with exact 64-bit and 80-bit values.
//  2. FMOVD / FMOVDP across multiple stack depths and register aliases (including
//     the exact FLDZ; FLD1; FMOVD F1, F0 regression popping all 3 slots), 10-byte
//     FMOVB/FMOVBP BCD read/write, 80-bit arithmetic, and FUCOMI/FCOMI flags
//     (including OF/SF/AF clearing).
//  3. Portable X87Software execution verified on every host AND native X87Hardware
//     machine-code differential comparison against Go's native amd64 assembler on
//     amd64 hosts (mandatory when PLAN9ASM_REQUIRE_AMD64_DIFF=1), writing real
//     native-diff counts into PLAN9ASM_DIFF_REPORT_OUT.
func TestTranslateGoModuleAMD64X87StackAndConstants(t *testing.T) {
	requireDiff := os.Getenv("PLAN9ASM_REQUIRE_AMD64_DIFF") == "1"
	optTool := findLLVM22Tool("opt")
	if optTool == "" {
		t.Fatal("LLVM 22 opt is required for TestTranslateGoModuleAMD64X87StackAndConstants (check LLVM_CONFIG / PATH)")
	}
	llcTool, clangTool, haveTools := findLlcAndClang(t)
	if !haveTools {
		if requireDiff {
			t.Fatalf("PLAN9ASM_REQUIRE_AMD64_DIFF=1 requires LLVM 22 llc/clang (llc=%q clang=%q)", llcTool, clangTool)
		}
		t.Skipf("LLVM 22 llc/clang unavailable (llc=%q clang=%q)", llcTool, clangTool)
	}

	// Part A (Round 10 P2 #3): Every one of the 7 FLD* constants must translate
	// cleanly via public TranslateGoModule (matching shared x87ConstSpecs).
	constGoSrc := "package p\nfunc f() float64\n"
	for _, op := range []string{"FLD1", "FLDZ", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2"} {
		t.Run("const/"+op, func(t *testing.T) {
			fset := token.NewFileSet()
			astFile, err := parser.ParseFile(fset, "p.go", constGoSrc, 0)
			if err != nil {
				t.Fatal(err)
			}
			cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
			pkg, err := cfg.Check("p", fset, []*ast.File{astFile}, nil)
			if err != nil {
				t.Fatal(err)
			}
			asmSrc := "TEXT ·f(SB), NOSPLIT, $0-8\n\t" + op + "\n\tFMOVDP F0, ret+0(FP)\n\tRET\n"
			res, err := TranslateGoModule(GoPackage{Path: "p", Types: pkg, Syntax: []*ast.File{astFile}}, []byte(asmSrc), GoModuleOptions{
				FileName:     "p_amd64.s",
				GOOS:         "linux",
				GOARCH:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			})
			if err != nil {
				t.Fatalf("TranslateGoModule(%s) failed: %v", op, err)
			}
			rawIR := res.Module.String()
			res.Module.Dispose()
			tmp := t.TempDir()
			inPath := filepath.Join(tmp, "in.ll")
			outPath := filepath.Join(tmp, "opt.ll")
			if err := os.WriteFile(inPath, []byte(rawIR), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", inPath, "-o", outPath).CombinedOutput(); err != nil {
				t.Fatalf("%s: LLVM 22 opt -O2 failed: %v\n%s", op, err, out)
			}
			objPath := filepath.Join(tmp, "out.o")
			if out, err := exec.Command(llcTool, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", outPath, "-o", objPath).CombinedOutput(); err != nil {
				t.Fatalf("%s: llc failed: %v\n%s", op, err, out)
			}
		})
	}

	// Part B: Load shared testdata/conformance/amd64/x87_diff_amd64.s + x87_diff.go.
	goPath := filepath.Join("testdata", "conformance", "amd64", "x87_diff.go")
	asmPath := filepath.Join("testdata", "conformance", "amd64", "x87_diff_amd64.s")
	goSrcBytes, err := os.ReadFile(goPath)
	if err != nil {
		t.Fatalf("read %s: %v", goPath, err)
	}
	asmSrc, err := os.ReadFile(asmPath)
	if err != nil {
		t.Fatalf("read %s: %v", asmPath, err)
	}
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, goPath, goSrcBytes, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", goPath, err)
	}
	cfg := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "amd64")}
	pkg, err := cfg.Check("amd64conformance", fset, []*ast.File{astFile}, nil)
	if err != nil {
		t.Fatalf("typecheck %s: %v", goPath, err)
	}
	gp := GoPackage{Path: "amd64conformance", Types: pkg, Syntax: []*ast.File{astFile}}
	resolve := func(sym string) string {
		sym = strings.TrimSuffix(sym, "<>")
		sym = strings.TrimPrefix(sym, "·")
		return sym
	}

	harnessC := `
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __MINGW32__
int _fltused = 0;
#endif

extern void diffX87FmovdStackDepths(uint64_t *out);
extern void diffX87Constants(uint64_t *outF64, uint8_t *outRaw80);
extern void diffX87BCD(uint8_t *inBCD, uint8_t *outBCD, uint64_t *outF64);
extern void diffX87Arith80(double a, double b, uint64_t *out);
extern void diffX87FUCOMI(double a, double b, uint64_t *out);
extern void diffX87TopStatus(uint64_t *out);
extern void diffX87Binary80Precision(int64_t *outInt, uint8_t *outRaw80);
extern void diffX87Exceptions(uint64_t *out);
extern void diffX87ConstRoundingModes(uint8_t *outRaw80);
extern void diffX87BCDOne(uint64_t cw, uint8_t *inRaw80, uint8_t *outBCD, uint64_t *outSW);
extern void diffX87ConvInt(uint64_t cw, uint8_t *inRaw80, uint64_t *outVals, uint64_t *outSW);
extern void diffX87ConvFloat(uint64_t cw, uint8_t *inRaw80, uint32_t *outF32, uint64_t *outF64, uint8_t *outRnd80, uint64_t *outSW);
extern void diffX87ArithPC(uint64_t cw, uint8_t *aRaw80, uint8_t *bRaw80, uint8_t *outRaw80, uint64_t *outSW);
extern void diffX87Cmp(uint8_t *aRaw80, uint8_t *bRaw80, uint64_t *outCC, uint64_t *outExc);
extern void diffX87DynamicStackBranch(uint64_t x, uint64_t *out);
extern void diffX87MMXAliasAndTop(uint64_t x, uint64_t *out);
extern void diffX87CallAndMergeAlias(uint64_t x, uint64_t *out);
extern void diffX87EntryTopAndCW(uint64_t x, uint64_t *out);

typedef struct { uint64_t sig; uint16_t se; } raw80_spec;

static void make_raw80(raw80_spec s, uint8_t out[10]) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(s.sig >> (i * 8));
    out[8] = (uint8_t)(s.se & 0xff);
    out[9] = (uint8_t)(s.se >> 8);
}

static void print_u64s(const uint64_t *v, int n) {
    for (int i = 0; i < n; i++) {
        if (i > 0) putchar(',');
        printf("%016llx", (unsigned long long)v[i]);
    }
}

static void print_hex(const uint8_t *p, int n) {
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(void) {
    uint64_t stackOut[16] = {0};
    diffX87FmovdStackDepths(stackOut);
    printf("x87_stack="); print_u64s(stackOut, 16); putchar('\n');

    uint64_t constF64[7] = {0};
    uint8_t constRaw80[70] = {0};
    diffX87Constants(constF64, constRaw80);
    printf("x87_consts="); print_u64s(constF64, 7); putchar('|'); print_hex(constRaw80, 70); putchar('\n');

    const uint8_t bcds[8][10] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
        {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
        {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x99, 0x99, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
        {0x78, 0x56, 0x34, 0x12, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00},
        {0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0x76, 0x98, 0x80},
    };
    for (int i = 0; i < 8; i++) {
        uint8_t inB[10], outB[10] = {0};
        uint64_t outF = 0;
        memcpy(inB, bcds[i], 10);
        diffX87BCD(inB, outB, &outF);
        printf("x87_bcd[%d]=", i); print_hex(outB, 10); printf("|%016llx\n", (unsigned long long)outF);
    }

    const double apairs[3][2] = {{10.0, 3.0}, {-7.5, 2.25}, {1.0, 3.0}};
    for (int i = 0; i < 3; i++) {
        uint64_t out10[10] = {0};
        diffX87Arith80(apairs[i][0], apairs[i][1], out10);
        printf("x87_arith[%d]=", i); print_u64s(out10, 10); putchar('\n');
    }

    uint64_t nanBits = 0x7ff8000000000001ULL;
    double nanVal;
    memcpy(&nanVal, &nanBits, sizeof(nanVal));
    const double cpairs[6][2] = {
        {1.0, 2.0},
        {2.0, 2.0},
        {3.0, 2.0},
        {-0.0, 0.0},
        {nanVal, 1.0},
        {1.0, nanVal},
    };
    for (int i = 0; i < 6; i++) {
        uint64_t out6[6] = {0};
        diffX87FUCOMI(cpairs[i][0], cpairs[i][1], out6);
        printf("x87_fucomi[%d]=", i); print_u64s(out6, 6); putchar('\n');
    }

    uint64_t topOut[12] = {0};
    diffX87TopStatus(topOut);
    printf("x87_top="); print_u64s(topOut, 12); putchar('\n');

    int64_t bin80Int[6] = {0};
    uint8_t bin80Raw[60] = {0};
    diffX87Binary80Precision(bin80Int, bin80Raw);
    uint64_t bin80U64[6];
    for (int i = 0; i < 6; i++) bin80U64[i] = (uint64_t)bin80Int[i];
    printf("x87_bin80="); print_u64s(bin80U64, 6); putchar('|'); print_hex(bin80Raw, 60); putchar('\n');

    uint64_t excOut[10] = {0};
    diffX87Exceptions(excOut);
    printf("x87_exc="); print_u64s(excOut, 10); putchar('\n');

    uint8_t constRCRaw[280] = {0};
    diffX87ConstRoundingModes(constRCRaw);
    printf("x87_const_rc="); print_hex(constRCRaw, 280); putchar('\n');

    const uint64_t rcWords[4] = {0x037f, 0x077f, 0x0b7f, 0x0f7f};
    const uint64_t pcrcWords[12] = {
        0x007f, 0x047f, 0x087f, 0x0c7f,
        0x027f, 0x067f, 0x0a7f, 0x0e7f,
        0x037f, 0x077f, 0x0b7f, 0x0f7f,
    };
    const raw80_spec bcdSpecs[21] = {
        {0xde0b6b3a763ffff0ULL, 0x403a}, {0xde0b6b3a763ffff0ULL, 0xc03a},
        {0xde0b6b3a76400000ULL, 0x403a}, {0xde0b6b3a76400000ULL, 0xc03a},
        {0xde0b6b3a763ffff8ULL, 0x403a}, {0xde0b6b3a763ffff8ULL, 0xc03a},
        {0xde0b6b3a763ffff1ULL, 0x403a}, {0xde0b6b3a763ffff1ULL, 0xc03a},
        {0x8000000000000000ULL, 0x403b},
        {0x0000000000000000ULL, 0x0000}, {0x0000000000000000ULL, 0x8000},
        {0x8000000000000000ULL, 0x3ffd}, {0x8000000000000000ULL, 0xbffd},
        {0x8000000000000000ULL, 0x3ffe}, {0x8000000000000000ULL, 0xbffe},
        {0xc000000000000000ULL, 0x3fff}, {0xc000000000000000ULL, 0xbfff},
        {0x8000000000000000ULL, 0x7fff}, {0x8000000000000000ULL, 0xffff},
        {0xc000000000000001ULL, 0x7fff}, {0x8000000000000001ULL, 0x7fff},
    };
    const raw80_spec intSpecs[24] = {
        {0xfffe000000000000ULL, 0x400d}, {0xffff000000000000ULL, 0x400d},
        {0x8000000000000000ULL, 0x400e}, {0x8000000000000000ULL, 0xc00e},
        {0x8000800000000000ULL, 0xc00e}, {0x8001000000000000ULL, 0xc00e},
        {0xfffffffe00000000ULL, 0x401d}, {0xffffffff00000000ULL, 0x401d},
        {0x8000000000000000ULL, 0x401e}, {0x8000000000000000ULL, 0xc01e},
        {0x8000000080000000ULL, 0xc01e}, {0x8000000100000000ULL, 0xc01e},
        {0xfffffffffffffffeULL, 0x403d}, {0xffffffffffffffffULL, 0x403d},
        {0x8000000000000000ULL, 0x403e}, {0x8000000000000000ULL, 0xc03e},
        {0xffffffffffffffffULL, 0xc03d}, {0x8000000000000001ULL, 0xc03e},
        {0x8000000000000000ULL, 0xc03f},
        {0x8000000000000000ULL, 0xbffd}, {0x8000000000000000ULL, 0x3ffe},
        {0x8000000000000000ULL, 0x7fff}, {0xc000000000000001ULL, 0x7fff},
        {0x8000000000000001ULL, 0x7fff},
    };
    const raw80_spec fltSpecs[21] = {
        {0x0000000000000000ULL, 0x0000}, {0x0000000000000000ULL, 0x8000},
        {0x8000000000000000ULL, 0x3ffd}, {0x8000000000000000ULL, 0xbffd},
        {0x8000000000000000ULL, 0x3ffe}, {0x8000000000000000ULL, 0xbffe},
        {0xc000000000000000ULL, 0x3fff}, {0xc000000000000000ULL, 0xbfff},
        {0x8000000000000400ULL, 0x3fff}, {0x8000000000000c00ULL, 0x3fff},
        {0x8000008000000000ULL, 0x3fff}, {0x8000018000000000ULL, 0x3fff},
        {0xffffffffffffffffULL, 0x403d}, {0x8000000000000000ULL, 0x403e},
        {0xfffffffffffffc00ULL, 0x3c00}, {0xffffffc000000000ULL, 0x3f80},
        {0xffffffffffffffffULL, 0x7ffe}, {0x8000000000000000ULL, 0x0001},
        {0x0000000000000001ULL, 0x0000}, {0x8000000000000000ULL, 0x7fff},
        {0x8000000000000001ULL, 0x7fff},
    };
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < 21; i++) {
            uint8_t inB[10], outB[10] = {0};
            uint64_t outSW = 0;
            make_raw80(bcdSpecs[i], inB);
            diffX87BCDOne(rcWords[r], inB, outB, &outSW);
            printf("x87_bcd_rc[%d][%d]=", r, i); print_hex(outB, 10); printf("|%04llx\n", (unsigned long long)outSW);
        }
        for (int i = 0; i < 24; i++) {
            uint8_t inB[10];
            uint64_t outV[3] = {0}, outSW[3] = {0};
            make_raw80(intSpecs[i], inB);
            diffX87ConvInt(rcWords[r], inB, outV, outSW);
            printf("x87_conv_int[%d][%d]=", r, i); print_u64s(outV, 3); putchar('|'); print_u64s(outSW, 3); putchar('\n');
        }
        for (int i = 0; i < 21; i++) {
            uint8_t inB[10], outRnd[10] = {0};
            uint32_t outF32 = 0;
            uint64_t outF64 = 0, outSW[3] = {0};
            make_raw80(fltSpecs[i], inB);
            diffX87ConvFloat(rcWords[r], inB, &outF32, &outF64, outRnd, outSW);
            printf("x87_conv_flt[%d][%d]=%08x|%016llx|", r, i, (unsigned)outF32, (unsigned long long)outF64);
            print_hex(outRnd, 10); putchar('|'); print_u64s(outSW, 3); putchar('\n');
        }
    }
    const raw80_spec arithPairs[13][2] = {
        {{0x8000000000000000ULL, 0x3fff}, {0xc000000000000000ULL, 0x4000}},
        {{0x8000000000000000ULL, 0x4000}, {0xc000000000000000ULL, 0x4000}},
        {{0x8000000000000000ULL, 0x4034}, {0x8000000000000000ULL, 0x3fff}},
        {{0x8000000000000000ULL, 0x4017}, {0x8000000000000000ULL, 0x3fff}},
        {{0xffffffffffffffffULL, 0x7ffe}, {0x8000000000000000ULL, 0x4000}},
        {{0x8000000000000000ULL, 0x0001}, {0xc000000000000000ULL, 0x4000}},
        {{0x0000000000000001ULL, 0x0000}, {0x8000000000000000ULL, 0x3fff}},
        {{0x8000000000000000ULL, 0x3fff}, {0x0000000000000000ULL, 0x0000}},
        {{0x0000000000000000ULL, 0x0000}, {0x0000000000000000ULL, 0x0000}},
        {{0x8000000000000000ULL, 0x7fff}, {0x8000000000000000ULL, 0x7fff}},
        {{0x0000000000000000ULL, 0x8000}, {0x0000000000000000ULL, 0x8000}},
        {{0xc000000000000001ULL, 0x7fff}, {0x8000000000000000ULL, 0x3fff}},
        {{0x8000000000000001ULL, 0x7fff}, {0x8000000000000000ULL, 0x3fff}},
    };
    for (int m = 0; m < 12; m++) {
        for (int i = 0; i < 13; i++) {
            uint8_t aB[10], bB[10], outRaw[50] = {0};
            uint64_t outSW[5] = {0};
            make_raw80(arithPairs[i][0], aB);
            make_raw80(arithPairs[i][1], bB);
            diffX87ArithPC(pcrcWords[m], aB, bB, outRaw, outSW);
            printf("x87_arith_pc[%d][%d]=", m, i); print_hex(outRaw, 50); putchar('|'); print_u64s(outSW, 5); putchar('\n');
        }
    }
    const raw80_spec cmpPairs[10][2] = {
        {{0x8000000000000000ULL, 0x3fff}, {0x8000000000000000ULL, 0x4000}},
        {{0x8000000000000000ULL, 0x4000}, {0x8000000000000000ULL, 0x4000}},
        {{0xc000000000000000ULL, 0x4000}, {0x8000000000000000ULL, 0x4000}},
        {{0x0000000000000000ULL, 0x8000}, {0x0000000000000000ULL, 0x0000}},
        {{0xc000000000000001ULL, 0x7fff}, {0x8000000000000000ULL, 0x3fff}},
        {{0x8000000000000001ULL, 0x7fff}, {0x8000000000000000ULL, 0x3fff}},
        {{0x0000000000000001ULL, 0x0000}, {0x8000000000000000ULL, 0x3fff}},
        {{0xc000000000000001ULL, 0x7fff}, {0x0000000000000001ULL, 0x0000}},
        {{0x8000000000000001ULL, 0x7fff}, {0x0000000000000001ULL, 0x0000}},
        {{0x8000000000000000ULL, 0xffff}, {0x8000000000000000ULL, 0x7fff}},
    };
    for (int i = 0; i < 10; i++) {
        uint8_t aB[10], bB[10];
        uint64_t outCC[5] = {0}, outExc[5] = {0};
        make_raw80(cmpPairs[i][0], aB);
        make_raw80(cmpPairs[i][1], bB);
        diffX87Cmp(aB, bB, outCC, outExc);
        printf("x87_cmp[%d]=", i); print_u64s(outCC, 5); putchar('|'); print_u64s(outExc, 5); putchar('\n');
    }
    for (uint64_t x = 0; x <= 1; x++) {
        uint64_t outDyn[4] = {0};
        diffX87DynamicStackBranch(x, outDyn);
        printf("x87_dyn_branch[%llu]=", (unsigned long long)x); print_u64s(outDyn, 4); putchar('\n');
    }
    for (uint64_t x = 0; x <= 1; x++) {
        uint64_t outMMX[8] = {0};
        diffX87MMXAliasAndTop(x, outMMX);
        printf("x87_mmx_alias[%llu]=", (unsigned long long)x); print_u64s(outMMX, 8); putchar('\n');
    }
    for (uint64_t x = 0; x <= 1; x++) {
        uint64_t outCM[6] = {0};
        diffX87CallAndMergeAlias(x, outCM);
        printf("x87_call_merge[%llu]=", (unsigned long long)x); print_u64s(outCM, 6); putchar('\n');
    }
    for (uint64_t x = 0; x <= 1; x++) {
        uint64_t outET[4] = {0};
        diffX87EntryTopAndCW(x, outET);
        printf("x87_entry_top_cw[%llu]=", (unsigned long long)x); print_u64s(outET, 4); putchar('\n');
    }
    return 0;
}
`

	// Step 1: Translate in default X87Hardware mode via public TranslateGoModule,
	// run LLVM 22 opt -O2, and verify x86_64 llc -filetype=obj compilation.
	hwRes, err := TranslateGoModule(gp, asmSrc, GoModuleOptions{
		FileName:     "x87_diff_amd64.s",
		GOOS:         "linux",
		GOARCH:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym:   resolve,
	})
	if err != nil {
		t.Fatalf("TranslateGoModule(x87_diff_amd64.s, X87Hardware) failed: %v", err)
	}
	hwRawIR := hwRes.Module.String()
	hwRes.Module.Dispose()

	tmp := t.TempDir()
	hwInPath := filepath.Join(tmp, "x87_hw_raw.ll")
	hwOptPath := filepath.Join(tmp, "x87_hw_opt.ll")
	hwObjPath := filepath.Join(tmp, "x87_hw.o")
	if err := os.WriteFile(hwInPath, []byte(hwRawIR), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", hwInPath, "-o", hwOptPath).CombinedOutput(); err != nil {
		t.Fatalf("LLVM 22 opt -O2 (X87Hardware) failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(llcTool, "-mtriple=x86_64-unknown-linux-gnu", "-filetype=obj", hwOptPath, "-o", hwObjPath).CombinedOutput(); err != nil {
		t.Fatalf("llc x86_64 (X87Hardware) failed: %v\n%s", err, out)
	}

	// Step 2: Portable X87Software execution on EVERY host (including arm64) AND
	// zero-libcall 32-bit softfloat llc verification.
	var swMap map[string]string
	hostTriple := hostLLVMTriple()
	if hostTriple != "" {
		swRes, err := TranslateGoModule(gp, asmSrc, GoModuleOptions{
			FileName:     "x87_diff_amd64.s",
			GOOS:         "linux",
			GOARCH:       "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu",
			X87Mode:      X87Software,
			ResolveSym:   resolve,
		})
		if err != nil {
			t.Fatalf("TranslateGoModule(x87_diff_amd64.s, X87Software) failed: %v", err)
		}
		swRawIR := swRes.Module.String()
		swRes.Module.Dispose()
		swInPath := filepath.Join(tmp, "x87_sw_raw.ll")
		swOptPath := filepath.Join(tmp, "x87_sw_opt.ll")
		swHostPath := filepath.Join(tmp, "x87_sw_host.ll")
		swObjPath := filepath.Join(tmp, "x87_sw_host.o")
		if err := os.WriteFile(swInPath, []byte(swRawIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", swInPath, "-o", swOptPath).CombinedOutput(); err != nil {
			t.Fatalf("LLVM 22 opt -O2 (X87Software) failed: %v\n%s", err, out)
		}
		// Verify pure-integer binary80 software IR compiles cleanly on 32-bit i386
		// softfloat with zero hardware x87 instructions and zero i128 libcalls.
		sw386Asm := filepath.Join(tmp, "x87_sw_386.s")
		if out, err := exec.Command(llcTool, "-O2", "-mtriple=i386-unknown-linux-gnu", "-mattr=+soft-float,-x87,-sse,-sse2", "-filetype=asm", swOptPath, "-o", sw386Asm).CombinedOutput(); err != nil {
			t.Fatalf("llc i386 softfloat (X87Software) failed: %v\n%s", err, out)
		}
		if asmBytes, err := os.ReadFile(sw386Asm); err == nil {
			s := string(asmBytes)
			for _, badCall := range []string{"__udivti3", "__divti3", "__multi3", "__ashlti3", "__lshrti3"} {
				if strings.Contains(s, badCall) {
					t.Fatalf("X87Software i386 softfloat unexpectedly emitted external libcall %s", badCall)
				}
			}
		}
		swOptBytes, err := os.ReadFile(swOptPath)
		if err != nil {
			t.Fatal(err)
		}
		swHostIR := strings.Replace(string(swOptBytes), `target triple = "x86_64-unknown-linux-gnu"`, `target triple = "`+hostTriple+`"`, 1)
		if err := os.WriteFile(swHostPath, []byte(swHostIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(llcTool, "-mtriple="+hostTriple, "-filetype=obj", swHostPath, "-o", swObjPath).CombinedOutput(); err != nil {
			t.Fatalf("llc host (%s, X87Software) failed: %v\n%s", hostTriple, err, out)
		}
		harnessPath := filepath.Join(tmp, "x87_harness.c")
		if err := os.WriteFile(harnessPath, []byte(harnessC), 0o600); err != nil {
			t.Fatal(err)
		}
		swBin := filepath.Join(tmp, "x87_sw_bin")
		if runtime.GOOS == "windows" {
			swBin += ".exe"
		}
		swLinkArgs := []string{"-O2", harnessPath, swObjPath, "-o", swBin}
		if runtime.GOOS != "windows" {
			swLinkArgs = append(swLinkArgs, "-lm")
		}
		if out, err := exec.Command(clangTool, swLinkArgs...).CombinedOutput(); err != nil {
			t.Fatalf("clang link X87Software harness failed: %v\n%s", err, out)
		}
		swOut, err := exec.Command(swBin).CombinedOutput()
		if err != nil {
			t.Fatalf("run X87Software harness failed: %v\n%s", err, swOut)
		}
		swMap, _ = parseDiffTranscript(t, string(swOut))

		// Verify golden invariants on portable X87Software run:
		wantStackVals := []float64{0, 1, 0, 10, 30, 20, 10, 7, 7, 5, 9, 2, 9, 22, 33, 55}
		wantStackHex := make([]string, len(wantStackVals))
		for i, v := range wantStackVals {
			wantStackHex[i] = fmt.Sprintf("%016x", math.Float64bits(v))
		}
		if got, want := swMap["x87_stack"], strings.Join(wantStackHex, ","); got != want {
			t.Fatalf("X87Software x87_stack:\n  got:  %s\n  want: %s", got, want)
		}
		wantConstF64 := []float64{1.0, 0.0, math.Pi, math.Log2E, math.Log2(10), math.Log10(2), math.Ln2}
		wantConstHex := make([]string, len(wantConstF64))
		for i, v := range wantConstF64 {
			wantConstHex[i] = fmt.Sprintf("%016x", math.Float64bits(v))
		}
		wantRaw80 := "0000000000000080ff3f" + // FLD1
			"00000000000000000000" + // FLDZ
			"35c26821a2da0fc90040" + // FLDPI
			"bcf0175c293baab8ff3f" + // FLDL2E
			"fe8a1bcd4b789ad40040" + // FLDL2T
			"99f7cffb849a209afd3f" + // FLDLG2
			"ac79cfd1f71772b1fe3f" // FLDLN2
		if got, want := swMap["x87_consts"], strings.Join(wantConstHex, ",")+"|"+wantRaw80; got != want {
			t.Fatalf("X87Software x87_consts:\n  got:  %s\n  want: %s", got, want)
		}
		// Verify FUCOMI(1.0, 2.0) clears OF/SF/AF and sets CF=1, ZF=0, PF=0 (0x03 = bit1|CF).
		fu0 := strings.Split(swMap["x87_fucomi[0]"], ",")
		if len(fu0) != 6 || fu0[0] != "0000000000000003" || fu0[1] != "0000000000000003" || fu0[3] != "0000000000000003" || fu0[4] != "0000000000000003" {
			t.Fatalf("X87Software x87_fucomi[0] (1.0 vs 2.0) = %v, want flags=0x03 (OF=SF=AF=0, CF=1)", fu0)
		}
		// Verify BCD -0 preserves negative zero sign bit.
		if got := swMap["x87_bcd[1]"]; got != "00000000000000000080|8000000000000000" {
			t.Fatalf("X87Software x87_bcd[1] (-0) = %s, want 00000000000000000080|8000000000000000", got)
		}
		// Verify Round 11 P1 #1: FSTSW tracks architectural x87 stack TOP pointer across all 12 steps.
		wantTopVals := []uint64{0x0000, 0x3800, 0x3000, 0x2800, 0x6800, 0x2900, 0x2800, 0x3000, 0x0000, 0x3800, 0x0000, 0x0000}
		wantTopHex := make([]string, len(wantTopVals))
		for i, v := range wantTopVals {
			wantTopHex[i] = fmt.Sprintf("%016x", v)
		}
		if got, want := swMap["x87_top"], strings.Join(wantTopHex, ","); got != want {
			t.Fatalf("X87Software x87_top:\n  got:  %s\n  want: %s", got, want)
		}
		// Verify Round 11 P1 #2: X87Software preserves full 64-bit significand binary80 precision!
		wantBin80Ints := []uint64{
			9007199254740993,    // 2^53 + 1
			4611686018427387905, // 2^62 + 1
			4611686018427387903, // 2^62 - 1
			27021597764222979,   // (2^53 + 1) * 3
			384307168202282326,  // (2^60 + 2) / 3
			2147483648,          // sqrt(2^62)
		}
		wantBin80Hex := make([]string, len(wantBin80Ints))
		for i, v := range wantBin80Ints {
			wantBin80Hex[i] = fmt.Sprintf("%016x", v)
		}
		wantBin80Raw := "abaaaaaaaaaaaaaafd3f" + // 1 / 3
			"8464def933f304b5ff3f" + // sqrt(2)
			"9e5365c242d7b3ddff3f" + // sqrt(3)
			"4a5dba671b7cb2920140" + // pi + log2(e)
			"3cb705850c925d8b0040" + // pi * ln(2)
			"fefffffffffffffffe3f" // 1 - 2^-63
		if got, want := swMap["x87_bin80"], strings.Join(wantBin80Hex, ",")+"|"+wantBin80Raw; got != want {
			t.Fatalf("X87Software x87_bin80:\n  got:  %s\n  want: %s", got, want)
		}
		// Verify Round 12 P1 #1: sticky x87 arithmetic exception flags + C1 + TOP in FSTSW.
		wantExcVals := []uint64{0x3804, 0x3801, 0x3a20, 0x0004, 0x3800, 0x0001, 0x0020, 0x0228, 0x0230, 0x0022}
		wantExcHex := make([]string, len(wantExcVals))
		for i, v := range wantExcVals {
			wantExcHex[i] = fmt.Sprintf("%016x", v)
		}
		if got, want := swMap["x87_exc"], strings.Join(wantExcHex, ","); got != want {
			t.Fatalf("X87Software x87_exc:\n  got:  %s\n  want: %s", got, want)
		}
		// Verify Round 12 P1 #2: all 7 FLD* constants across RN (0x037f), RD (0x077f), RU (0x0b7f), RZ (0x0f7f).
		wantConstRC := "" +
			// Mode 0: RN (0x037f)
			"0000000000000080ff3f" + // FLD1
			"00000000000000000000" + // FLDZ
			"35c26821a2da0fc90040" + // FLDPI  (...c235)
			"bcf0175c293baab8ff3f" + // FLDL2E (...f0bc)
			"fe8a1bcd4b789ad40040" + // FLDL2T (...8afe)
			"99f7cffb849a209afd3f" + // FLDLG2 (...f799)
			"ac79cfd1f71772b1fe3f" + // FLDLN2 (...79ac)
			// Mode 1: RD (0x077f)
			"0000000000000080ff3f" + // FLD1
			"00000000000000000000" + // FLDZ
			"34c26821a2da0fc90040" + // FLDPI  (...c234)
			"bbf0175c293baab8ff3f" + // FLDL2E (...f0bb)
			"fe8a1bcd4b789ad40040" + // FLDL2T (...8afe)
			"98f7cffb849a209afd3f" + // FLDLG2 (...f798)
			"ab79cfd1f71772b1fe3f" + // FLDLN2 (...79ab)
			// Mode 2: RU (0x0b7f)
			"0000000000000080ff3f" + // FLD1
			"00000000000000000000" + // FLDZ
			"35c26821a2da0fc90040" + // FLDPI  (...c235)
			"bcf0175c293baab8ff3f" + // FLDL2E (...f0bc)
			"ff8a1bcd4b789ad40040" + // FLDL2T (...8aff)
			"99f7cffb849a209afd3f" + // FLDLG2 (...f799)
			"ac79cfd1f71772b1fe3f" + // FLDLN2 (...79ac)
			// Mode 3: RZ (0x0f7f)
			"0000000000000080ff3f" + // FLD1
			"00000000000000000000" + // FLDZ
			"34c26821a2da0fc90040" + // FLDPI  (...c234)
			"bbf0175c293baab8ff3f" + // FLDL2E (...f0bb)
			"fe8a1bcd4b789ad40040" + // FLDL2T (...8afe)
			"98f7cffb849a209afd3f" + // FLDLG2 (...f798)
			"ab79cfd1f71772b1fe3f" // FLDLN2 (...79ab)
		if got := swMap["x87_const_rc"]; got != wantConstRC {
			t.Fatalf("X87Software x87_const_rc:\n  got:  %s\n  want: %s", got, wantConstRC)
		}
		// Verify Round 13 P1 golden BCD boundary invariants on portable X87Software (every host):
		// max valid (+999999999999999999), min valid (-999999999999999999), +10^18, -10^18,
		// and rounding-induced overflow (+/-999999999999999999.5, +/-999999999999999999.0625)
		// across RN (0), RD (1), RU (2), RZ (3) checking ALL 10 bytes + IE/PE/C1/TOP!
		wantMaxPos := "99999999999999999900"
		wantMaxNeg := "99999999999999999980"
		wantIndef := "00000000000000c0ffff"
		bcdGoldens := []struct{ key, want string }{
			{"x87_bcd_rc[0][0]", wantMaxPos + "|0000"}, // +10^18-1 RN
			{"x87_bcd_rc[0][1]", wantMaxNeg + "|0000"}, // -10^18-1 RN
			{"x87_bcd_rc[0][2]", wantIndef + "|0001"},  // +10^18 RN -> IE=1 + indefinite
			{"x87_bcd_rc[0][3]", wantIndef + "|0001"},  // -10^18 RN -> IE=1 + indefinite
			{"x87_bcd_rc[0][4]", wantIndef + "|0001"},  // +10^18-0.5 RN -> rounds to 10^18 -> IE=1
			{"x87_bcd_rc[1][4]", wantMaxPos + "|0020"}, // +10^18-0.5 RD -> valid max + PE
			{"x87_bcd_rc[2][4]", wantIndef + "|0001"},  // +10^18-0.5 RU -> IE=1
			{"x87_bcd_rc[3][4]", wantMaxPos + "|0020"}, // +10^18-0.5 RZ -> valid max + PE
			{"x87_bcd_rc[0][5]", wantIndef + "|0001"},  // -10^18+0.5 RN -> IE=1
			{"x87_bcd_rc[1][5]", wantIndef + "|0001"},  // -10^18+0.5 RD -> IE=1
			{"x87_bcd_rc[2][5]", wantMaxNeg + "|0020"}, // -10^18+0.5 RU -> valid min + PE
			{"x87_bcd_rc[3][5]", wantMaxNeg + "|0020"}, // -10^18+0.5 RZ -> valid min + PE
			{"x87_bcd_rc[0][6]", wantMaxPos + "|0020"}, // +10^18-0.9375 RN -> valid max + PE
			{"x87_bcd_rc[2][6]", wantIndef + "|0001"},  // +10^18-0.9375 RU -> rounds up to 10^18 -> IE=1
			{"x87_bcd_rc[1][7]", wantIndef + "|0001"},  // -10^18+0.9375 RD -> rounds down to -10^18 -> IE=1
			{"x87_bcd_rc[0][8]", wantIndef + "|0001"},  // +2^60 RN -> IE=1
			{"x87_bcd_rc[0][17]", wantIndef + "|0001"}, // +Inf -> IE=1
			{"x87_bcd_rc[0][19]", wantIndef + "|0001"}, // QNaN -> IE=1
			{"x87_bcd_rc[0][20]", wantIndef + "|0001"}, // SNaN -> IE=1
		}
		for _, bg := range bcdGoldens {
			if got := swMap[bg.key]; got != bg.want {
				t.Fatalf("X87Software %s = %s, want %s", bg.key, got, bg.want)
			}
		}
		if got, want := swMap["x87_dyn_branch[0]"], "0000000000000000,0000000000000800,0000000000000000,0000000000000000"; got != want {
			t.Fatalf("X87Software x87_dyn_branch[0] = %s, want %s", got, want)
		}
		if got, want := swMap["x87_dyn_branch[1]"], "0000000000000000,0000000000000000,0000000000000800,0000000000000000"; got != want {
			t.Fatalf("X87Software x87_dyn_branch[1] = %s, want %s", got, want)
		}
		if got, want := swMap["x87_mmx_alias[0]"], "8000000000000000,000000000000007b,0000000000003800,0000000000003800,c90fdaa22168c235,8000000000000000,8000000000000000,000000000000007b"; got != want {
			t.Fatalf("X87Software x87_mmx_alias[0] = %s, want %s", got, want)
		}
		if got, want := swMap["x87_mmx_alias[1]"], "8000000000000000,000000000000007b,0000000000003800,0000000000003800,c90fdaa22168c235,8000000000000000,8000000000000000,c90fdaa22168c235"; got != want {
			t.Fatalf("X87Software x87_mmx_alias[1] = %s, want %s", got, want)
		}
		if got, want := swMap["x87_call_merge[0]"], "8000000000000000,8000000000000000,8000000000000000,8000000000000000,8000000000000000,0000000000003800"; got != want {
			t.Fatalf("X87Software x87_call_merge[0] = %s, want %s", got, want)
		}
		if got, want := swMap["x87_call_merge[1]"], "8000000000000000,8000000000000000,8000000000000000,8000000000000000,c90fdaa22168c235,0000000000003800"; got != want {
			t.Fatalf("X87Software x87_call_merge[1] = %s, want %s", got, want)
		}
		const wantEntryTopCW = "8000000000000000,8000000000000000,c90fdaa22168c235,c90fdaa22168c234"
		if got := swMap["x87_entry_top_cw[0]"]; got != wantEntryTopCW {
			t.Fatalf("X87Software x87_entry_top_cw[0] = %s, want %s", got, wantEntryTopCW)
		}
		if got := swMap["x87_entry_top_cw[1]"]; got != wantEntryTopCW {
			t.Fatalf("X87Software x87_entry_top_cw[1] = %s, want %s", got, wantEntryTopCW)
		}
		if len(swMap) < 461 {
			t.Fatalf("X87Software produced only %d diff keys, want >= 461", len(swMap))
		}
	}

	// Step 3: Native Go amd64 vs LLVM 22 X87Hardware machine-code differential comparison!
	if runtime.GOARCH != "amd64" || hostTriple == "" {
		t.Logf("portable X87Software execution + X87Hardware llc verification PASSED; native amd64 Go-asm x87 diff runs on amd64 runners")
		return
	}

	hwLinkObjPath := hwObjPath
	if hostTriple != "x86_64-unknown-linux-gnu" {
		hwOptBytes, err := os.ReadFile(hwOptPath)
		if err != nil {
			t.Fatal(err)
		}
		hwHostIR := strings.Replace(string(hwOptBytes), `target triple = "x86_64-unknown-linux-gnu"`, `target triple = "`+hostTriple+`"`, 1)
		hwHostPath := filepath.Join(tmp, "x87_hw_host.ll")
		hwHostObjPath := filepath.Join(tmp, "x87_hw_host.o")
		if err := os.WriteFile(hwHostPath, []byte(hwHostIR), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(llcTool, "-mtriple="+hostTriple, "-filetype=obj", hwHostPath, "-o", hwHostObjPath).CombinedOutput(); err != nil {
			t.Fatalf("llc host (%s, X87Hardware) failed: %v\n%s", hostTriple, err, out)
		}
		hwLinkObjPath = hwHostObjPath
	}

	harnessPath := filepath.Join(tmp, "x87_hw_harness.c")
	if err := os.WriteFile(harnessPath, []byte(harnessC), 0o600); err != nil {
		t.Fatal(err)
	}
	hwBin := filepath.Join(tmp, "x87_hw_bin")
	if runtime.GOOS == "windows" {
		hwBin += ".exe"
	}
	linkArgs := []string{"-O2", harnessPath, hwLinkObjPath, "-o", hwBin}
	if runtime.GOOS != "windows" {
		linkArgs = append(linkArgs, "-lm")
	}
	if out, err := exec.Command(clangTool, linkArgs...).CombinedOutput(); err != nil {
		t.Fatalf("clang link X87Hardware harness failed: %v\n%s", err, out)
	}
	hwOut, err := exec.Command(hwBin).CombinedOutput()
	if err != nil {
		t.Fatalf("run X87Hardware harness failed: %v\n%s", err, hwOut)
	}
	llvmMap, _ := parseDiffTranscript(t, string(hwOut))

	oraclePath := filepath.Join(tmp, "x87_go_oracle.txt")
	oracleCmd := exec.Command("go", "test", "./testdata/conformance/amd64", "-run", "^TestAMD64X87DiffDumpOracle$", "-count=1")
	oracleCmd.Env = append(os.Environ(), "PLAN9ASM_X87_DIFF_ORACLE_OUT="+oraclePath)
	if out, err := oracleCmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go amd64 x87 oracle execution failed: %v\n%s", err, out)
	}
	oracleBytes, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatalf("read x87 oracle transcript %s: %v", oraclePath, err)
	}
	oracleMap, _ := parseDiffTranscript(t, string(oracleBytes))
	if len(oracleMap) < 461 {
		t.Fatalf("native Go amd64 x87 oracle executed only %d cases, want >= 461", len(oracleMap))
	}

	compared := 0
	var mismatches []string
	failedKeys := map[string]bool{}
	for k, want := range oracleMap {
		gotHW, ok := llvmMap[k]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("%s: missing from LLVM X87Hardware transcript (oracle=%s)", k, want))
			failedKeys[k] = true
			continue
		}
		compared++
		if gotHW != want {
			mismatches = append(mismatches, fmt.Sprintf("%s [X87Hardware]:\n  go-asm:   %s\n  plan9asm: %s", k, want, gotHW))
			failedKeys[k] = true
		}
		if gotSW, okSW := swMap[k]; !okSW || gotSW != want {
			mismatches = append(mismatches, fmt.Sprintf("%s [X87Software]:\n  go-asm:   %s\n  plan9asm: %s", k, want, gotSW))
			failedKeys[k] = true
		}
	}
	writeAMD64ManifestDiffExecutionReport(t, "amd64/x87_diff_amd64.s", llcTool, true, map[string][]string{
		"amd64-diff-gate-x87": {"x87_stack", "x87_consts", "x87_bcd[", "x87_arith[", "x87_fucomi[", "x87_top", "x87_bin80", "x87_exc", "x87_const_rc", "x87_bcd_rc[", "x87_conv_int[", "x87_conv_flt[", "x87_arith_pc[", "x87_cmp[", "x87_dyn_branch[", "x87_mmx_alias[", "x87_call_merge[", "x87_entry_top_cw["},
	}, llvmMap, oracleMap, failedKeys, "")
	if len(mismatches) > 0 {
		t.Fatalf("AMD64 x87 machine-code differential mismatch (%d/%d failed):\n%s", len(mismatches), compared, strings.Join(mismatches, "\n"))
	}

	// Step 4: On native amd64 hardware, also verify Round 17 P1 #2 exact repro
	// (FLDPI without FINIT/FLDCW) executed under caller FLDCW=0x037f (RN) and
	// FLDCW=0x077f (RD): X87Hardware reads live hardware FCW and matches Go
	// native amd64 silicon (0xc90fdaa22168c235 / 0xc90fdaa22168c234), while
	// X87Software explicitly rejects it.
	r17GoSrc := "package r17cw\nfunc entryCwFldpi() uint64\n"
	r17AsmSrc := []byte(`TEXT ·entryCwFldpi(SB), NOSPLIT, $16-8
	FLDPI
	FMOVXP F0, 0(SP)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`)
	r17Fset := token.NewFileSet()
	r17Ast, err := parser.ParseFile(r17Fset, "r17cw.go", r17GoSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	r17Pkg, err := cfg.Check("r17cw", r17Fset, []*ast.File{r17Ast}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r17GP := GoPackage{Path: "r17cw", Types: r17Pkg, Syntax: []*ast.File{r17Ast}}
	if swR17, err := TranslateGoModule(r17GP, r17AsmSrc, GoModuleOptions{
		FileName:     "r17cw_amd64.s",
		GOOS:         "linux",
		GOARCH:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		X87Mode:      X87Software,
		ResolveSym:   resolve,
	}); err == nil {
		swR17.Module.Dispose()
		t.Fatalf("Round 17 P1 #2: X87Software unexpectedly accepted entry FLDPI without FINIT/FLDCW")
	}
	hwR17, err := TranslateGoModule(r17GP, r17AsmSrc, GoModuleOptions{
		FileName:     "r17cw_amd64.s",
		GOOS:         "linux",
		GOARCH:       "amd64",
		TargetTriple: hostTriple,
		X87Mode:      X87Hardware,
		ResolveSym:   resolve,
	})
	if err != nil {
		t.Fatalf("Round 17 P1 #2: X87Hardware entry FLDPI failed: %v", err)
	}
	hwR17IR := hwR17.Module.String()
	hwR17.Module.Dispose()
	r17InLL := filepath.Join(tmp, "r17_hw.ll")
	r17OptLL := filepath.Join(tmp, "r17_hw_opt.ll")
	r17Obj := filepath.Join(tmp, "r17_hw.o")
	r17C := filepath.Join(tmp, "r17_hw_harness.c")
	r17Bin := filepath.Join(tmp, "r17_hw_bin")
	if runtime.GOOS == "windows" {
		r17Bin += ".exe"
	}
	if err := os.WriteFile(r17InLL, []byte(hwR17IR), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(optTool, "-passes=default<O2>", "-S", r17InLL, "-o", r17OptLL).CombinedOutput(); err != nil {
		t.Fatalf("opt -O2 (r17_hw) failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(llcTool, "-mtriple="+hostTriple, "-filetype=obj", r17OptLL, "-o", r17Obj).CombinedOutput(); err != nil {
		t.Fatalf("llc (r17_hw) failed: %v\n%s", err, out)
	}
	r17HarnessC := `
#include <stdint.h>
#include <stdio.h>
extern uint64_t entryCwFldpi(void);
static uint64_t call_with_cw(uint16_t cw) {
    uint64_t res;
    __asm__ __volatile__("fninit; fldcw %0" : : "m"(cw) : "memory");
    res = entryCwFldpi();
    __asm__ __volatile__("fninit" : : : "memory");
    return res;
}
int main(void) {
    uint64_t rn = call_with_cw(0x037f);
    uint64_t rd = call_with_cw(0x077f);
    printf("rn=%016llx rd=%016llx\n", (unsigned long long)rn, (unsigned long long)rd);
    if (rn != 0xc90fdaa22168c235ULL || rd != 0xc90fdaa22168c234ULL) return 1;
    return 0;
}
`
	if err := os.WriteFile(r17C, []byte(r17HarnessC), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(clangTool, "-O2", r17C, r17Obj, "-o", r17Bin).CombinedOutput(); err != nil {
		t.Fatalf("clang link r17_hw failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(r17Bin).CombinedOutput(); err != nil {
		t.Fatalf("Round 17 P1 #2 X87Hardware live-FCW silicon test failed: %v\n%s", err, out)
	}
	t.Logf("AMD64 x87 native machine-code differential gate PASSED: compared=%d (BOTH X87Hardware and X87Software vs Go native amd64 asm + X87Hardware live-FCW entry FLDPI)", compared)
}
