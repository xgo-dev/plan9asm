//go:build !llgo

package plan9asm

import (
	"go/token"
	"go/types"
	"os/exec"
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
