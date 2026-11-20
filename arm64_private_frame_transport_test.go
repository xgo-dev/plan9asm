package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64PrivateLiveScratchSource(call string) string {
	source := arm64CallCopyLoopSource(call, "LDP (R6),(R2,R5)\nSTP (R2,R5),(R7)")
	// This fresh-frame pointer is never an argument, stored address or result.
	// The original Go caller-save value may be clobbered: no later instruction
	// consumes it. Requiring a physical clear before CALL/RET is unnecessary.
	return strings.Replace(source, "\t"+call+" runtime·memmove(SB)", "\tADD $32,RSP,R17\n\tMOVD (R17),R11\n\t"+call+" runtime·memmove(SB)", 1)
}

func TestARM64PrivateFrameTransportStillRejectsEscapes(t *testing.T) {
	pkg := arm64PrivateCallDeclarations(t, "func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr\n")
	callee := arm64CallInputMemmoveSig(t)
	resolve := func(sym string) string {
		return strings.ReplaceAll(goStripABISuffix(strings.TrimPrefix(sym, "·")), "·", ".")
	}
	for _, effect := range []string{
		"MOVD R17,8(RSP)",
		"MOVD R17,dst+0(FP)",
		"MOVD R17,ret+24(FP)",
		"MOVD R17,holder(SB)",
		"MOVD R17,(R7)",
		"FMOVD R17,F0",
		"VMOV R17,V0.D[0]",
		"CBZ R4,alternate\nB merged\nalternate:\nADD $40,RSP,R17\nmerged:\nMOVD (R17),R11",
		"ADD $56,RSP,R17\nLDP (R17),(R10,R11)",
	} {
		t.Run(effect, func(t *testing.T) {
			source := strings.Replace(arm64PrivateLiveScratchSource("CALL"), "\tCALL runtime·memmove(SB)", effect+"\n\tCALL runtime·memmove(SB)", 1)
			source += "\nGLOBL holder(SB),NOPTR,$8\n"
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", "arm64")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes,
				func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" })
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs, ResolveSym: resolve}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s escaped/unbounded private transport: %v", target, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Module escaped/unbounded private transport: %v", target, err)
				}
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
					ManualSig: func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" },
				})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s GoModule escaped/unbounded private transport: %v", target, err)
				}
			}
		})
	}
}

func TestARM64PrivateFrameTypedTerminatorTransports(t *testing.T) {
	entry := FuncSig{Name: "Entry", Ret: Void}
	resolve := func(sym string) string { return goStripABISuffix(sym) }
	for _, tc := range []struct {
		name    string
		callee  FuncSig
		symbol  string
		present bool
		want    bool
	}{
		{name: "explicit_zero_arguments", callee: FuncSig{Ret: Void}, symbol: "X", present: true, want: true},
		{name: "missing_target", symbol: "X"},
		{name: "unproved_internal", callee: FuncSig{Ret: Void}, symbol: "X<ABIInternal>", present: true},
		{name: "private_custom_argument", callee: FuncSig{Ret: Void, Args: []LLVMType{Ptr}, ArgRegs: []Reg{"R17"}}, symbol: "X", present: true},
		{name: "invalid_custom_argument", callee: FuncSig{Ret: Void, Args: []LLVMType{Ptr}, ArgRegs: []Reg{"R40"}}, symbol: "X", present: true},
		{name: "incomplete_custom_arguments", callee: FuncSig{Ret: Void, Args: []LLVMType{Ptr, I64}, ArgRegs: []Reg{"R0"}}, symbol: "X", present: true},
		{name: "hidden_carrier", callee: FuncSig{Ret: Void, ARM64ClosureABI: &ARM64ClosureABI{}}, symbol: "X", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := arm64PrivateFrameTransport{entry: entry, resolve: resolve, sigs: make(map[string]FuncSig)}
			if tc.present {
				transport.sigs["X"] = tc.callee
			}
			state := arm64PrivateFrameAddresses{"R17": {offset: 32, exact: true}}
			ins := Instr{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: tc.symbol + "(SB)"}}}
			if got := transport.consume(ins, state, false); got != tc.want {
				t.Fatalf("typed terminator proof=%v, want %v", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		typ  LLVMType
		reg  Reg
		want bool
	}{
		{"unused_void", Void, "R17", true},
		{"unused_scalar_scratch", I64, "R17", true},
		{"private_integer_result", I64, "R0", false},
		{"private_pointer_result", Ptr, "R0", false},
		{"private_fp_result", "double", "F0", false},
		{"mixed_private_integer_result", "{ double, i64 }", "R0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := arm64PrivateFrameTransport{entry: FuncSig{Ret: tc.typ}}
			state := arm64PrivateFrameAddresses{tc.reg: {offset: 32, exact: true}}
			if got := transport.consume(Instr{Op: OpRET}, state, false); got != tc.want {
				t.Fatalf("typed result proof=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateUntransportedScratch(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, call := range []string{"CALL", "BL"} {
		t.Run(call, func(t *testing.T) {
			source := arm64PrivateLiveScratchSource(call)
			runARM64LocalRegisterGoOracle(t, source, `package main
import "unsafe"
func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr
func main() {
    for _,n:=range []int{0,1,2,7,8,16,17,31,32,33,64,131} {
        var src,dst,want [160]byte
        for i:=range src { src[i]=byte(i*71+29); dst[i]=0xa7; want[i]=0xa7 }
        copy(want[17:],src[5:5+n])
        if CopyLoop(unsafe.Pointer(&dst[17]),unsafe.Pointer(&src[5]),uintptr(n))!=uintptr(n) || dst!=want {
            panic("typed unused private scratch copy/canary mismatch")
        }
    }
}
`, len(runner) != 0, "1.20")
			ir := arm64CallCopyLoopModule(t, source, triple)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_unused_"+call, triple, ir, `#include <stdint.h>
#include <string.h>
extern uint64_t CopyLoop(void *,const void *,uint64_t);
void runtime_memmove(void *,const void *,uint64_t) __asm__("runtime.memmove");
void runtime_memmove(void *d,const void *s,uint64_t n) { memmove(d,s,(size_t)n); }
int main(void) {
    const int sizes[]={0,1,2,7,8,16,17,31,32,33,64,131};
    for(unsigned j=0;j<sizeof(sizes)/sizeof(sizes[0]);j++) {
        int n=sizes[j];
        unsigned char src[160],dst[160],want[160];
        for(int i=0;i<160;i++) { src[i]=(unsigned char)(i*71+29); dst[i]=0xa7; want[i]=0xa7; }
        memcpy(want+17,src+5,(size_t)n);
        if(CopyLoop(dst+17,src+5,(uint64_t)n)!=(uint64_t)n || memcmp(dst,want,sizeof(dst))) return 1;
    }
    return 0;
}
`, runner)
		})
	}
}

func TestARM64PrivateFrameUntransportedScratchObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	pkg := arm64PrivateCallDeclarations(t, "func CopyLoop(dst,src unsafe.Pointer,n uintptr) uintptr\n")
	callee := arm64CallInputMemmoveSig(t)
	resolve := func(sym string) string {
		return strings.ReplaceAll(goStripABISuffix(strings.TrimPrefix(sym, "·")), "·", ".")
	}
	for _, call := range []string{"CALL", "BL"} {
		source := arm64PrivateLiveScratchSource(call)
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatal("uncontracted source-only proof admitted a live scratch")
		}
		sizes := types.SizesFor("gc", "arm64")
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes,
			func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" })
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range arm64TypedNativeTargets {
			t.Run(call+"_"+target, func(t *testing.T) {
				opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs, ResolveSym: resolve}
				text, err := Translate(file, opt)
				if err != nil {
					t.Fatalf("typed unused private scratch: %v", err)
				}
				compileLLVMToObject(t, llc, target, "text.ll", "text.o", text)
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err != nil {
					t.Fatal(err)
				}
				defer module.Dispose()
				compileLLVMToObject(t, llc, target, "module.ll", "module.o", module.String())
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
					ManualSig: func(name string) (FuncSig, bool) { return callee, name == "runtime.memmove" },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer bound.Module.Dispose()
				compileLLVMToObject(t, llc, target, fmt.Sprintf("go-%s.ll", call), fmt.Sprintf("go-%s.o", call), bound.Module.String())
			})
		}
	}
}
