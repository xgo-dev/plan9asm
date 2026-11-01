package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86Legacy386OriginalStackAdjust = `TEXT stackAdjust(SB),NOSPLIT,$0-0
	PUSHFL
	ADJSP $156
	MOVL AX, 152(SP)
	ADJSP $-156
	POPFL
	RET
`

const x86Legacy386OriginalIDProbe = `TEXT cpuidProbe(SB),NOSPLIT,$0-0
	PUSHFL
	PUSHFL
	XORL $0x200000, 0(SP)
	POPFL
	PUSHFL
	POPL AX
	XORL 0(SP), AX
	POPFL
	TESTL $0x200000, AX
	JNE cpuidAvailable
	MOVL $0, AX
	RET
cpuidAvailable:
	MOVL $1, AX
	RET
`

const x86Legacy386OriginalStrings = `TEXT strings386(SB),NOSPLIT,$0-0
	CLD
	REP; MOVSB
	STD
	REP; MOVSL
	CLD
	REP; STOSL
	REPN; SCASB
	RET
`

const x86Legacy386OriginalMMXLoad = `TEXT mmxload(SB),NOSPLIT,$0-0
	MOVQ (SI), M0
	MOVL M0, AX
	EMMS
	RET
`

// Explicit register assignments in a format fixture do not establish a Go
// native entry contract. These separate ABI0 counterparts retain every body
// instruction, load their actual declared inputs and publish a typed result.
func x86Legacy386RegisterCounterparts(t *testing.T, source string, sigs map[string]FuncSig) string {
	t.Helper()
	stringsBody := strings.Replace(x86Legacy386OriginalStrings, "$0-0\n", "$0-16\n"+
		"\tMOVL src+0(FP),SI\n\tMOVL dst+4(FP),DI\n\tMOVL count+8(FP),CX\n\tMOVL value+12(FP),AX\n", 1)
	mmxBody := strings.Replace(x86Legacy386OriginalMMXLoad, "$0-0\n", "$0-8\n\tMOVL input+0(FP),SI\n", 1)
	mmxBody = strings.Replace(mmxBody, "\tRET\n", "\tMOVL AX,ret+4(FP)\n\tRET\n", 1)
	for _, row := range []struct{ before, after string }{
		{x86Legacy386OriginalStrings, stringsBody}, {x86Legacy386OriginalMMXLoad, mmxBody},
	} {
		if strings.Count(source, row.before) != 1 {
			t.Fatal("complete original register fixture anchor changed")
		}
		source = strings.Replace(source, row.before, row.after, 1)
	}
	sigs["strings386"] = FuncSig{Name: "strings386", Args: []LLVMType{Ptr, Ptr, I32, I32}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1},
			{Offset: 8, Type: I32, Index: 2, Field: -1}, {Offset: 12, Type: I32, Index: 3, Field: -1},
		}}}
	sigs["mmxload"] = FuncSig{Name: "mmxload", Args: []LLVMType{Ptr}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
		}}
	return source
}

func TestX86Legacy386RegisterCounterpartsThreeAPIs(t *testing.T) {
	sigs := make(map[string]FuncSig)
	source := x86Legacy386RegisterCounterparts(t, x86Legacy386OriginalStrings+x86Legacy386OriginalMMXLoad, sigs)
	declarations := "func strings386(src,dst *byte,count,value uint32)\nfunc mmxload(input *byte) uint32\n"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, strings.ReplaceAll(source, ",NOSPLIT,", ",4,"))
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			}
		})
	}
}

// These separate programs have explicit inputs, initial FLAGS and result
// slots. Neither supplies native entry FLAGS or physical-SP backing to an
// original fixture. The original ADJSP and physical-memory forms stay in the
// complete emitter-only object below, not in these public execution claims.
const x86Legacy386InitializedStack = `TEXT stackAdjust(SB),4,$156-8
	PUSHL $2
	POPFL
	MOVL value+0(FP),AX
	MOVL AX,spill-4(SP)
	STC
	PUSHFL
	CLC
	POPFL
	SETCS CL
	MOVBLZX CL,CX
	SHLL $8,CX
	MOVL spill-4(SP),AX
	ANDL $255,AX
	ORL CX,AX
	MOVL AX,ret+4(FP)
	RET
`

const x86Legacy386InitializedIDProbe = `TEXT cpuidProbe(SB),4,$0-4
	PUSHL $2
	POPFL
	PUSHFL
	POPL AX
	MOVL AX,CX
	XORL $0x200000,AX
	PUSHL AX
	POPFL
	PUSHFL
	POPL AX
	PUSHL CX
	POPFL
	XORL CX,AX
	TESTL $0x200000,AX
	JNE cpuidAvailable
	MOVL $0,AX
	JMP cpuidDone
cpuidAvailable:
	MOVL $1,AX
cpuidDone:
	MOVL AX,ret+0(FP)
	RET
`

func x86Legacy386StackCounterparts(t *testing.T, original string) string {
	t.Helper()
	for _, row := range []struct{ original, initialized string }{
		{x86Legacy386OriginalStackAdjust, x86Legacy386InitializedStack},
		{x86Legacy386OriginalIDProbe, x86Legacy386InitializedIDProbe},
	} {
		if strings.Count(original, row.original) != 1 {
			t.Fatal("complete original stack fixture anchor changed")
		}
		original = strings.Replace(original, row.original, row.initialized, 1)
	}
	return original
}

// Preserve the complete ADJSP and ID sources. The former still needs physical
// storage. The latter's bounded private FLAGS copies cancel the unknown entry
// ID bit, so its separately checked logical result needs no native SP backing.
func x86Legacy386StackFormatObject(t *testing.T, triple string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, x86Legacy386OriginalStackAdjust+x86Legacy386OriginalIDProbe)
	if err != nil || len(file.Funcs) != 2 {
		t.Fatal("complete original stack/ID format inventory changed", err)
	}
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	emitAMD64Prelude(&ir, "386", file)
	for _, fn := range file.Funcs {
		ret := Void
		if fn.Sym == "cpuidProbe" {
			ret = I32
		}
		sig := FuncSig{Name: fn.Sym, Ret: ret}
		fmt.Fprintf(&ir, "define %s %s() {\n", ret, llvmGlobal(fn.Sym))
		consumer := newX86Ctx(&ir, fn, sig, func(name string) string { return name }, nil, "386", triple, false)
		if err := consumer.emitEntryAllocas(); err != nil {
			t.Fatal(err)
		}
		if err := consumer.lowerBlocks(); err != nil {
			t.Fatal("original source format was not emitted completely", fn.Sym, err)
		}
		ir.WriteString("}\n")
	}
	return ir.String()
}

func TestX86Legacy386StackFixturesKeepOriginalContextAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			for _, row := range []struct {
				name, source string
				ret          LLVMType
			}{
				{"stackAdjust", x86Legacy386OriginalStackAdjust, Void},
				{"cpuidProbe", x86Legacy386OriginalIDProbe, I32},
			} {
				x86LEAActualTargetGoObject(t, "386", triple, strings.ReplaceAll(row.source, ",NOSPLIT,", ",4,"))
				pkg := mustGoPackage(t, "legacy386", "package legacy386")
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, row.source, pkg, "386", triple, api,
						func(name string) (FuncSig, bool) {
							return FuncSig{Name: row.name, Ret: row.ret}, name == row.name
						})
					if row.name == "cpuidProbe" {
						if err != nil {
							t.Fatal("balanced private ID correlation lost its defined logical result", api, err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, text, level)
							}
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("original physical stack acquired a public entry/backing contract", row.name, api, err)
					}
				}
			}
			ir := x86Legacy386StackFormatObject(t, triple)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
		})
	}
}

func TestX86Legacy386InitializedStackFixturesThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const declarations = "func stackAdjust(value uint32) uint32\nfunc cpuidProbe() uint32\n"
	const source = x86Legacy386InitializedStack + x86Legacy386InitializedIDProbe
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized stack/ID program lost its complete source proof", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86Legacy386InitializedStackFixturesPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t stackAdjust(uint32_t);
extern uint32_t cpuidProbe(void);
int main(void) {
    const uint32_t values[]={0,1,7,127,128,255,256,65535,0x12345678,UINT32_MAX};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint32_t v=values[i],want=(v&255)|256;
        uint32_t got=stackAdjust(v),id=cpuidProbe();
        if(got!=want||id!=1) {
            fprintf(stderr,"legacy386 case=%u value=%x got=%x want=%x id=%x\n",i,v,got,want,id);
            return 1;
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86Legacy386InitializedStack+x86Legacy386InitializedIDProbe,
				"func stackAdjust(value uint32) uint32\nfunc cpuidProbe() uint32\n", "386", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "asm ") {
				t.Fatal("portable numerical stack test acquired native ISA execution")
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "legacy386-stack-values", triple, text, driver, nil, level)
				}
			}
		})
	}
}
