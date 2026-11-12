package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86LogicalAUTOProjectionRequiresCompleteSource(t *testing.T) {
	file, sig, _ := x86ResultAUTOFixture(t, "386", "func Value(x uint32) uint32", 32,
		"MOVL x+0(FP),AX\nMOVL AX,saved-4(SP)\nPUSHL $7\nPOPL BX\nMOVL saved-4(SP),AX\nMOVL AX,ret0+4(FP)\nRET")
	makeConsumer := func() *amd64Ctx {
		fn := file.Funcs[0]
		fn.Instrs = append([]Instr(nil), fn.Instrs...)
		return newX86Ctx(new(strings.Builder), fn, sig,
			func(name string) string { return strings.TrimPrefix(name, "·") }, nil,
			"386", "i386-unknown-linux-gnu", false)
	}
	for _, checked := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing-or-failed-proof-%v", checked), func(t *testing.T) {
			consumer := makeConsumer()
			consumer.fpScalarChecked = checked
			if checked {
				consumer.fpScalarCheckErr = ErrProbeNeedsContext
			}
			if err := consumer.prepareLogicalAUTOStorage(); err != nil || consumer.logicalAUTOExtent != 0 || consumer.logicalAUTOBase != "" {
				t.Fatal("missing/failed source proof supplied logical storage", err)
			}
		})
	}
	for _, mutation := range []string{"unchanged", "changed-frame", "changed-literal"} {
		t.Run(mutation, func(t *testing.T) {
			consumer := makeConsumer()
			if err := consumer.scalarFPResultInitialized(); err != nil {
				t.Fatal("independent complete source rejected", err)
			}
			switch mutation {
			case "changed-frame":
				consumer.frameSize *= 2
			case "changed-literal":
				consumer.fpScalarSource.Instrs[2].Raw = "MOVL AX,-4(SP)"
			}
			err := consumer.emitEntryAllocas()
			if mutation != "unchanged" {
				if !errors.Is(err, ErrProbeNeedsContext) || consumer.logicalAUTOBase != "" {
					t.Fatal("changed source revived a cached storage projection", err)
				}
				return
			}
			if err != nil || consumer.logicalAUTOExtent != 32 || consumer.logicalAUTOBase == "" {
				t.Fatal("complete ordinary source lost its immutable entry base", err)
			}
			for _, memory := range []MemRef{
				{Base: SP, Off: -33}, {Base: SP}, {Base: SP, Off: -4, OffRaw: "missing"},
				{Base: SP, Off: -4, Index: AX}, {Base: SP, Off: -4, Scale: 2},
				{Base: SP, Off: -4, Segment: FS},
			} {
				address, recognized, err := consumer.logicalAUTOAddress(memory)
				if !recognized || !errors.Is(err, ErrProbeNeedsContext) || address != "" {
					t.Fatal("unbound address borrowed logical AUTO bytes", memory, err)
				}
			}
			// Go's 386 SB Reg annotation is ignored, not a physical SP input.
			memory := MemRef{Base: SP, Sym: "literal(SB)"}
			if _, recognized, err := consumer.logicalAUTOAddress(memory); recognized || err != nil {
				t.Fatal("logical AUTO projection captured an independent static-symbol role", err)
			}
		})
	}
}

func TestX86LogicalAUTOStaticSPAnnotationKeepsIndependentRole(t *testing.T) {
	const source = `DATA literal<>+0(SB)/4,$0x12345678
GLOBL literal<>(SB),8,$4
TEXT ·StaticAUTO(SB),4,$32-8
MOVL value+0(FP),AX
MOVL AX,saved-4(SP)
PUSHL $7
POPL BX
MOVL literal<>(SB)(SP),BX
MOVL saved-4(SP),AX
XORL BX,AX
MOVL AX,ret+4(FP)
RET
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func StaticAUTO(value uint32) uint32", "386", triple, api)
				if err != nil {
					t.Fatal("logical AUTO captured Go's independent ignored SP annotation", api, err)
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

// The original Go AUTO address is above the post-prologue SP. Private PUSH
// storage is below it. Keep those distinct even though parsed AUTO offsets
// are negative. No physical SP/address or native frame permission is supplied.
func x86LogicalAUTOPrivateStackSources(arch string) (string, string, string) {
	word, typ, ctype, bytes := "Q", "uint64", "uint64_t", 8
	if arch == "386" {
		word, typ, ctype, bytes = "L", "uint32", "uint32_t", 4
	}
	var source, declarations, driver strings.Builder
	fmt.Fprintf(&driver, "#include <stdint.h>\n#include <stdio.h>\ntypedef %s word;\n", ctype)
	var checks strings.Builder
	for index, push := range []string{"PUSHW $7", "PUSH" + word + " $7", "PUSHFW", "PUSHF" + word} {
		pop := "POP" + word + " BX"
		if index == 0 || index == 2 {
			pop = "POPW BX"
		}
		name := fmt.Sprintf("AutoStack%d", index)
		fmt.Fprintf(&source, `TEXT ·%s(SB),4,$32-%d
PUSH%s $2
POPF%s
MOV%s value+0(FP),AX
MOV%s AX,saved-%d(SP)
%s
%s
MOV%s saved-%d(SP),AX
MOV%s AX,ret+%d(FP)
RET
`, name, 2*bytes, word, word, word, word, bytes, push, pop, word, bytes, word, bytes)
		fmt.Fprintf(&declarations, "func %s(value %s) %s\n", name, typ, typ)
		fmt.Fprintf(&driver, "extern word %s(word);\n", name)
		fmt.Fprintf(&checks, `{
    word got=%s(value);
    if(got!=value) {
        fprintf(stderr,"AUTO/private-stack row=%d value=%%llx got=%%llx\n",
            (unsigned long long)value,(unsigned long long)got);
        return 1;
    }
}
`, name, index)
	}
	driver.WriteString(`int main(void) {
    const word values[]={0,1,7,255,256,65535,65536,UINT32_MAX,(word)UINT64_MAX,
        (word)UINT64_C(0x1122334455667788),(word)UINT64_C(0x8000000000000000)};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        word value=values[i];
`)
	driver.WriteString(checks.String())
	driver.WriteString("    }\n    return 0;\n}\n")
	return source.String(), declarations.String(), driver.String()
}

func TestX86LogicalAUTOPrivateStackFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _ := x86LogicalAUTOPrivateStackSources(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86LogicalAUTOPrivateStackPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, driver := x86LogicalAUTOPrivateStackSources(arch)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []int{0, 2} {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "auto-private-stack-values", triple, text, driver, nil, level)
					}
				}
			})
		}
	}
}
