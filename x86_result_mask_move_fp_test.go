package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var x86MaskMoveFPOracle = []struct {
	op          string
	bits, input int
}{
	{"KMOVB", 8, 0}, {"KMOVW", 16, 0}, {"KMOVD", 32, 0}, {"KMOVQ", 64, 0},
	{"KMOVB", 8, 3}, {"KMOVW", 16, 3}, {"KMOVD", 32, 2},
}

func x86MaskMoveFPFixture() (string, string, []string) {
	var source, declarations strings.Builder
	var names []string
	for index, row := range x86MaskMoveFPOracle {
		name := fmt.Sprintf("MaskFP%d", index)
		names = append(names, name)
		fmt.Fprintf(&declarations, "func %s(a,b uint32) uint64\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\n"+
			"MOVL $0x11223344,AX\nMOVL AX,ret+8(FP)\n"+
			"MOVL $0x55667788,AX\nMOVL AX,ret+12(FP)\n"+
			"%s a+%d(FP),K1\n%s K1,ret+8(FP)\nRET\n", name, row.op, row.input, row.op)
	}
	return source.String(), declarations.String(), names
}

func TestX86MaskMoveLogicalFPExactReadAndWriteWidths(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source, declarations, names := x86MaskMoveFPFixture()
	if len(names) != 7 {
		t.Fatal("complete FP width/cross-field denominator changed", len(names))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete logical mask movement rejected", api, err)
				}
				x86CompactExpandRequireAllDefinitions(t, ir, names)
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86MaskMoveLogicalFPExactBytesPortableRuntime(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	source, declarations, names := x86MaskMoveFPFixture()
	var prototypes, checks strings.Builder
	for index, name := range names {
		row := x86MaskMoveFPOracle[index]
		fmt.Fprintf(&prototypes, "extern uint64_t %s(uint32_t,uint32_t);\n", name)
		fmt.Fprintf(&checks, "if(check(%s,\"%s\",%d,%d)) return 1;\n", name, name, row.bits, row.input)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static int check(uint64_t (*fn)(uint32_t,uint32_t),const char *name,unsigned bits,unsigned offset) {
    const uint32_t values[]={0,1,UINT32_MAX,UINT32_C(0x89abcdef),UINT32_C(0x12345678)};
    uint64_t mask=bits==64 ? UINT64_MAX : (UINT64_C(1)<<bits)-1;
    for(unsigned a=0;a<5;a++) for(unsigned b=0;b<5;b++) {
        uint64_t source=(uint64_t)values[a]|((uint64_t)values[b]<<32);
        uint64_t expected=(UINT64_C(0x5566778811223344)&~mask)|((source>>(8*offset))&mask);
        uint64_t actual=fn(values[a],values[b]);
        if(actual!=expected) {
            fprintf(stderr,"%s a=%x b=%x actual=%llx expected=%llx\n",name,values[a],values[b],
                    (unsigned long long)actual,(unsigned long long)expected);
            return 1;
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete logical FP mask source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "mask-fp", triple, text, oracle, nil, level)
				}
			}
		})
	}
}

func TestX86NumericalEffectConsumesOnlyCheckedCallerContinuation(t *testing.T) {
	_, _, options, source := x86PrivateReadObserverFixture(t)
	signature := options.Sigs["caller.kernel"]
	for _, mutation := range []string{"complete", "inferred-features", "foreign-features", "unbound-features", "changed-declaration", "missing-declaration-caller", "missing-caller", "changed-signature", "changed-source", "different-stack", "different-arch"} {
		t.Run(mutation, func(t *testing.T) {
			consumer, _ := newAMD64CtxWithFuncForTest(t, source, signature, nil)
			switch mutation {
			case "inferred-features":
				consumer.fpFeatureAttrs, consumer.sig.Attrs = "#17", "#17"
			case "foreign-features":
				consumer.fpFeatureAttrs, consumer.sig.Attrs = "#17", "#18"
			case "unbound-features":
				consumer.sig.Attrs = "#17"
			case "changed-declaration":
				consumer.fpSourceSig.Name += ".foreign"
			case "missing-declaration-caller":
				consumer.fpSourceSig.x86CallerRegions = nil
			case "missing-caller":
				consumer.sig.x86CallerRegions = nil
			case "changed-signature":
				consumer.sig.Name += ".foreign"
			case "changed-source":
				consumer.fpScalarSource.Instrs = append(append([]Instr(nil), source.Instrs...), Instr{Op: "NOP"})
			case "different-stack":
				copy := *consumer.sourceStack
				consumer.sourceStack = &copy
			case "different-arch":
				consumer.goarch = "386"
			}
			err := consumer.integerEffectResultInitialized("mask movement")
			if mutation == "complete" || mutation == "inferred-features" {
				if err != nil || consumer.fpScalarChecked {
					t.Fatal("complete caller proof was lost or impersonated a logical FP proof", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("edited or missing complete caller proof became numerical authority", err)
			}
		})
	}
}
