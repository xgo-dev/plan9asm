package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86VectorUpperOracle struct {
	name      string
	binary    bool
	immediate bool
}

// Seed every physical byte, not only the X view. These original instructions
// are accepted by both named frontends, including 386's three-operand limit.
const x86VectorNonzeroUpperSeed = "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" +
	"VPXORD Z2,Z2,Z2\nVPXORD Z7,Z7,Z7\nMOVL $-1,AX\nVPBROADCASTD AX,Z2\n" +
	"MOVL $0,AX\nKMOVD AX,K1\nVPCOMPRESSQ Z0,K1,Z7\n"

func x86VectorUpperMembers() []x86VectorUpperOracle {
	var members []x86VectorUpperOracle
	for _, op := range x86CompactExpandResultMembers {
		members = append(members, x86VectorUpperOracle{name: op})
	}
	for _, op := range x86IndexedPermuteResultNames {
		members = append(members, x86VectorUpperOracle{name: op, binary: true})
	}
	for _, row := range x86GFNIResultOracle {
		members = append(members, x86VectorUpperOracle{name: row.name, binary: true, immediate: row.immediate})
	}
	for _, row := range x86BitCountResultOracle {
		members = append(members, x86VectorUpperOracle{name: row.name})
	}
	return members
}

func x86VectorUpperFixture(arch string) (string, string, []string) {
	var source, declarations strings.Builder
	var names []string
	for _, member := range x86VectorUpperMembers() {
		for _, bank := range []string{"X", "Y"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				arity := 2
				if member.binary {
					arity++
				}
				if member.immediate {
					arity++
				}
				if mode != "plain" {
					arity++
				}
				if arch == "386" && arity > 3 {
					continue // Original named frontend limit, not an execution skip.
				}
				op, mask, second, immediate := member.name, "", "", ""
				if mode != "plain" {
					mask = "K1,"
				}
				if mode == "zero" {
					op += ".Z"
				}
				if member.binary {
					second = bank + "1,"
				}
				if member.immediate {
					immediate = "$0,"
				}
				name := "Value" + member.name + bank + mode
				names = append(names, name)
				fmt.Fprintf(&declarations, "func %s() uint32\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n"+x86VectorNonzeroUpperSeed+
					"%s %s%s0,%s%s%s2\nVEXTRACTI32X4 $3,Z2,X3\nPEXTRD $0,X3,AX\nMOVL AX,ret+0(FP)\nRET\n",
					name, op, immediate, bank, second, mask, bank)
			}
		}
	}
	return source.String(), declarations.String(), names
}

func x86VectorUpperNativeFixture(arch string) (string, string, []string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	var names []string
	for _, member := range x86CompactExpandResultMembers {
		if !strings.Contains(member, "EXPAND") {
			continue // Compression has no memory-to-vector encoding.
		}
		for _, bank := range []string{"X", "Y"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				op, mask := member, ""
				if mode != "plain" {
					mask = "K1,"
				}
				if mode == "zero" {
					op += ".Z"
				}
				name := "Native" + member + bank + mode
				names = append(names, name)
				fmt.Fprintf(&declarations, "func %s(p *[64]byte) uint32\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DI\n"+
					x86VectorNonzeroUpperSeed+
					"%s (DI),%s%s2\nVEXTRACTI32X4 $3,Z2,X3\nPEXTRD $0,X3,AX\nMOVL AX,ret+%d(FP)\nRET\n",
					name, word+4, move, op, mask, bank, word)
			}
		}
	}
	return source.String(), declarations.String(), names
}

func x86VectorUpperRequireZeroReturns(t *testing.T, ir string, names []string) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			function := module.NamedFunction(name)
			if function.IsNil() || function.FirstBasicBlock().IsNil() {
				t.Fatal("original nonzero-upper source body disappeared")
			}
			returns := 0
			for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
				terminator := block.LastInstruction()
				if terminator.IsNil() || terminator.InstructionOpcode() != llvm.Ret {
					continue
				}
				returns++
				if terminator.OperandsCount() != 1 || terminator.Operand(0).IsAConstantInt().IsNil() || terminator.Operand(0).ZExtValue() != 0 {
					t.Fatal("VEX/EVEX write retained old nonzero upper bytes", terminator.String())
				}
			}
			if returns != 1 {
				t.Fatal("missing exact independent upper-quarter result", returns)
			}
		})
	}
}

func TestX86VectorValueFamiliesClearNonzeroUpperAliases(t *testing.T) {
	if len(x86VectorUpperMembers()) != 35 {
		t.Fatal("complete independently inventoried family changed")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86VectorUpperFixture(target.arch)
			want := 210
			if target.arch == "386" {
				want = 138
			}
			if len(names) != want {
				t.Fatal("whole-family write-width/mask denominator changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized nonzero-upper source rejected", err)
					}
					x86VectorUpperRequireZeroReturns(t, ir, names)
				})
			}
		})
	}
}

func TestX86CompactNativeExpandClearsNonzeroUpperAliases(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86VectorUpperNativeFixture(target.arch)
			if len(names) != 36 {
				t.Fatal("complete native expand upper-alias denominator changed", len(names))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized native expand source rejected", err)
					}
					x86VectorUpperRequireZeroReturns(t, ir, names)
				})
			}
		})
	}
}

func TestX86VectorValueUpperAliasesPortableRuntime(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	source, declarations, names := x86VectorUpperFixture("amd64")
	nativeSource, nativeDeclarations, nativeNames := x86VectorUpperNativeFixture("amd64")
	if len(names) != 210 || len(nativeNames) != 36 {
		t.Fatal("complete runtime family denominator changed", len(names), len(nativeNames))
	}
	var prototypes, checks strings.Builder
	for _, name := range names {
		fmt.Fprintf(&prototypes, "extern uint32_t %s(void);\n", name)
		fmt.Fprintf(&checks, "if(check(%s(),\"%s\")) return 1;\n", name, name)
	}
	for _, name := range nativeNames {
		fmt.Fprintf(&prototypes, "extern uint32_t %s(const uint8_t*);\n", name)
		fmt.Fprintf(&checks, "if(check(%s(input),\"%s\")) return 1;\n", name, name)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static int check(uint32_t value,const char *name) {
    if(value==0) return 0;
    fprintf(stderr,"%s retained old upper quarter: %x\n",name,value);
    return 1;
}
int main(void) {
    uint8_t input[64]={0};
` + checks.String() + "return 0;\n}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source+nativeSource, declarations+nativeDeclarations, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete portable upper-alias source rejected", err)
			}
			for _, optimized := range []bool{false, true} {
				objectIR := ir
				if optimized {
					objectIR = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "vector-upper", triple, objectIR, oracle, nil, level)
					})
				}
			}
		})
	}
	if !t.Failed() {
		t.Log("246 complete-family programs passed on the actual host; portable LLVM, not original-Go/native AVX512")
	}
}
