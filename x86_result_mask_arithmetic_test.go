package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Independent of the implementation maps: the complete Go KADD/KSHIFT and
// KUNPCK families have 15 names and two operand rows (_ykaddb/_ykshiftlb).
var x86MaskNumericalOracle = []struct {
	op    string
	bits  int
	shift bool
}{
	{"KADDB", 8, false}, {"KADDW", 16, false},
	{"KADDD", 32, false}, {"KADDQ", 64, false},
	{"KSHIFTLB", 8, true}, {"KSHIFTLW", 16, true},
	{"KSHIFTLD", 32, true}, {"KSHIFTLQ", 64, true},
	{"KSHIFTRB", 8, true}, {"KSHIFTRW", 16, true},
	{"KSHIFTRD", 32, true}, {"KSHIFTRQ", 64, true},
	{"KUNPCKBW", 8, false}, {"KUNPCKWD", 16, false}, {"KUNPCKDQ", 32, false},
}

func TestX86MaskArithmeticCompletePortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	var source, declarations, prototypes, checks strings.Builder
	count := 0
	for _, row := range x86MaskNumericalOracle {
		counts := []int{0}
		operation := 0
		if row.shift {
			counts = []int{0, row.bits - 1, row.bits, 255}
			operation = 1
			if strings.HasPrefix(row.op, "KSHIFTR") {
				operation = 2
			}
		} else if strings.HasPrefix(row.op, "KUNPCK") {
			operation = 3
		}
		for _, shift := range counts {
			name := fmt.Sprintf("MaskValue%d", count)
			count++
			first := "K0"
			if row.shift {
				first = fmt.Sprintf("$%d", shift)
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nKMOVQ a+0(FP),K0\nKMOVQ b+8(FP),K7\n"+
				"%s %s,K7,K3\nKMOVQ K3,ret+16(FP)\nRET\n", name, row.op, first)
			fmt.Fprintf(&declarations, "func %s(a,b uint64) uint64\n", name)
			fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if(check(%s,\"%s\",%d,%d,%d)) return 1;\n", name, name, operation, row.bits, shift)
		}
	}
	if count != 39 {
		t.Fatal("complete runtime family/count denominator changed", count)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static int check(uint64_t (*fn)(uint64_t,uint64_t),const char *name,unsigned op,unsigned bits,unsigned count) {
 const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x89abcdef01234567),UINT64_C(0x8000000000000000),UINT64_C(0x55555555aaaaaaaa)};
 uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1;
 for(unsigned a=0;a<6;a++) for(unsigned b=0;b<6;b++) {
  uint64_t x=values[a]&mask,y=values[b]&mask,expected=0;
  if(op==0) expected=(x+y)&mask;
  if(op==1 && count<bits) expected=(y<<count)&mask;
  if(op==2 && count<bits) expected=y>>count;
  if(op==3) expected=x|(y<<bits);
  uint64_t actual=fn(values[a],values[b]);
  if(actual!=expected) {
   fprintf(stderr,"%s a=%llx b=%llx got=%llx want=%llx\n",name,
    (unsigned long long)values[a],(unsigned long long)values[b],(unsigned long long)actual,(unsigned long long)expected);
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
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete initialized mask-value runtime rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "mask-values", triple, text, oracle, nil, level)
				}
			}
		})
	}
}

func TestX86MaskArithmeticNumericalInputsAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86MaskNumericalOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				for destination := 0; destination < 8; destination++ {
					for seed := 0; seed < 256; seed++ {
						first := "K0"
						if row.shift {
							first = "$255"
						}
						ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s,K7,K%d", row.op, first, destination))
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.pointerGP[0] = 0x93, true
						for mask := range state.masks {
							state.masks[mask] = seed&(1<<mask) != 0
						}
						before := state.clone()
						want := state.masks[7] && (row.shift || state.masks[0])
						if accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch); accepted != want {
							t.Fatalf("missing or invented input: destination=%d seed=%x accepted=%v want=%v", destination, seed, accepted, want)
						}
						if want {
							before.masks[destination] = true
						}
						if !reflect.DeepEqual(state, before) {
							t.Fatal("mask result changed GP, FLAGS, memory or an unrelated mask")
						}
					}
				}
			})
		}
	}
}

func TestX86MaskArithmeticRejectsNonIntegerImmediateConsumers(t *testing.T) {
	for _, row := range x86MaskNumericalOracle {
		if !row.shift {
			continue
		}
		for _, value := range []string{"$0.0", "$1.0", "$UNRESOLVED", "$-1", "$256"} {
			t.Run(row.op+"/"+value, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" "+value+",K1,K2")
				for _, arch := range []string{"386", "amd64"} {
					control := x86ScalarLaneInstruction(t, row.op+" $1,K1,K2")
					consumer, _ := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{control}}, FuncSig{Ret: Void}, nil)
					consumer.goarch = arch
					if err := consumer.lowerMaskArithmetic(control.Op, control); err != nil {
						t.Fatal("valid immediate control did not reach the lowerer", err)
					}
					if err := consumer.lowerMaskArithmetic(ins.Op, ins); err == nil {
						t.Fatal("lowerer accepted a non-Yu8 immediate", arch, value)
					}
					state := x86ResultState{}
					state.masks[1] = true
					before := state.clone()
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
						t.Fatal("invalid immediate acquired numerical authority", arch, value)
					}
				}
			})
		}
	}
}

func TestX86MaskArithmeticVoidCannotInventInputs(t *testing.T) {
	for _, row := range x86MaskNumericalOracle {
		t.Run(row.op, func(t *testing.T) {
			first := "K0"
			if row.shift {
				first = "$255"
			}
			source := "TEXT ·Value(SB),4,$0-0\n" + row.op + " " + first + ",K7,K3\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, arch := range []string{"386", "amd64"} {
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unknown mask input borrowed implementation zeros", arch, api, err)
					}
				}
			}
		})
	}
}

func TestX86MaskArithmeticCompleteResultFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			var names []string
			for _, row := range x86MaskNumericalOracle {
				counts := []int{0}
				if row.shift {
					counts = []int{0, row.bits - 1, row.bits, 255}
				}
				for _, count := range counts {
					name := fmt.Sprintf("MaskResult%d", len(names))
					names = append(names, name)
					first := "K0"
					if row.shift {
						first = fmt.Sprintf("$%d", count)
					}
					fmt.Fprintf(&declarations, "func %s(a,b uintptr) uintptr\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s a+0(FP),AX\nKMOVD AX,K0\n"+
						"%s b+%d(FP),AX\nKMOVD AX,K7\n%s %s,K7,K3\nKMOVD K3,BX\n%s BX,ret+%d(FP)\nRET\n",
						name, 3*word, move, move, word, row.op, first, move, 2*word)
				}
			}
			if len(names) != 39 {
				t.Fatal("complete operation/count denominator changed", len(names))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete initialized mask result rejected", api, err)
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
