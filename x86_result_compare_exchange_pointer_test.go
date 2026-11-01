package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86PointerCompareExchangeFixture(arch, op, shape string) (string, string) {
	source, declaration := x86ResultCompareExchangeFixture(arch, op, shape == "locked", shape == "register")
	word, typ := "Q", "uint64"
	if arch == "386" {
		word, typ = "L", "uint32"
	}
	// A pointer word is not a numerical SIMD input. The independent pointer
	// fixture never borrows the existing numeric fixture's vector round trip.
	source = strings.Replace(source, "MOV"+word+" AX,X0\nMOV"+word+" X0,AX\n", "", 1)
	declaration = strings.Replace(declaration, "a,d,b,c "+typ, "a,d,b,c *byte", 1)
	return source, strings.Replace(declaration, ") uint8", ") bool", 1)
}

func TestX86CompareExchangeCallerPointerWordObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			ops := []string{"CMPXCHGQ", "CMPXCHG16B"}
			if target.arch == "386" {
				ops = []string{"CMPXCHGL", "CMPXCHG8B"}
			}
			var source, declarations strings.Builder
			for _, op := range ops {
				for _, shape := range []string{"memory", "locked", "register"} {
					if shape == "register" && strings.HasSuffix(op, "B") {
						continue // Original pair-register encodings are #UD.
					}
					body, declaration := x86PointerCompareExchangeFixture(target.arch, op, shape)
					name := "Pointer" + op + shape
					source.WriteString(strings.Replace(body, "·cas(SB)", "·"+name+"(SB)", 1))
					declarations.WriteString(strings.Replace(declaration, "func cas(", "func "+name+"(", 1) + "\n")
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete caller pointer words rejected by native CAS continuation", api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

func TestX86CompareExchangePointerInputBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		op, move, word := "CMPXCHGQ", "MOVQ", 8
		if target.arch == "386" {
			op, move, word = "CMPXCHGL", "MOVL", 4
		}
		for _, row := range []struct{ name, from, to string }{
			{"missing-source", fmt.Sprintf("%s c+%d(FP),CX\n", move, 4*word), ""},
			{"partial-source", fmt.Sprintf("%s c+%d(FP),CX", move, 4*word), fmt.Sprintf("MOVW c+%d(FP),CX", 4*word)},
			{"missing-expected", fmt.Sprintf("%s a+%d(FP),AX\n", move, word), ""},
			{"not-an-address", move + " p+0(FP),SI", move + " $0,SI"},
			{"unbound-frame", "$0-", "$8-"},
			{"raw-source", "LOCK\n", "BYTE $0x90\nLOCK\n"},
			{"pointer-not-numeric", "SETEQ ret+", "MOVB CX,ret+"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source, declarations := x86PointerCompareExchangeFixture(target.arch, op, "locked")
					if !strings.Contains(source, row.from) {
						t.Fatal("negative mutation lost its complete source operand", row.name)
					}
					source = strings.Replace(source, row.from, row.to, 1)
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("incomplete pointer/source role gained CAS transport", err)
					}
				})
			}
		}
	}
}

// A register CAS has no native memory access. This host-width LLVM oracle
// checks actual pointer values, not C _Bool attributes or native Go ABI entry.
func TestX86CompareExchangePointerRegisterPortable(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	const assembly = "TEXT ·Value(SB),4,$0-25\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ c+16(FP),CX\nCMPXCHGQ CX,BX\nSETEQ ret+24(FP)\nRET\n"
	const shim = `
define i32 @Probe(ptr %a,ptr %b,ptr %c) {
 %result = call i1 @Value(ptr %a,ptr %b,ptr %c)
 %output = zext i1 %result to i32
 ret i32 %output
}
`
	const driver = `extern int Probe(void*,void*,void*);
int main(void) {
 char values[3];
 for (unsigned a=0;a<3;a++)
  for (unsigned b=0;b<3;b++)
   for (unsigned c=0;c<3;c++)
    if (Probe(values+a,values+b,values+c)!=(a==b)) return 1;
 return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, "func Value(a,b,c *byte) bool", "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			ir += shim
			for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "pointer-cas", triple, input, driver, nil, level)
				}
			}
		})
	}
}

func TestX86CompareExchangePointerDoesNotAcquireNUM(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		op, word := "CMPXCHGQ", int64(8)
		if arch == "386" {
			op, word = "CMPXCHGL", 4
		}
		ins := x86ScalarLaneInstruction(t, op+" CX,(SI)")
		state := x86ResultState{}
		state.pointerGP[6], state.pointerGP[0], state.pointerGP[1] = true, true, true
		state.callerAddressGP[0], state.callerAddressGP[1] = true, true
		before := state.clone()
		if accepted, known := x86LoweredCompareExchangeResultStep(ins, &state, nil, arch); accepted || !known || !reflect.DeepEqual(state, before) {
			t.Fatal("unscoped numerical observer consumed opaque pointer words", word, accepted, known)
		}
	}
}

func TestX86CompareExchangePointerConditionalWordFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op    string
			width int64
			pair  bool
		}{
			{"CMPXCHGB", 1, false}, {"CMPXCHGW", 2, false},
			{"CMPXCHGL", 4, false}, {"CMPXCHGQ", 8, false},
			{"CMPXCHG8B", 4, true}, {"CMPXCHG16B", 8, true},
		} {
			if arch == "386" && row.width == 8 {
				continue // The original Go grammar rejects these two forms.
			}
			for _, register := range []bool{false, true} {
				if row.pair && register {
					continue // Original pair-register encodings are #UD.
				}
				body := row.op + " CX,(SI)"
				inputs := []int{0, 1}
				if row.pair {
					body, inputs = row.op+" (SI)", []int{0, 2, 3, 1}
				} else if register {
					body, inputs = row.op+" CX,BX", append(inputs, 3)
				}
				for _, opaque := range inputs {
					t.Run(fmt.Sprintf("%s/%s/register=%t/opaque=%d", arch, row.op, register, opaque), func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, body)
						mask := uint8((uint16(1) << uint(row.width)) - 1)
						state := x86ResultState{}
						for _, root := range []int{0, 1, 2, 3} {
							state.gp[root] = mask
						}
						state.pointerGP[6] = true
						state.gp[opaque] = 0
						state.pointerGP[opaque], state.callerAddressGP[opaque] = true, true
						before := state.clone()
						accepted, known := x86LoweredCompareExchangeResultStepWithAddressBits(ins, &state, nil, arch, true)
						if row.width != x86ResultPointerWord(arch) {
							if accepted || !known || !reflect.DeepEqual(state, before) {
								t.Fatal("partial pointer bits gained an input or changed state")
							}
							return
						}
						if !accepted || !known {
							t.Fatal("complete independently scoped caller word rejected")
						}
						outputs := []int{0}
						if row.pair {
							outputs = append(outputs, 2)
						} else if register {
							outputs = append(outputs, 3)
						}
						for _, root := range outputs {
							numeric := root != opaque
							if register {
								numeric = opaque != 3 && (root == 0 && opaque != 0 || root == 3 && opaque != 1)
							}
							want := uint8(0)
							if numeric {
								want = mask
							}
							if state.gp[root] != want || state.pointerGP[root] {
								t.Fatal("conditional CAS invented NUM or pointer identity", root, state.gp[root], want)
							}
						}
						before.callerAddressGP[opaque] = false
						withoutCaller := before.clone()
						if accepted, known := x86LoweredCompareExchangeResultStepWithAddressBits(ins, &withoutCaller, nil, arch, true); accepted || !known || !reflect.DeepEqual(withoutCaller, before) {
							t.Fatal("opaque identity alone supplied actual caller-word bits")
						}
					})
				}
			}
		}
	}
}

func TestX86CompareExchangeBoundPrefixKeepsOnlyPriorCallerWords(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		prefix := x86ScalarLaneInstruction(t, "LOCK")
		before, transferred := [16]bool{true, false, true}, [16]bool{true, true, false}
		if got := x86ResultCallerAddressesAfterTransfer(prefix, before, transferred, nil, arch); got != ([16]bool{true}) {
			t.Fatal("paired prefix invented or revived a caller word", got)
		}
		if got := x86ResultCallerAddressesAfter(prefix, before, nil, arch); got != ([16]bool{}) {
			t.Fatal("standalone overwrite query borrowed a bound source prefix", got)
		}
	}
}
