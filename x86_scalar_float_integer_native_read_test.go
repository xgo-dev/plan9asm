package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The independent namespace already checks all 32 original Go encoder rows.
// These source-bound cases exercise their common m32/m64 native continuation,
// not a declaration-only promise that an opaque pointer has initialized bytes.
func x86ScalarIntegerNativeNames(arch string) []string {
	var names []string
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		if arch == "386" && !strings.HasPrefix(name, "V") && strings.HasSuffix(name, "Q") {
			continue
		}
		names = append(names, name)
	}
	return names
}

func x86ScalarIntegerNativeSource(arch, symbol, name, variant string, live bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	setup := fmt.Sprintf("%s p+0(FP),DI\n%s csr+%d(FP),SI\n", move, move, word)
	operand := "(DI)"
	switch variant {
	case "index":
		setup += "MOVL $0,CX\n"
		operand = "(DI)(CX*1)"
	case "missing-pointer":
		setup = fmt.Sprintf("%s csr+%d(FP),SI\n", move, word)
	case "numeric-pointer":
		setup += move + " $4096,DI\n"
	case "missing-index":
		operand = "(DI)(CX*1)"
	case "opaque-index":
		setup += move + " p+0(FP),CX\n"
		operand = "(DI)(CX*2)"
	case "missing-vector":
		operand = "X1"
	case "initialized-vector":
		setup += "PXOR X1,X1\n"
		operand = "X1"
	case "missing-mxcsr-pointer":
		setup = move + " p+0(FP),DI\n"
	}
	frame, result, ret := 2*word, "", ""
	if live {
		frame += 4
		result = fmt.Sprintf("MOVL AX,ret+%d(FP)\n", 2*word)
		ret = " uint32"
	} else {
		result = "XORL AX,AX\n"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%sLDMXCSR (SI)\n%s %s,AX\n%sRET\n",
		symbol, frame, setup, name, operand, result)
	declaration := fmt.Sprintf("func %s(p *uint64,csr *uint32)%s\n", symbol, ret)
	return source, declaration
}

func TestX86ScalarFloatIntegerPairedNativeReadCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			type function struct {
				name  string
				width int
			}
			var functions []function
			for _, name := range x86ScalarIntegerNativeNames(target.arch) {
				for _, live := range []bool{false, true} {
					symbol := fmt.Sprintf("native%d", len(functions))
					variant := ""
					if live {
						variant = "index"
					}
					body, decl := x86ScalarIntegerNativeSource(target.arch, symbol, name, variant, live)
					source.WriteString(body)
					declarations.WriteString(decl)
					width := 4
					if strings.Contains(name, "SD") {
						width = 8
					}
					functions = append(functions, function{symbol, width})
				}
			}
			// The entire original program is independently assembled first.
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized original native conversion did not close", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, fn := range functions {
							body := x86StringMemoryFunction(t, input, fn.name)
							if strings.Count(body, "~{fpsr}") != 1 || !strings.Contains(body, "asm sideeffect") ||
								!strings.Contains(body, "*m,~{memory},~{fpsr}") || !strings.Contains(body, fmt.Sprintf("elementtype([%d x i8])", fn.width)) ||
								strings.Contains(body, "fptosi ") || strings.Contains(body, "fptoui ") {
								t.Fatal("dead or live conversion lost its exact native read/MXCSR effect", fn.name, optimized, body)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "scalar-native-read.ll", "scalar-native-read.o", input)
					}
				})
			}
			t.Logf("%d complete initialized original functions; 3 APIs, original/O2 IR objects; not native execution", len(functions))
		})
	}
}

func TestX86ScalarFloatIntegerPairedReadRequiresIndependentInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		type sample struct {
			name, variant, source, decl string
			live                        bool
		}
		var samples []sample
		var original strings.Builder
		for _, name := range x86ScalarIntegerNativeNames(arch) {
			for _, live := range []bool{false, true} {
				for _, variant := range []string{"index", "initialized-vector", "missing-pointer", "numeric-pointer", "missing-index", "opaque-index", "missing-vector", "missing-mxcsr-pointer"} {
					symbol := fmt.Sprintf("input%d", len(samples))
					source, decl := x86ScalarIntegerNativeSource(arch, symbol, name, variant, live)
					samples = append(samples, sample{name, variant, source, decl, live})
					original.WriteString(source)
				}
			}
		}
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		for _, item := range samples {
			t.Run(fmt.Sprintf("%s/%s/%s/live=%t", arch, item.name, item.variant, item.live), func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						_, err := x86ScalarFPBitViewAPI(t, item.source, item.decl, arch, triple, api)
						positive := item.variant == "index" || item.variant == "initialized-vector"
						if positive && err != nil || !positive && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native input/pointer role mismatch", positive, err)
						}
					})
				}
			})
		}
	}
}

func TestX86ScalarFloatIntegerNativeEffectsDoNotGrantObserverBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86ScalarIntegerNativeNames(arch) {
			t.Run(arch+"/"+name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, name+" (DI),AX")
				effect, known, err := x86TypedScalarFloatIntegerByteEffect(ins.Op, ins, arch)
				if err != nil || !known || !effect.requiresResultProof {
					t.Error("native conversion must check original inputs even for Void", known, err)
				}
				state := &x86ResultState{flags: 0x3f}
				state.pointerGP[7] = true
				before := state.clone()
				accepted, known := x86ResultScalarFloatIntegerStep(ins, state, nil, 0, arch)
				if !known || accepted || !reflect.DeepEqual(*state, before) {
					t.Fatal("strict observer borrowed a native read or mutated failed state", known, accepted)
				}
				ins = x86ScalarLaneInstruction(t, name+" X1,AX")
				state.writeVector(1, 64, ^uint64(0), false)
				before = state.clone()
				accepted, known = x86ResultScalarFloatIntegerStep(ins, state, nil, 0, arch)
				if !known || !accepted || state.flags != before.flags || state.vectorBytes(1) != before.vectorBytes(1) || state.pointerGP[7] != before.pointerGP[7] {
					t.Fatal("conversion changed FLAGS, its source, or independent pointer identity", known, accepted)
				}
			})
		}
	}
}

func TestX86ScalarFloatIntegerNativeContinuationRetainsMXCSRTarget(t *testing.T) {
	var original strings.Builder
	for index, name := range x86ScalarFloatIntegerOracleNames() {
		source, _ := x86ScalarIntegerNativeSource("amd64", fmt.Sprintf("target%d", index), name, "", false)
		original.WriteString(source)
	}
	goAssemblerOracleOutput(t, "amd64", original.String(), "", true)
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		source, decl := x86ScalarIntegerNativeSource("amd64", "value", name, "", false)
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", "i386-unknown-linux-gnu"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(name+"/"+triple+"/"+api, func(t *testing.T) {
					if _, err := x86ScalarFPBitViewAPI(t, source, decl, "amd64", triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native continuation invented cross-target MXCSR semantics", err)
					}
				})
			}
		}
	}
}
