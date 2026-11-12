package plan9asm

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

type amd64RegisterTupleRuntimeCase struct {
	name, declaration string
	results           []string
}

func amd64RegisterTupleRuntimeCases() []amd64RegisterTupleRuntimeCase {
	return []amd64RegisterTupleRuntimeCase{
		{name: "nine", results: []string{"uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64"}},
		{name: "widths", results: []string{"uint8", "uint16", "uint32"}},
		{name: "struct", results: []string{"uint64", "uint64", "uint64"}, declaration: "func tuple(seed uint64) (struct{ A,B uint64 },uint64)"},
		{name: "array-one", results: []string{"uint64", "uint64", "uint64"}, declaration: "func tuple(seed uint64) ([1]uint64,uint64,uint64)"},
		{name: "array-zero", results: []string{"uint64", "uint64", "uint64"}, declaration: "func tuple(seed uint64) ([0]uint64,uint64,uint64,uint64)"},
	}
}

func amd64RegisterTupleRuntimeInputs(t *testing.T, test amd64RegisterTupleRuntimeCase, api string) (string, string) {
	t.Helper()
	source, declaration := amd64RegisterTupleFixture(test.results)
	if test.declaration != "" {
		declaration = test.declaration
	}
	pkg := mustGoPackage(t, "tupleruntime", "package tupleruntime\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("tuple", pkg.Types.Scope().Lookup("tuple").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
	if err != nil {
		t.Fatal(err)
	}
	fields, tuple := parseLiteralStructFields(sig.Ret)
	if !tuple || len(fields) != len(test.results) || len(sig.Args) != 1 || sig.Args[0] != I64 {
		t.Fatalf("runtime shim differs from the actual declared LLVM signature: %+v", sig)
	}
	var shim strings.Builder
	fmt.Fprintf(&shim, "\ndefine void @observe_tuple(ptr %%out, i64 %%seed) {\n  %%value = call %s @tuple(i64 %%seed)\n", sig.Ret)
	var widths []string
	for index, typ := range fields {
		bytes := amd64IntegerRegisterResultBytes(typ)
		if bytes == 0 {
			t.Fatal("non-numerical tuple shim field", typ)
		}
		widths = append(widths, fmt.Sprint(8*bytes))
		fmt.Fprintf(&shim, "  %%v%d = extractvalue %s %%value, %d\n", index, sig.Ret, index)
		value := fmt.Sprintf("%%v%d", index)
		if typ != I64 {
			fmt.Fprintf(&shim, "  %%wide%d = zext %s %s to i64\n", index, typ, value)
			value = fmt.Sprintf("%%wide%d", index)
		}
		fmt.Fprintf(&shim, "  %%p%d = getelementptr i64, ptr %%out, i64 %d\n  store i64 %s, ptr %%p%d, align 8\n", index, index, value, index)
	}
	shim.WriteString("  ret void\n}\n")
	main := strings.ReplaceAll(amd64RegisterTupleValueOracle, "@WIDTHS@", strings.Join(widths, ","))
	main = strings.ReplaceAll(main, "@COUNT@", fmt.Sprint(len(fields)))
	return ir + shim.String(), main
}

const amd64RegisterTupleValueOracle = `
#include <stdint.h>
#include <stdio.h>
extern void observe_tuple(uint64_t *, uint64_t);
int main(void) {
  const uint64_t guard=UINT64_C(0xabcdef7654321098);
  const unsigned widths[]={@WIDTHS@};
  volatile uint64_t seed=UINT64_C(0xfedcba9876543210);
  for(unsigned iteration=0;iteration<32;iteration++) {
    uint64_t out[11];
    for(unsigned i=0;i<11;i++) out[i]=guard;
    if(iteration==0) seed=0;
    else if(iteration==1) seed=UINT64_MAX;
    else seed=seed*UINT64_C(6364136223846793005)+1;
    observe_tuple(out+1,seed);
    if(out[0]!=guard) return 2;
    for(unsigned field=0;field<@COUNT@;field++) {
      uint64_t expected=seed+UINT64_C(28800)+field;
      if(widths[field]<64) expected&=(UINT64_C(1)<<widths[field])-1;
      if(out[field+1]!=expected) {
        fprintf(stderr,"field=%u got=%llx expected=%llx\n",field,(unsigned long long)out[field+1],(unsigned long long)expected);
        return 3;
      }
    }
    for(unsigned i=@COUNT@+1;i<11;i++) if(out[i]!=guard) return 4;
  }
  puts("REGISTER_TUPLE_TRANSLATED_PASS fields=@COUNT@ calls=32");
  return 0;
}
`

func TestAMD64RegisterTupleResultRuntimeArtifacts(t *testing.T) {
	for _, test := range amd64RegisterTupleRuntimeCases() {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(test.name+"/"+api, func(t *testing.T) {
				ir, main := amd64RegisterTupleRuntimeInputs(t, test, api)
				data, err := json.Marshal(map[string]string{"case": test.name, "api": api,
					"ir": base64.StdEncoding.EncodeToString([]byte(ir)), "main": base64.StdEncoding.EncodeToString([]byte(main))})
				if err != nil {
					t.Fatal(err)
				}
				t.Log("REGISTER_TUPLE_RUNTIME_INPUT=" + string(data))
			})
		}
	}
}

var amd64RegisterTupleCases = [][]string{
	{"uint64", "uint64"},
	{"uint64", "uint64", "uint64"},
	{"uint64", "uint64", "uint64", "uint64"},
	{"uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64"},
	{"uint8", "uint16", "uint32"},
	{"uint16", "uint32", "uint64"},
	{"uint32", "uint64", "uint8"},
	{"uint64", "uint8", "uint16"},
}

// A value-preserving, already modeled instruction family selects the existing
// mandatory register-result observer. Plain legacy MOV/RET is not that query.
const amd64RegisterTupleAudit = "MOVQ AX,X0\nPINSRQ $0,AX,X0\nMOVQ X0,AX\n"

func amd64RegisterTupleFixture(results []string) (source, declaration string) {
	registers := []string{"AX", "BX", "CX", "DI", "SI", "R8", "R9", "R10", "R11"}
	source = "TEXT ·tuple<ABIInternal>(SB),4,$0\nADDQ $28800,AX\n"
	for index := 1; index < len(results); index++ {
		source += fmt.Sprintf("MOVQ AX,%s\nADDQ $%d,%s\n", registers[index], index, registers[index])
	}
	return source + "RET\n", "func tuple(seed uint64) (" + strings.Join(results, ",") + ")\n"
}

func TestAMD64RegisterTupleResultOriginalGo(t *testing.T) {
	for _, results := range amd64RegisterTupleCases {
		t.Run(strings.Join(results, "_"), func(t *testing.T) {
			source, _ := amd64RegisterTupleFixture(results)
			requireAMD64RegisterResultGoObject(t, source)
		})
	}
}

// The existing virtual register entry must close every numerical result. It
// does not acquire physical Go calls, stack slots, pointer bounds or an env.
func TestAMD64RegisterTupleResultThreeAPIs(t *testing.T) {
	for _, results := range amd64RegisterTupleCases {
		t.Run(strings.Join(results, "_"), func(t *testing.T) {
			source, declaration := amd64RegisterTupleFixture(results)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Errorf("%s: complete register tuple rejected: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterTupleResultObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, results := range amd64RegisterTupleCases {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(triple+"/"+strings.Join(results, "_")+"/"+api, func(t *testing.T) {
					source, declaration := amd64RegisterTupleFixture(results)
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, optimized := range []bool{false, true} {
						body := ir
						if optimized {
							body = x86MulDivRoundOptimize(t, body)
						}
						x86ResultInitializationObject(t, llc, triple, body, "register-tuple")
					}
				})
			}
		}
	}
}

func TestAMD64RegisterTupleResultEveryReturnRequiresEveryField(t *testing.T) {
	const declaration = "func tuple() (uint64,uint64,uint64)\n"
	const source = "TEXT ·tuple<ABIInternal>(SB),4,$0\nMOVQ $1,AX\nMOVQ $2,BX\nMOVQ $3,CX\nRET\n"
	for name, changed := range map[string]string{
		"missing second":    strings.Replace(source, "MOVQ $2,BX\n", "", 1),
		"missing third":     strings.Replace(source, "MOVQ $3,CX\n", "", 1),
		"partial second":    strings.Replace(source, "MOVQ $2,BX", "MOVB $2,BL", 1),
		"unknown third":     strings.Replace(source, "MOVQ $3,CX", "MOVQ R12,CX", 1),
		"lost on one path":  strings.Replace(source, "MOVQ $3,CX", "RDTSC\nCMPQ AX,$0\nJE done\nMOVQ $3,CX\ndone:", 1),
		"physical stack":    strings.Replace(source, "MOVQ $3,CX", "MOVQ (SP),CX", 1),
		"hidden closure":    strings.Replace(source, "MOVQ $3,CX", "MOVQ DX,CX", 1),
		"hidden runtime g":  strings.Replace(source, "MOVQ $3,CX", "MOVQ R14,CX", 1),
		"unbound call":      strings.Replace(source, "RET", "CALL ·Unknown(SB)\nRET", 1),
		"logical FP result": strings.Replace(source, "RET", "MOVQ CX,ret+16(FP)\nRET", 1),
	} {
		t.Run(name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if name == "unbound call" && err != nil {
					continue // The existing unresolved declaration error is also a real rejection.
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: unclosed tuple accepted: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterTupleResultTransportGuards(t *testing.T) {
	const source = "TEXT ·tuple<ABIInternal>(SB),4,$0\nMOVQ $1,AX\nMOVQ $2,BX\nMOVQ $3,CX\n" + amd64RegisterTupleAudit + "RET\n"
	for _, declaration := range []string{
		"func tuple() (*uint64,uint64,uint64)",
		"func tuple() (float64,uint64,uint64)",
		"func tuple() (bool,uint64,uint64)",
		"func tuple() ([2]uint64,uint64)",
		"func tuple() (uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64)",
	} {
		t.Run(declaration, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: another result transport accepted: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterTupleResultGoSourceShapes(t *testing.T) {
	for _, declaration := range []string{
		"func tuple(seed uint64) (struct{ A,B uint64 },uint64)",
		"func tuple(seed uint64) (struct{ Pair struct{ A,B uint64 }; C uint64 })",
		"func tuple(seed uint64) ([1]uint64,uint64,uint64)",
		"func tuple(seed uint64) ([0]uint64,uint64,uint64,uint64)",
	} {
		t.Run(declaration, func(t *testing.T) {
			source, _ := amd64RegisterTupleFixture([]string{"uint64", "uint64", "uint64"})
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Errorf("%s: valid recursively assigned Go numerical leaves: %v", api, err)
				}
			}
		})
	}
	for _, declaration := range []string{
		"func tuple(seed uint64) ([2]uint64,uint64)",
		"func tuple(seed uint64) (struct{ A [2]uint64 },uint64)",
	} {
		t.Run(declaration, func(t *testing.T) {
			pkg := mustGoPackage(t, "tuplesource", "package tuplesource\n"+declaration)
			source, _ := amd64RegisterTupleFixture([]string{"uint64", "uint64", "uint64"})
			flattened, err := DeriveGoFuncABI0Signature("tuple", pkg.Types.Scope().Lookup("tuple").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				for _, override := range []bool{false, true} {
					var manual func(string) (FuncSig, bool)
					if override {
						manual = func(string) (FuncSig, bool) { return flattened, true }
					}
					_, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api, manual)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s override=%v: real Go stack result acquired numerical registers: %v", api, override, err)
					}
				}
			}
		})
	}
}

func TestAMD64RegisterTupleResultSignatureGuards(t *testing.T) {
	source, declaration := amd64RegisterTupleFixture([]string{"uint64", "uint64", "uint64"})
	pkg := mustGoPackage(t, "tupleguard", "package tupleguard\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("tuple", pkg.Types.Scope().Lookup("tuple").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*FuncSig){
		"no frame slots": func(sig *FuncSig) { sig.Frame.Results = nil },
		"permuted slots": func(sig *FuncSig) {
			sig.Frame.Results[0], sig.Frame.Results[1] = sig.Frame.Results[1], sig.Frame.Results[0]
		},
		"missing slot":              func(sig *FuncSig) { sig.Frame.Results = sig.Frame.Results[:2] },
		"duplicate index":           func(sig *FuncSig) { sig.Frame.Results[1].Index = 0 },
		"out of range index":        func(sig *FuncSig) { sig.Frame.Results[1].Index = 3 },
		"wrong slot type":           func(sig *FuncSig) { sig.Frame.Results[1].Type = I32 },
		"nested field":              func(sig *FuncSig) { sig.Frame.Results[1].Field = 0 },
		"nested path":               func(sig *FuncSig) { sig.Frame.Results[1].Fields = []int{0} },
		"custom argument registers": func(sig *FuncSig) { sig.ArgRegs = []Reg{AX} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := sig
			changed.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
			change(&changed)
			ctx := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: changed, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("malformed result transport was accepted: %v", err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				manual := func(string) (FuncSig, bool) { return changed, true }
				_, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api, manual)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: malformed layout bypassed the common result audit: %v", api, err)
				}
			}
		})
	}
}

func TestAMD64RegisterTupleResultDispatch(t *testing.T) {
	fn := Func{Sym: "tuple<ABIInternal>"}
	for name, sig := range map[string]FuncSig{
		"no frame":         {Ret: "{ i64, i64, i64 }"},
		"wrong frame type": {Ret: "{ i64, i64, i64 }", Frame: FrameLayout{Results: []FrameSlot{{Type: Ptr}}}},
		"custom registers": {Ret: "{ i64, i64, i64 }", ArgRegs: []Reg{AX}},
	} {
		t.Run(name, func(t *testing.T) {
			if !x86TypedFPResultNeedsProof(fn, sig, "amd64") {
				t.Fatal("integer tuple skipped the common audit because its Frame/role was invalid")
			}
		})
	}
	for _, arch := range []string{"386", "arm", "arm64", "wasm"} {
		if x86TypedFPResultNeedsProof(fn, FuncSig{Ret: "{ i64, i64, i64 }"}, arch) {
			t.Fatal("AMD64 register tuple restriction changed another architecture:", arch)
		}
	}
	for _, name := range []string{"tuple", "tuple<ABI0>"} {
		if x86TypedFPResultNeedsProof(Func{Sym: name}, FuncSig{Ret: "{ i64, i64, i64 }"}, "amd64") {
			t.Fatal("register tuple restriction inferred a missing selector:", name)
		}
	}
}
