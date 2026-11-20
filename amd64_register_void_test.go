package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This derives an ordinary language signature, not a compiler/native entry,
// a physical frame, a pointer extent or any initialized memory contents.
func amd64RegisterVoidSource(t *testing.T, declaration, body string) (Func, FuncSig, string) {
	t.Helper()
	_, sig, source := x86ScalarFPVoidSource(t, declaration, body, "amd64")
	source = strings.Replace(source, "·view(SB)", "·view<ABIInternal>(SB)", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("ordinary register-void fixture lost its complete source", err)
	}
	return file.Funcs[0], sig, source
}

func TestAMD64RegisterVoidKeepsDeclaredInputsAndFullFlow(t *testing.T) {
	registers := []Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"}
	cases := 0
	for _, width := range []struct {
		typ, move string
		bytes     int64
	}{
		{"uint8", "MOVB", 1}, {"uint16", "MOVW", 2},
		{"uint32", "MOVL", 4}, {"uint64", "MOVQ", 8},
	} {
		for index, register := range registers {
			t.Run(width.typ+"/"+string(register), func(t *testing.T) {
				declaration := "func view(" + strings.TrimSuffix(strings.Repeat(width.typ+",", index+1), ",") + ")\n"
				body := fmt.Sprintf("%s %s,R12", width.move, register)
				fn, sig, _ := amd64RegisterVoidSource(t, declaration, body)
				seen, shapes := 0, 0
				err := checkAMD64RegisterResultInitialization(fn, sig, false,
					func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
						if ins.Raw != body {
							t.Fatal("unexpected source effect in the input counterexample", ins.Raw)
						}
						if state.shapeOnly {
							shapes++
							return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
						}
						seen++
						for carrier, reg := range registers {
							position, _, valid := x86ResultGP(reg, width.bytes, arch)
							if !valid {
								t.Fatal("invalid original argument carrier", reg)
							}
							want := uint8(0)
							if carrier <= index {
								want = uint8(1<<uint(width.bytes)) - 1
							}
							if state.gp[position] != want || state.pointerGP[position] {
								t.Fatal("Void changed declared carrier bytes or pointer roles", reg, state.gp[position], want)
							}
						}
						return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
					})
				if err != nil || seen != 1 || shapes != 1 {
					t.Fatal("ordinary Void must consume both source shape and actual input/effect", seen, shapes, err)
				}
			})
			cases++
		}
	}
	if cases != 36 {
		t.Fatal("incomplete ordinary argument-width/carrier matrix", cases)
	}

	t.Run("pointer-is-not-numerical", func(t *testing.T) {
		fn, sig, _ := amd64RegisterVoidSource(t, "func view(input *uint64)\n", "MOVQ AX,BX\nMOVQ BX,CX")
		seen, shapes := 0, 0
		err := checkAMD64RegisterResultInitialization(fn, sig, false,
			func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				if state.shapeOnly {
					shapes++
					return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
				}
				register := AX
				if seen != 0 {
					register = BX
				}
				position, _, _ := x86ResultGP(register, 8, arch)
				if !state.pointerGP[position] || !state.callerAddressGP[position] || state.gp[position] != 0 {
					t.Fatal("Void discarded the original opaque pointer role or invented numerical bytes")
				}
				seen++
				return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
			})
		if err != nil || seen != 2 || shapes != 2 {
			t.Fatal("Void pointer copies require the complete original source shape and flow", seen, shapes, err)
		}
	})

	t.Run("no-AX-result", func(t *testing.T) {
		fn, sig, _ := amd64RegisterVoidSource(t, "func view()\n", "MOVQ $7,BX")
		seen, shapes := 0, 0
		err := checkAMD64RegisterResultInitialization(fn, sig, false,
			func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				if state.shapeOnly {
					shapes++
					return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
				}
				position, _, _ := x86ResultGP(AX, 8, arch)
				if state.gp[position] != 0 {
					t.Fatal("the Void entry fabricated AX initialization")
				}
				seen++
				return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
			})
		if err != nil || seen != 1 || shapes != 1 {
			t.Fatal("Void has no AX result but retains both source shape and reaching effects", seen, shapes, err)
		}
	})
}

func TestAMD64RegisterVoidWholeFunctionThreeAPIsAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	var assembly, declarations strings.Builder
	fixtures := 0
	for index, fixture := range []struct {
		declaration, body string
	}{
		{"func view(input uint8)\n", "MOVB AX,R12"},
		{"func view(input uint16)\n", "MOVW AX,R12"},
		{"func view(input uint32)\n", "MOVL AX,R12"},
		{"func view(input uint64)\n", "MOVQ AX,R12"},
		{"func view(input *uint64)\n", "MOVQ AX,BX\nMOVQ BX,CX"},
		{"func view()\n", "MOVQ $7,BX"},
		{"func view(input *uint64)\n", "MOVQ (AX),BX"},
	} {
		_, _, source := amd64RegisterVoidSource(t, fixture.declaration, fixture.body)
		name := fmt.Sprintf("consume%d", index)
		assembly.WriteString(strings.Replace(source, "·view<", "·"+name+"<", 1))
		declarations.WriteString(strings.Replace(fixture.declaration, "view(", name+"(", 1))
		fixtures++
	}
	if fixtures != 7 {
		t.Fatal("incomplete integer/pointer/empty/native-read Void source matrix", fixtures)
	}
	requireAMD64RegisterResultGoObject(t, assembly.String())
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), "amd64", triple, api)
				if err != nil || ir == "" {
					t.Fatal("ordinary typed Void entry requires no fabricated result", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					text := ir
					if level == "-O2" {
						text = x86MulDivRoundOptimize(t, text)
					}
					if strings.Count(text, "load volatile i64,") != 1 {
						t.Fatal("Void discarded or duplicated its exact native qword read", api, level)
					}
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			})
		}
	}
}

func amd64RegisterVoidX15Stores(t *testing.T) (string, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	for index, op := range []string{"MOVO", "MOVOA", "MOVOU", "MOVAPS", "MOVUPS", "MOVAPD", "MOVUPD"} {
		// RDTSC makes the complete-body effect check run, as the native
		// operations later in runtime.memclrNoHeapPointers do.
		_, _, source := amd64RegisterVoidSource(t, "func view(destination *[16]byte)\n", op+" X15,(AX)\nRDTSC")
		name := fmt.Sprintf("store%d", index)
		assembly.WriteString(strings.Replace(source, "·view<", "·"+name+"<", 1))
		fmt.Fprintf(&declarations, "func %s(destination *[16]byte)\n", name)
	}
	return assembly.String(), declarations.String()
}

func TestAMD64RegisterVoidX15EntryStores(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	assembly, declarations := amd64RegisterVoidX15Stores(t)
	requireAMD64RegisterResultGoObject(t, assembly)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", triple, api)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, triple, ir, "register-x15-entry-stores")
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixAMD64RegisterVoidX15EntryStores(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	assembly, declarations := amd64RegisterVoidX15Stores(t)
	const main = `
#include <stdint.h>
#include <string.h>

extern void store0(uint8_t *), store1(uint8_t *), store2(uint8_t *),
            store3(uint8_t *), store4(uint8_t *), store5(uint8_t *), store6(uint8_t *);

int main(void) {
    void (*const stores[])(uint8_t *) = {store0, store1, store2, store3, store4, store5, store6};
    _Alignas(16) uint8_t bytes[48];
    for (unsigned i = 0; i < sizeof(stores) / sizeof(stores[0]); i++) {
        memset(bytes, 255, sizeof(bytes));
        stores[i](bytes + 16);
        for (unsigned j = 0; j < sizeof(bytes); j++) {
            unsigned want = j >= 16 && j < 32 ? 0 : 255;
            if (bytes[j] != want)
                return i + 1;
        }
    }
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			compiler := []string{clang, "-target", triple}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "register-x15", triple, ir, main, prefix, 0)
			optimized := x86MulDivRoundOptimize(t, ir)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "register-x15-o2", triple, optimized, main, prefix, 2)
		})
	}
}

func TestAMD64RegisterVoidX15EntryBoundaries(t *testing.T) {
	const declaration = "func view(destination *[32]byte)\n"
	for _, test := range []struct{ name, triple, body string }{
		{"plan9", "x86_64-unknown-plan9", "MOVOU X15,(AX)"},
		{"unknown OS", "x86_64-unknown-unknown", "MOVOU X15,(AX)"},
		{"other XMM", "x86_64-unknown-linux-gnu", "MOVOU X14,(AX)"},
		{"wider alias", "x86_64-unknown-linux-gnu", "VMOVDQU Y15,(AX)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, source := amd64RegisterVoidSource(t, declaration, test.body+"\nRDTSC")
			requireAMD64RegisterResultGoObject(t, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", test.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: unknown entry bytes were admitted: %v", api, err)
				}
			}
		})
	}
	t.Run("explicit Plan 9 Go source", func(t *testing.T) {
		_, _, source := amd64RegisterVoidSource(t, declaration, "MOVOU X15,(AX)\nRDTSC")
		pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		result, err := TranslateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOOS: "plan9", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		})
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
		}
		if result != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("Plan 9 source gained an X15 entry guarantee from the backend triple: %v", err)
		}
	})
}

func amd64RegisterVoidForwardStores(t *testing.T) (string, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	const declaration = "func view(destination *[32]byte, value, count uint64)\n"
	for _, suffix := range []string{"B", "W", "L", "Q"} {
		for _, repeat := range []bool{false, true} {
			beforeStore := "MOVQ AX,DI\nMOVQ BX,AX\n"
			name := "stos" + suffix
			if repeat {
				beforeStore += "REP\n"
				name = "rep" + name
			}
			_, _, source := amd64RegisterVoidSource(t, declaration, beforeStore+"STOS"+suffix+"\nRDTSC")
			assembly.WriteString(strings.Replace(source, "·view<", "·"+name+"<", 1))
			declarations.WriteString(strings.Replace(declaration, "view(", name+"(", 1))
		}
	}
	return assembly.String(), declarations.String()
}

func TestAMD64RegisterVoidForwardStringEntry(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	assembly, declarations := amd64RegisterVoidForwardStores(t)
	requireAMD64RegisterResultGoObject(t, assembly)
	const triple = "x86_64-unknown-linux-gnu"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, triple, ir, "register-forward-stores")
		})
	}
}

func TestCrossLinuxRuntimeMatrixAMD64RegisterVoidForwardStores(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	assembly, declarations := amd64RegisterVoidForwardStores(t)
	const main = `
#include <stdint.h>
#include <string.h>

typedef void store(uint8_t *, uint64_t, uint64_t);
extern store stosB, repstosB, stosW, repstosW, stosL, repstosL, stosQ, repstosQ;

int main(void) {
    store *const stores[] = {stosB, repstosB, stosW, repstosW, stosL, repstosL, stosQ, repstosQ};
    const uint64_t value = UINT64_C(0x0123456789abcdef);
    uint8_t bytes[48];
    for (unsigned i = 0; i < sizeof(stores) / sizeof(stores[0]); i++) {
        const unsigned width = 1u << (i / 2);
        for (unsigned count = 0; count <= 3; count++) {
            const unsigned size = width * (i % 2 ? count : 1);
            memset(bytes, 255, sizeof(bytes));
            stores[i](bytes + 8, value, count);
            for (unsigned j = 0; j < sizeof(bytes); j++) {
                unsigned want = j >= 8 && j < 8 + size
                    ? (value >> (8 * ((j - 8) % width))) & 255 : 255;
                if (bytes[j] != want)
                    return i + 1;
            }
        }
    }
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			compiler := []string{clang, "-target", triple}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "register-forward-stos", triple, ir, main, prefix, 0)
			optimized := x86MulDivRoundOptimize(t, ir)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "register-forward-stos-o2", triple, optimized, main, prefix, 2)
		})
	}
}

func TestAMD64RegisterVoidCannotWaiveFaultingInputsAndSourceRoles(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, body string
		registerProofOnly       bool
	}{
		{"undefined-base", "func view(input uint64)\n", "MOVQ (R10),AX", false},
		{"NUM-is-not-pointer", "func view(input uint64)\n", "MOVQ (AX),BX", false},
		{"hidden-closure", "func view(input uint64)\n", "MOVQ 8(DX),BX", false},
		{"hidden-g", "func view(input uint64)\n", "MOVQ (R14),AX", false},
		{"physical-stack", "func view(input uint64)\n", "MOVQ (SP),AX", true},
		{"ABI0-input", "func view(input uint64)\n", "MOVQ input+0(FP),AX", true},
		{"ABI0-store", "func view(input uint64)\n", "MOVQ AX,input+0(FP)", true},
		{"one-path-fault", "func view(input uint64)\n", "CMPQ AX,$0\nJE done\nMOVQ (R10),BX\ndone:", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			fn, sig, source := amd64RegisterVoidSource(t, fixture.declaration, fixture.body)
			declaration := fixture.declaration
			if fixture.registerProofOnly {
				// The legacy ordinary-MOV path can use logical frame fields without
				// this register-entry proof. Its public admission is not a native
				// ABIInternal frame contract. Keep the exact original source here,
				// and make the paired-read public counterexample explicit below.
				err := checkAMD64RegisterResultInitialization(fn, sig, false,
					func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
						return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
					})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original SP/FP source acquired register-entry ownership", err)
				}
				declaration = "func view(input *uint64)\n"
				_, _, source = amd64RegisterVoidSource(t, declaration, "MOVQ (AX),R10\n"+fixture.body)
				requireAMD64RegisterResultGoObject(t, source)
			}
			if fixture.name == "NUM-is-not-pointer" {
				err := checkAMD64RegisterResultInitialization(fn, sig, false,
					func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
						return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
					})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone register query acquired native storage authority", err)
				}
				requireAMD64RegisterResultGoObject(t, source)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if fixture.name == "NUM-is-not-pointer" {
					if err != nil || !strings.Contains(ir, "load volatile i64,") {
						t.Fatal("complete NUM input lost its paired native read", api, err)
					}
					x86NumericNativeAddressObject(t, ir, "x86_64-unknown-linux-gnu")
					continue
				}
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Error("Void waived a faulting read or its original source/entry role", api, err)
				}
			}
		})
	}

	t.Run("unbound-call", func(t *testing.T) {
		const declaration = "func view(input uint64)\n"
		_, _, source := amd64RegisterVoidSource(t, declaration, "CALL ·unknown(SB)")
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err == nil || ir != "" {
				t.Error("Void admitted a call without its required signature", api, err)
			}
		}
	})
}

func TestAMD64RegisterVoidRejectsForgedResultsAndEntries(t *testing.T) {
	for _, change := range []string{"ABI0", "manual-registers", "result-without-slot", "slot-on-Void", "raw", "physical-address-mode", "WASM-entry"} {
		t.Run(change, func(t *testing.T) {
			fn, sig, _ := amd64RegisterVoidSource(t, "func view(input uint64)\n", "MOVQ AX,BX")
			switch change {
			case "ABI0":
				fn.Sym = strings.TrimSuffix(fn.Sym, "<ABIInternal>")
			case "manual-registers":
				sig.ArgRegs = []Reg{AX}
			case "result-without-slot":
				sig.Ret = I64
			case "slot-on-Void":
				sig.Frame.Results = append(sig.Frame.Results, sig.Frame.Params[0])
			case "raw":
				fn.Instrs[1].x86Encoded = true
			case "physical-address-mode":
				fn.Instrs[1].x86AddressBits = 32
			case "WASM-entry":
				sig.WASMContext = "go"
			}
			calls := 0
			err := checkAMD64RegisterResultInitialization(fn, sig, false,
				func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
					calls++
					return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
				})
			if !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
				t.Fatal("Void admitted contradictory result/entry metadata", calls, err)
			}
		})
	}
}
