package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64PrivateCallFrameAddressEscapeRemainsContext(t *testing.T) {
	for _, tc := range []struct {
		name, before, after, data string
	}{
		{name: "direct_sp", before: "MOVD RSP,R5"},
		{name: "affine_sp", before: "MOVD RSP,R9\nADD $16,R9,R5"},
		{name: "sp_address_expression", before: "MOVD $-32(RSP),R9"},
		{name: "bit_transformed_sp", before: "MOVD RSP,R9\nEOR $8,R9,R5\nEOR $8,R5"},
		{name: "caller_fp_escape", before: "MOVD RSP,R9\nMOVD R9,dst+0(FP)\nMOVD dst+0(FP),R5"},
		{name: "fp_address", before: "MOVD $dst+0(FP),R5"},
		{name: "global_escape", before: "MOVD RSP,R9\nMOVD R9,holder(SB)", data: "GLOBL holder(SB),NOPTR,$8\n"},
		{name: "data_target_escape", before: "MOVD holder(SB),R10\nMOVD RSP,R9\nMOVD R9,(R10)", data: "DATA holder+0(SB)/8,$payload(SB)\nGLOBL holder(SB),NOPTR,$8\nGLOBL payload(SB),NOPTR,$8\n"},
		{name: "heap_escape", before: "MOVD RSP,R9\nMOVD R9,(R5)"},
		{name: "previous_call_holds_frame", before: "MOVD RSP,R9\nMOVD R9,8(RSP)\nCALL runtime·memmove(SB)\nMOVD dst+0(FP),R5\nMOVD src+8(FP),R6\nMOVD n+16(FP),R7"},
		{name: "branch_merge", before: "CBZ R7,external\nMOVD RSP,R5\nexternal:"},
		{name: "dead_escape", after: "MOVD RSP,R9\nMOVD R9,holder(SB)\nRET", data: "GLOBL holder(SB),NOPTR,$8\n"},
		{name: "raw_sp_value", before: "WORD $0x910003e9\nMOVD R9,R5"},
		{name: "raw_sp_dword", before: "DWORD $0xd503201f910003e9"},
		{name: "unknown_raw", before: "WORD $0xd50330ff"},
		{name: "native_indirect_call", before: "MOVD dst+0(FP),R9\nCALL (R9)"},
		{name: "raw_indirect_call", before: "MOVD dst+0(FP),R9\nWORD $0xd63f0120"},
		{name: "unknown_symbol", before: "CALL unknown(SB)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(arm64PrivateCallCopySource, "\tMOVD R5, 8(RSP)", tc.before+"\n\tMOVD R5, 8(RSP)", 1)
			source += tc.after + "\n" + tc.data
			arm64PrivateCallGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name != "unknown_symbol" && arm64CallFrameUnexposed(file.Funcs[0]) {
				t.Fatal("source-wide escape/unknown-form gate accepted this original function")
			}
			for _, target := range arm64TypedNativeTargets {
				opt := arm64PrivateCallCopyOptions(target)
				unsupported := tc.name == "unknown_raw" || tc.name == "raw_sp_dword"
				if _, err := Translate(file, opt); err == nil || !unsupported && !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Translate exposed/unproven frame accepted: %v", target, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if err == nil || !unsupported && !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Module exposed/unproven frame accepted: %v", target, err)
				}
				bound, err := translateGoModuleInContext(ctx, arm64PrivateCallPackage(t), []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
					ManualSig: func(name string) (FuncSig, bool) {
						if name == "unknown" {
							return FuncSig{}, false
						}
						return opt.Sigs[name], name == "runtime.memmove"
					},
				})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				// An undeclared target is also rejected by Go binding; it must
				// never acquire a guessed type just to preserve the private LR.
				if err == nil || tc.name != "unknown_symbol" && !unsupported && !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Go-bound exposed/unproven frame accepted: %v", target, err)
				}
			}
		})
	}
}

func TestARM64PrivateCallFrameAggregatePointersInvalidateFP(t *testing.T) {
	for _, typ := range []LLVMType{Ptr, "{ ptr, i64 }", "{ i64, { ptr, double } }", "{ ptr, i64, i64 }", "[1 x ptr]", "[2 x ptr]", "unrecognized"} {
		t.Run(string(typ), func(t *testing.T) {
			sig := FuncSig{Name: "callee", Args: []LLVMType{typ}, Ret: Void, Frame: FrameLayout{
				Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
			}}
			state := &arm64ControlState{
				regs: map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R30": arm64ControlFromMap(map[string]bool{"label:continuation": true})},
				memory: map[string]arm64ControlValue{
					"sp:0": arm64ControlFromMap(map[string]bool{"label:outer": true}), "sp:8": arm64ControlFromMap(map[string]bool{"": true}), "fp:0": arm64ControlFromMap(map[string]bool{"fpa:0": true}),
				},
			}
			for _, proof := range []bool{false, true} {
				copy := state.clone()
				ctx := &arm64Ctx{resolve: func(s string) string { return s }, sigs: map[string]FuncSig{"callee": sig},
					unexposedCallFrame: proof, sourceGoFrame: arm64GoFrame{present: true},
				}
				ctx.invalidateControlCallResults(copy, Operand{Kind: OpSym, Sym: "callee(SB)"})
				if !arm64ControlHas(copy.memory["fp:0"], "") || arm64ControlHas(copy.memory["sp:0"], "") == proof {
					t.Fatalf("pointer-containing/unknown transport lost the separate SP/FP contract (proof=%t): %v", proof, copy.memory)
				}
			}
		})
	}
}

func arm64PrivateCallPackage(t *testing.T) GoPackage {
	return arm64PrivateCallDeclarations(t, "func ABI0Copy(dst,src unsafe.Pointer,n uintptr)\n")
}

func arm64PrivateCallDeclarations(t *testing.T, declarations string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "declaration.go", "package copy\nimport \"unsafe\"\n"+declarations, 0)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "arm64")}
	pkg, err := conf.Check("test/copy", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: "test/copy", Types: pkg, Syntax: []*ast.File{file}}
}

func TestARM64PrivateCallFrameProofIsZeroDefaultAndSPOnly(t *testing.T) {
	for _, tc := range []struct {
		name, argument, escaped     string
		proof, known, frame, intact bool
	}{
		{name: "fresh", proof: true, known: true, frame: true, intact: true},
		{name: "zero_default", known: true, frame: true},
		{name: "missing_source_frame", proof: true, known: true},
		{name: "unknown_callee", proof: true, frame: true},
		{name: "sp_argument", proof: true, known: true, frame: true, argument: "sp:8"},
		{name: "fp_argument", proof: true, known: true, frame: true, argument: "fp:0"},
		{name: "fp_address_argument", proof: true, known: true, frame: true, argument: "fpa:0"},
		{name: "code_argument", proof: true, known: true, frame: true, argument: "label:local"},
		{name: "previous_escape", proof: true, known: true, frame: true, escaped: "sp:16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := FuncSig{Name: "callee", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{
				Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
			}}
			state := &arm64ControlState{
				regs: map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R30": arm64ControlFromMap(map[string]bool{"label:continuation": true})},
				memory: map[string]arm64ControlValue{
					"sp:0": arm64ControlFromMap(map[string]bool{"label:outer": true}), "sp:8": arm64ControlFromMap(map[string]bool{tc.argument: true}),
					"sp:16": arm64ControlFromMap(map[string]bool{"": true}), "fp:0": arm64ControlFromMap(map[string]bool{"label:local": true}),
				},
			}
			if tc.escaped != "" {
				state.escaped = arm64ControlFromMap(map[string]bool{tc.escaped: true})
			}
			ctx := &arm64Ctx{resolve: func(s string) string { return s }, sigs: map[string]FuncSig{},
				unexposedCallFrame: tc.proof, sourceGoFrame: arm64GoFrame{present: tc.frame},
			}
			if tc.known {
				ctx.sigs["callee"] = sig
			}
			ctx.invalidateControlCallResults(state, Operand{Kind: OpSym, Sym: "callee(SB)"})
			if arm64ControlHas(state.memory["sp:0"], "") == tc.intact {
				t.Errorf("SP preservation mismatch: %v", state.memory["sp:0"])
			}
			if !arm64ControlHas(state.memory["fp:0"], "") {
				t.Error("a private-SP proof must never retain an FP content category across a pointer call")
			}
			if !arm64ControlHas(state.memory["sp:16"], "") || !arm64ControlHas(state.regs["R9"], "") {
				t.Error("private-SP proof restored unknown memory or caller-save GP")
			}
		})
	}
	for _, source := range []string{
		"TEXT ABI0Copy(SB),NOSPLIT|NOFRAME,$0-24\nCALL runtime·memmove(SB)\nRET\n",
		"TEXT ABI0Copy(SB),NOSPLIT,$0-24\nRET\n",
		"TEXT ABI0Copy(SB),NOSPLIT,$32-24\nMOVD $8(RSP),R9\nCALL runtime·memmove(SB)\nRET\n",
	} {
		arm64PrivateCallGoObject(t, source)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Errorf("unproved source frame accepted: %s", source)
		}
	}
	file, err := Parse(ArchARM64, arm64PrivateCallCopySource)
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	if !arm64CallFrameUnexposed(fn) {
		t.Fatal("original ordinary ABI0 call did not establish a fresh unexposed SP object")
	}
	for _, sig := range []FuncSig{
		{Args: []LLVMType{Ptr}, ArgRegs: []Reg{SP}},
		{Args: []LLVMType{Ptr}, ArgRegs: []Reg{"RSP"}},
		{ARM64GoRegisterABI: &ARM64GoRegisterABI{Params: []ARM64GoRegisterValue{{Type: Ptr, Register: SP}}}},
	} {
		if arm64CallFrameFreshEntry(sig) || newARM64Ctx(new(strings.Builder), fn, sig, nil, nil, false).unexposedCallFrame {
			t.Fatal("an incoming custom SP can overwrite the fresh root and must not borrow its disjointness")
		}
	}
	fn.Instrs = fn.Instrs[1:]
	if arm64CallFrameUnexposed(fn) {
		t.Fatal("a caller-constructed function without an actual TEXT contract borrowed a private-frame proof")
	}
}

type arm64PrivateComposite struct {
	name, goType, prepare, callee string
	argSize                       int
	constantResult                bool
}

func arm64PrivateComposites() []arm64PrivateComposite {
	return []arm64PrivateComposite{
		{name: "scalar", goType: "unsafe.Pointer", prepare: "MOVD R5,8(RSP)", callee: "MOVD value+0(FP),R0\nMOVD $7,R1", argSize: 8, constantResult: true},
		{name: "struct", goType: "struct{ P unsafe.Pointer; N uint64 }", prepare: "MOVD R5,8(RSP)\nMOVD R6,16(RSP)", callee: "MOVD value_P+0(FP),R0\nMOVD value_N+8(FP),R1", argSize: 16},
		{name: "nested_struct", goType: "struct{ N uint64; X struct{ P unsafe.Pointer; F float64 } }", prepare: "MOVD R6,8(RSP)\nMOVD R5,16(RSP)\nMOVD $0,R7\nMOVD R7,24(RSP)", callee: "MOVD value_X_P+8(FP),R0\nMOVD value_N+0(FP),R1", argSize: 24},
		{name: "slice", goType: "[]uint64", prepare: "MOVD R5,8(RSP)\nMOVD R6,16(RSP)\nMOVD R6,24(RSP)", callee: "MOVD value_base+0(FP),R0\nMOVD value_len+8(FP),R1", argSize: 24},
		{name: "string", goType: "string", prepare: "MOVD R5,8(RSP)\nMOVD R6,16(RSP)", callee: "MOVD value_base+0(FP),R0\nMOVD value_len+8(FP),R1", argSize: 16},
		{name: "one_array", goType: "[1]unsafe.Pointer", prepare: "MOVD R5,8(RSP)", callee: "MOVD value+0(FP),R0\nMOVD $7,R1", argSize: 8, constantResult: true},
		{name: "two_array", goType: "[2]unsafe.Pointer", prepare: "MOVD R5,8(RSP)\nMOVD R5,16(RSP)", callee: "MOVD value+0(FP),R0\nMOVD $7,R1", argSize: 16, constantResult: true},
	}
}

func arm64PrivateCompositeSource(tc arm64PrivateComposite) string {
	return fmt.Sprintf("#include \"textflag.h\"\nTEXT ·Composite(SB),NOSPLIT,$32-16\nMOVD dst+0(FP),R5\nMOVD n+8(FP),R6\n%s\nCALL ·Touch(SB)\nRET\nTEXT ·Touch(SB),NOSPLIT,$0-%d\n%s\nMOVD R1,(R0)\nRET\n", tc.prepare, tc.argSize, tc.callee)
}

func TestARM64PrivateCallFrameDeclaredCompositeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tc := range arm64PrivateComposites() {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64PrivateCompositeSource(tc)
			arm64PrivateCallGoObject(t, source)
			pkg := arm64PrivateCallDeclarations(t, "func Composite(dst unsafe.Pointer,n uint64)\nfunc Touch(value "+tc.goType+")\n")
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				func() {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
					bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve})
					if err != nil {
						t.Fatal(err)
					}
					defer bound.Module.Dispose()
					opt := Options{Goarch: "arm64", TargetTriple: target, Sigs: bound.Signatures, ResolveSym: resolve}
					if _, err := Translate(file, opt); err != nil {
						t.Fatal(err)
					}
					module, err := TranslateModuleInContext(ctx, file, opt)
					if err != nil {
						t.Fatal(err)
					}
					defer module.Dispose()
					compileLLVMToObject(t, llc, target, tc.name+".ll", tc.name+".o", module.String())
				}()
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateCallComposites(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range arm64PrivateComposites() {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64PrivateCompositeSource(tc)
			declarations := "func Composite(dst unsafe.Pointer,n uint64)\nfunc Touch(value " + tc.goType + ")\n"
			want := "n"
			if tc.constantResult {
				want = "7"
			}
			// Headers are transported by the assembler, not dereferenced as
			// Go slices/strings. Keep lengths small and every pointer real.
			runARM64LocalRegisterGoOracle(t, source, "package main\nimport \"unsafe\"\n"+declarations+fmt.Sprintf(`func main() {
 for _,n:=range []uint64{0,1,3,7,15} {
  data:=[3]uint64{0x1122334455667788,0,0x8877665544332211}
  Composite(unsafe.Pointer(&data[1]),n)
  if data[0]!=0x1122334455667788 || data[1]!=%s || data[2]!=0x8877665544332211 { panic("composite call canary/value mismatch") }
 }
}
`, want), len(runner) != 0)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			bound, err := translateGoModuleInContext(ctx, arm64PrivateCallDeclarations(t, declarations), []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: triple, ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer bound.Module.Dispose()
			driver := fmt.Sprintf(`#include <stdint.h>
extern void Composite(void *,uint64_t);
int main(void) {
 const uint64_t inputs[]={0,1,3,7,15};
 for(int i=0;i<5;i++) {
  uint64_t n=inputs[i],data[]={UINT64_C(0x1122334455667788),0,UINT64_C(0x8877665544332211)};
  Composite(data+1,n);
  if(data[0]!=UINT64_C(0x1122334455667788)||data[1]!=%s||data[2]!=UINT64_C(0x8877665544332211)) return 1;
 }
 return 0;
}
`, want)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_composite_"+tc.name, triple, bound.Module.String(), driver, runner)
		})
	}
}

// This is the unchanged ABI0Copy source from llgo's runtime memmove regression.
const arm64PrivateCallCopySource = `#include "textflag.h"
TEXT ABI0Copy(SB),NOSPLIT,$32-24
	MOVD dst+0(FP), R5
	MOVD src+8(FP), R6
	MOVD n+16(FP), R7
	MOVD R5, 8(RSP)
	MOVD R6, 16(RSP)
	MOVD R7, 24(RSP)
	MOVD $1, R0
	MOVD $2, R1
	MOVD $3, R2
	CALL runtime·memmove(SB)
	RET
`

func arm64PrivateCallCopyOptions(target string) Options {
	args := []LLVMType{Ptr, Ptr, I64}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: I64, Index: 2, Field: -1},
	}}
	return Options{
		Goarch: "arm64", TargetTriple: target,
		ResolveSym: func(symbol string) string {
			return strings.ReplaceAll(goStripABISuffix(strings.TrimPrefix(symbol, "·")), "·", ".")
		},
		Sigs: map[string]FuncSig{
			"ABI0Copy":        {Name: "ABI0Copy", Args: args, Ret: Void, Frame: frame},
			"runtime.memmove": {Name: "memmove", Args: args, Ret: Void, Frame: frame},
		},
	}
}

func arm64PrivateCallGoObject(t *testing.T, source string) {
	t.Helper()
	if !strings.Contains(source, "\"textflag.h\"") {
		source = "#include \"textflag.h\"\n" + source
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "source.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-p", "runtime", "-I", filepath.Join(testGOROOT(t), "pkg/include"), "-o", filepath.Join(dir, "source.o"), path)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go assembler rejected private-frame source: %v\n%s", err, out)
	}
}

func TestARM64PrivateCallFrameIncomingPointerPreservesSavedLink(t *testing.T) {
	arm64PrivateCallGoObject(t, arm64PrivateCallCopySource)
	file, err := Parse(ArchARM64, arm64PrivateCallCopySource)
	if err != nil {
		t.Fatal(err)
	}
	pkg := arm64PrivateCallPackage(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			opt := arm64PrivateCallCopyOptions(target)
			ir, err := Translate(file, opt)
			if err != nil {
				t.Errorf("incoming Ptr cannot expose an otherwise unexposed private frame: %v", err)
			} else {
				base := regexp.MustCompile(`(%[A-Za-z0-9_]+) = getelementptr inbounds \[[0-9]+ x i8\], ptr %local_stack, i32 0, i64 [0-9]+`).FindStringSubmatch(ir)
				if !strings.Contains(ir, "%local_stack = alloca [") || len(base) != 2 || !strings.Contains(ir, "ptrtoint ptr "+base[1]+" to i64") {
					t.Error("the source SP must derive from a fresh backing allocation, not an incoming pointer")
				}
				compileLLVMToObject(t, llc, target, "private-copy.ll", "private-copy.o", ir)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Errorf("owned-context module: %v", err)
			} else {
				module.Dispose()
			}
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(arm64PrivateCallCopySource), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
				ManualSig: func(name string) (FuncSig, bool) {
					return opt.Sigs[name], name == "runtime.memmove"
				},
			})
			if err != nil {
				t.Errorf("declaration-backed module: %v", err)
			} else {
				bound.Module.Dispose()
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64PrivateCallCopy(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	// Only qualify the entry for Go's generated ABI0 declaration wrapper;
	// preserve every original instruction, frame and runtime call target.
	goSource := strings.Replace(arm64PrivateCallCopySource, "TEXT ABI0Copy(SB)", "TEXT ·ABI0Copy(SB)", 1)
	runARM64LocalRegisterGoOracle(t, goSource, `package main
import "unsafe"
func ABI0Copy(dst,src unsafe.Pointer,n uintptr)
func main() {
 for _,dst:=range []int{0,1,9,17,31} { for _,src:=range []int{0,1,9,17,31} { for _,n:=range []int{0,1,2,3,8,17,32,33} {
  var data, want [96]byte
  for i:=range data { data[i]=byte(i*37+dst*7+src*11+n); want[i]=data[i] }
  var snapshot [33]byte
  for i:=0;i<n;i++ { snapshot[i]=data[src+i] }
  for i:=0;i<n;i++ { want[dst+i]=snapshot[i] }
  ABI0Copy(unsafe.Pointer(&data[dst]),unsafe.Pointer(&data[src]),uintptr(n))
  if data!=want { panic("actual Go ABI0 memmove/canary mismatch") }
 } } }
}
`, len(runner) != 0)
	t.Log("actual Go ABI0 source memmove passed all 200 overlap/unaligned/full-canary vectors")
	file, err := Parse(ArchARM64, arm64PrivateCallCopySource)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, arm64PrivateCallCopyOptions(triple))
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	const driver = `#include <stdint.h>
extern void ABI0Copy(void *, const void *, uint64_t);
int main(void) {
 const int offsets[]={0,1,9,17,31}, sizes[]={0,1,2,3,8,17,32,33};
 for(int d=0;d<5;d++) for(int s=0;s<5;s++) for(int z=0;z<8;z++) {
  unsigned char data[96], want[96], snapshot[33];
  int dst=offsets[d],src=offsets[s],n=sizes[z];
  for(int i=0;i<96;i++) data[i]=want[i]=(unsigned char)(i*37+dst*7+src*11+n);
  for(int i=0;i<n;i++) snapshot[i]=data[src+i];
  for(int i=0;i<n;i++) want[dst+i]=snapshot[i];
  ABI0Copy(data+dst,data+src,(uint64_t)n);
  for(int i=0;i<96;i++) if(data[i]!=want[i]) return 1;
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_call_copy", triple, module.String(), driver, runner)
}
