package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Keep the old complete literal independent of the bounded counterpart. A
// pointer declaration does not authenticate the caller's dynamic Tag/TOP.
const x86X87ENVOriginalSource = `TEXT clearModeledStatus(SB),4,$0-16
MOVQ env+0(FP),BX
FLDENV (BX)
BYTE $0xdb; BYTE $0xe2
XORL AX,AX
FSTSW AX
MOVQ AX,ret+8(FP)
RET
`

func x86X87ENVBoundedSource() string {
	return strings.Replace(x86X87ENVOriginalSource, "MOVQ AX,ret+8(FP)\nRET\n",
		"MOVQ AX,ret+8(FP)\nFINIT\nRET\n", 1)
}

func x86X87ENVLiteral(t *testing.T, path, function string) string {
	t.Helper()
	return x86X87FunctionLiteral(t, path, function, "source")
}

func x86X87FunctionLiteral(t *testing.T, path, function, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != function {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || spec.Names[0].Name != name || len(spec.Values) != 1 {
				return true
			}
			literal, ok := spec.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("old source stopped being an independent complete literal")
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
			return false
		})
	}
	if len(values) != 1 {
		t.Fatal("old complete source literal missing or duplicated", path, function)
	}
	return values[0]
}

func TestX86X87ENVBoundedCounterpartPreservesCompleteOriginal(t *testing.T) {
	for _, owner := range []struct{ file, function string }{
		{"x86_x87_environment_source_test.go", "TestX86X87SoftwareEnvironmentClearCompleteSourceThreeAPIs"},
		{"amd64_raw_x87_control_test.go", "TestX86RawX87SoftwareClearPreservesAllStatusFields"},
	} {
		t.Run(owner.function, func(t *testing.T) {
			if got := x86X87ENVLiteral(t, owner.file, owner.function); got != x86X87ENVOriginalSource {
				t.Fatal("complete old environment source changed")
			}
		})
	}
	bounded := x86X87ENVBoundedSource()
	if strings.Count(bounded, "FINIT\n") != 1 || strings.Replace(bounded, "FINIT\n", "", 1) != x86X87ENVOriginalSource ||
		!strings.Contains(bounded, "FSTSW AX\nMOVQ AX,ret+8(FP)\nFINIT\nRET\n") {
		t.Fatal("counterpart must add only one FINIT after the captured result write")
	}
}

func TestX86X87ENVBoundedCounterpartThreeAPIs(t *testing.T) {
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, x86X87ENVBoundedSource(), "func clearModeledStatus(env *byte) uint64",
					"amd64", triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("bounded counterpart rejected before any read/value observation; original is not certified", err)
				}
			})
		}
	}
}

func TestX86X87ENVOriginalQueryAndSourceBoundaries(t *testing.T) {
	const declaration = "func clearModeledStatus(env *byte) uint64"
	for _, source := range []struct{ name, text string }{
		{"original-unknown-shape", x86X87ENVOriginalSource},
		{"bounded-counterpart", x86X87ENVBoundedSource()},
	} {
		t.Run("query/"+source.name, func(t *testing.T) {
			_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(env *byte) uint64", "RET")
			sig.Name = "clearModeledStatus"
			file, err := Parse(ArchAMD64, source.text)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := normalizeX86RawFile(file, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			for _, fn := range []Func{file.Funcs[0], normalized.Funcs[0]} {
				if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone original/decoded query borrowed a paired environment read", err)
				}
			}
		})
	}
	for _, mutation := range []struct{ name, source string }{
		{"original-unknown-shape", x86X87ENVOriginalSource},
		{"one-path-misses-init", strings.Replace(x86X87ENVBoundedSource(), "FINIT\nRET", "TESTL AX,AX\nJE done\nFINIT\ndone:\nRET", 1)},
		{"init-does-not-create-F0", strings.Replace(x86X87ENVBoundedSource(), "FINIT\nRET", "FINIT\nFTST\nRET", 1)},
		{"nonempty-after-init", strings.Replace(x86X87ENVBoundedSource(), "FINIT\nRET", "FINIT\nFLD1\nRET", 1)},
		{"unknown-address", strings.Replace(x86X87ENVBoundedSource(), "MOVQ env+0(FP),BX\n", "", 1)},
		{"NUM-is-not-pointer", strings.Replace(x86X87ENVBoundedSource(), "MOVQ env+0(FP),BX", "MOVQ $32,BX", 1)},
		{"FRSTOR-is-not-ENV28", strings.Replace(x86X87ENVBoundedSource(), "FLDENV", "FRSTOR", 1)},
		{"read-does-not-authorize-ENV-store", strings.Replace(x86X87ENVBoundedSource(), "FLDENV (BX)\n", "FLDENV (BX)\nFSTENV (BX)\n", 1)},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(mutation.name+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, mutation.source, declaration, "amd64", "x86_64-unknown-linux-gnu", api, X87Software)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("environment source borrowed unknown shape/value/address or another restore footprint", err)
				}
				// An earlier Context is not evidence that a later stack/shape
				// guard ran. Preserve this exact first diagnostic in the raw log.
				t.Logf("FIRST_CONTEXT %s: %v", mutation.name, err)
			})
		}
	}
}

func x86X87ENVReadIR(t *testing.T, segment Reg, dead bool) string {
	t.Helper()
	var body strings.Builder
	ctx := &amd64Ctx{b: &body, goarch: "amd64", x87Mode: X87Software,
		regSlot: map[Reg]string{BX: "%base"}, x87ControlSlot: "%cw", x87StatusSlot: "%sw"}
	source := Operand{Kind: OpMem, Mem: MemRef{Base: BX, Segment: segment}}
	if err := ctx.loadX87Environment(source); err != nil {
		t.Fatal(err)
	}
	result := "ret i16 0\n"
	if !dead {
		result = "%result = load i16, ptr %sw\nret i16 %result\n"
	}
	return "define i16 @EnvRead(i64 %address) {\n%base = alloca i64\nstore i64 %address, ptr %base\n" +
		"%cw = alloca i16\n%sw = alloca i16\n" + body.String() + result + "}\n"
}

func x86X87ENVTypeBytes(typ llvm.Type) int {
	switch typ.TypeKind() {
	case llvm.IntegerTypeKind:
		if bits := typ.IntTypeWidth(); bits > 0 && bits <= 224 && bits%8 == 0 {
			return bits / 8
		}
	case llvm.ArrayTypeKind:
		if typ.ArrayLength() <= 28 {
			return typ.ArrayLength() * x86X87ENVTypeBytes(typ.ElementType())
		}
	case llvm.VectorTypeKind:
		if typ.VectorSize() <= 28 {
			return typ.VectorSize() * x86X87ENVTypeBytes(typ.ElementType())
		}
	}
	return 0
}

func x86X87ENVReadOffset(pointer llvm.Value, roots map[llvm.Value]bool, remaining *int) (int, bool) {
	if *remaining == 0 {
		return 0, false // Unknown/cyclic pointer graphs cannot manufacture an offset.
	}
	*remaining--
	if roots[pointer] {
		return 0, true
	}
	if !pointer.IsAIntToPtrInst().IsNil() {
		return 0, true
	}
	if !pointer.IsASelectInst().IsNil() {
		first, firstOK := x86X87ENVReadOffset(pointer.Operand(1), roots, remaining)
		last, lastOK := x86X87ENVReadOffset(pointer.Operand(2), roots, remaining)
		return first, firstOK && lastOK && first == last
	}
	if !pointer.IsAPHINode().IsNil() {
		if pointer.IncomingCount() == 0 {
			return 0, false
		}
		first, valid := x86X87ENVReadOffset(pointer.IncomingValue(0), roots, remaining)
		for index := 1; valid && index < pointer.IncomingCount(); index++ {
			other, known := x86X87ENVReadOffset(pointer.IncomingValue(index), roots, remaining)
			valid = known && other == first
		}
		return first, valid
	}
	if pointer.IsAGetElementPtrInst().IsNil() || pointer.OperandsCount() != 2 ||
		pointer.GEPSourceElementType().TypeKind() != llvm.IntegerTypeKind || pointer.GEPSourceElementType().IntTypeWidth() != 8 ||
		pointer.Operand(1).IsAConstantInt().IsNil() {
		return 0, false
	}
	delta := pointer.Operand(1).SExtValue()
	if delta < -28 || delta > 28 {
		return 0, false // Bound arithmetic before narrowing or adding offsets.
	}
	base, valid := x86X87ENVReadOffset(pointer.Operand(0), roots, remaining)
	return base + int(delta), valid
}

func x86X87ENVReadFootprint(ir string, addressSpace int) error {
	return x86X87ENVReadFootprintOf(ir, addressSpace, "EnvRead")
}

func x86X87ENVReadFootprintOf(ir string, addressSpace int, name string) error {
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		return err
	}
	function := module.NamedFunction(name)
	if function.IsNil() {
		return fmt.Errorf("missing complete environment read")
	}
	roots := make(map[llvm.Value]bool)
	for index := 0; index < function.ParamsCount(); index++ {
		parameter := function.Param(index)
		if parameter.Type().TypeKind() == llvm.PointerTypeKind {
			roots[parameter] = true
		}
	}
	var seen [28]int
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for ins := block.FirstInstruction(); !ins.IsNil(); ins = llvm.NextInstruction(ins) {
			if ins.IsALoadInst().IsNil() || x86GPSIMDStoreTargetsBackingAlloca(ins.Operand(0)) {
				continue
			}
			pointer := ins.Operand(0)
			remaining := 256
			offset, valid := x86X87ENVReadOffset(pointer, roots, &remaining)
			width := x86X87ENVTypeBytes(ins.Type())
			if !valid || width <= 0 || offset < 0 || offset > 28-width || !ins.IsVolatile() || ins.Alignment() != 1 ||
				pointer.Type().PointerAddressSpace() != addressSpace {
				return fmt.Errorf("wrong ENV28 extent/volatility/address space: %s", ins.String())
			}
			for index := offset; index < offset+width; index++ {
				seen[index]++
			}
		}
	}
	for offset, count := range seen {
		if count != 1 {
			return fmt.Errorf("ENV byte %d read %d times, want exactly once", offset, count)
		}
	}
	return nil
}

// A direct emitter observation, not native entry or source admission. The
// independent public complete-source owner above must also pass separately.
func TestX86X87ENVSoftwareReadRetainsAll28BytesAndAddressSpace(t *testing.T) {
	for _, segment := range []Reg{"", FS, GS} {
		space := map[Reg]int{"": 0, FS: 257, GS: 256}[segment]
		for _, dead := range []bool{false, true} {
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("AS%d/dead%t/O2-%t", space, dead, optimized), func(t *testing.T) {
					ir := x86X87ENVReadIR(t, segment, dead)
					if optimized {
						ir = x86MulDivRoundOptimize(t, ir)
					}
					if err := x86X87ENVReadFootprint(ir, space); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86X87ENVReadFootprintCheckerHasIndependentControls(t *testing.T) {
	const reference = `define i16 @EnvRead(i64 %address) {
%p = inttoptr i64 %address to ptr addrspace(257)
%v = load volatile i224, ptr addrspace(257) %p, align 1
ret i16 0
}
`
	if err := x86X87ENVReadFootprint(reference, 257); err != nil {
		t.Fatal("independent full-28 reference was rejected", err)
	}
	for _, change := range []struct{ name, from, to string }{
		{"missing-volatility", "load volatile", "load"},
		{"word-only", "i224", "i16"},
		{"short-ENV", "i224", "i208"},
		{"FRSTOR-sized", "i224", "i864"},
		{"wrong-address-space", "257", "256"},
		{"invented-alignment", "align 1", "align 2"},
		{"duplicate-read", "ret i16 0", "%again = load volatile i224, ptr addrspace(257) %p, align 1\nret i16 0"},
		{"missing-read", "%v = load volatile i224, ptr addrspace(257) %p, align 1", "; no read"},
	} {
		t.Run(change.name, func(t *testing.T) {
			modified := strings.ReplaceAll(reference, change.from, change.to)
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := parseIRModuleInContext(context, modified)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal("checker control must be valid LLVM IR, not a parser rejection", err)
			}
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal("checker control is not valid LLVM IR", err)
			}
			if err := x86X87ENVReadFootprint(modified, 257); err == nil {
				t.Fatal("wrong ENV footprint escaped its independent reader")
			}
		})
	}
}

func TestX86X87ENVFinalFINITPreservesCapturedBytesNotValues(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			state := x86ResultState{fp: []bool{true, true}, gp: [16]uint8{0: 0xff},
				x87: &x86ResultX87State{invalid: true, status: 0xffff, gp: [16]uint16{0: 0xffff},
					word: &x86ResultX87WordState{control: 0xffff}}}
			before := state.clone()
			if accepted, known := x86ResultX87WordStep(x86X87ValueInstruction(t, "FINIT"), &state, nil, 0, arch); !known || !accepted {
				t.Fatal("explicit final initialize did not recover a known empty shape")
			}
			if state.x87.invalid || state.x87.depth != 0 || state.x87.slots != 0 || state.gp != before.gp ||
				state.x87.gp != before.x87.gp || len(state.fp) != 2 || !state.fp[0] || !state.fp[1] ||
				state.x87.read(Operand{Kind: OpReg, Reg: "F0"}) {
				t.Fatal("FINIT changed captured bytes or manufactured an initialized x87 value")
			}
		})
	}
}

// This executes Software semantics on the actual host target. It is neither
// original Go execution nor an x86 hardware ENV/Tag/exception oracle. The old
// host-gated hardware oracle and the original complete source remain unchanged.
func TestX86X87ENVBoundedHostSoftwareCapturedStatusExecution(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang are required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	const mainC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint64_t clearModeledStatus(const void *);
int main(void) {
  unsigned char storage[64], before[64];
  unsigned char *env=storage+17; /* unaligned, with canaries on both sides */
  const uint16_t control=0x037f, tags=0xffff;
  for (unsigned status=0; status<=0xffff; status++) {
    const uint16_t input=(uint16_t)status;
    memset(storage,0xa5,sizeof(storage)); memset(env,0,28);
    memcpy(env,&control,2); memcpy(env+4,&input,2); memcpy(env+8,&tags,2);
    memcpy(before,storage,sizeof(storage));
    const uint64_t got=clearModeledStatus(env), expected=status&0x7f00;
    if (got!=expected || memcmp(storage,before,sizeof(storage))) {
      fprintf(stderr,"Software status=%x got=%llx expected=%llx or input changed\n",
              status,(unsigned long long)got,(unsigned long long)expected);
      return 1;
    }
  }
  return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/IR-O2-%t", api, optimized), func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, x86X87ENVBoundedSource(), "func clearModeledStatus(env *byte) uint64",
					"amd64", triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("source rejected: host Software numerical execution was not reached", err)
				}
				if strings.Contains(ir, "asm sideeffect") {
					t.Fatal("host Software oracle must not execute hardware x87 inline assembly")
				}
				if optimized {
					ir = x86MulDivRoundOptimize(t, ir)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "env-bounded-software", triple, ir, mainC, nil)
			})
		}
	}
}
