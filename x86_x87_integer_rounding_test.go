package plan9asm

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const x86X87SignedI64IdentitySource = "TEXT ·Value(SB),4,$0-16\nFMOVV input+0(FP),F0\nFMOVVP F0,ret+8(FP)\nRET\n"
const x86X87SignedI64IdentityDeclaration = "func Value(input int64) int64"

// Every signed I64 is exactly representable by the original x87 integer
// load/store pair. Its identity does not depend on the ambient RC selection.
// There is deliberately no word opcode to turn a lost-bit regression into
// an unrelated source-proof failure.
var x86X87SignedI64IdentityInputs = []int64{
	0, 1, -1,
	1<<53 - 1, 1 << 53, 1<<53 + 1, -(1<<53 + 1),
	1<<63 - 1, -1 << 63,
	0x5555555555555555, -0x5555555555555555,
}

func TestX86X87SignedI64IdentityFixtureHasNoWordProbe(t *testing.T) {
	file, err := Parse(ArchAMD64, x86X87SignedI64IdentitySource)
	if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 4 {
		t.Fatal("integer identity source must retain exactly its complete original body", err)
	}
	fn := file.Funcs[0]
	if fn.FrameSize != 0 || fn.ArgSize != 16 || fn.Instrs[1].Op != "FMOVV" ||
		fn.Instrs[2].Op != "FMOVVP" || fn.Instrs[3].Op != OpRET {
		t.Fatal("identity source acquired an unrelated instruction/storage probe")
	}
	for _, ins := range fn.Instrs {
		if _, word, _ := x86X87WordProperties(ins, "amd64"); word {
			t.Fatal("word obligation cannot replace the numerical precision counterexample")
		}
	}
	for _, target := range x86RawReturnTargets {
		_, _, sig, _ := x86ResultInitializationFixture(t, target.arch,
			x86X87SignedI64IdentityDeclaration, "NOP\nRET")
		if len(sig.Frame.Params) != 1 || len(sig.Frame.Results) != 1 ||
			sig.Frame.Params[0].Offset != 0 || sig.Frame.Params[0].Type != I64 ||
			sig.Frame.Results[0].Offset != 8 || sig.Frame.Results[0].Type != I64 {
			t.Fatal("actual typed integer identity layout changed", target.arch, sig.Frame)
		}
	}
}

func x86X87InlineActualValue(t *testing.T, ir, parameter string, resultBits int) string {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal("actual translated identity IR is malformed", err)
	}
	function := module.NamedFunction("Value")
	if function.IsNil() || function.ParamsCount() != 1 || function.Param(0).Type().String() != parameter ||
		function.GlobalValueType().ReturnType().TypeKind() != llvm.IntegerTypeKind ||
		function.GlobalValueType().ReturnType().IntTypeWidth() != resultBits {
		t.Fatal("constant observer lost the actual translated parameter/result types")
	}
	// This test-only optimization request changes neither the source body nor
	// its signature. It ensures the observer checks the real translated call,
	// not the optimizer's heuristic decision about a large software helper.
	function.AddFunctionAttr(context.CreateEnumAttribute(llvm.AttributeKindID("alwaysinline"), 0))
	return module.String()
}

func TestX86X87SignedI64IdentityRetainsAllBitsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, x86X87SignedI64IdentitySource,
					x86X87SignedI64IdentityDeclaration, target.arch, target.triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("complete original integer identity did not reach its numerical consumer", err)
				}
				for _, input := range x86X87SignedI64IdentityInputs {
					t.Run(fmt.Sprintf("input=%016x", uint64(input)), func(t *testing.T) {
						probe := x86X87InlineActualValue(t, ir, "i64", 64) +
							fmt.Sprintf("\ndefine i64 @IdentityProbe() {\n %%r = call i64 @Value(i64 %d)\n ret i64 %%r\n}\n", input)
						x86ScalarFPNamedConstantResult(t, probe, "IdentityProbe", []uint64{uint64(input)})
					})
				}
			})
		}
	}
	// This is LLVM O2 constant-state evidence on the local host, not execution
	// of original Go opcodes or of the Auto/Hardware inline assembly.
}

func TestX86X87SoftwareRoundedIntegerBoundariesNeverBecomePoison(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.triple != "x86_64-unknown-linux-gnu" && target.triple != "i386-unknown-linux-gnu" {
			continue // Full five-target direction grammar is independently tested above.
		}
		for _, row := range []struct {
			op, typ string
			bits    int
		}{
			{"FMOVW", "int16", 16},
			{"FMOVWP", "int16", 16},
			{"FMOVL", "int32", 32},
			{"FMOVLP", "int32", 32},
			{"FMOVVP", "int64", 64},
		} {
			lower, upper := -math.Ldexp(1, row.bits-1), math.Ldexp(1, row.bits-1)
			below := lower - 1
			if row.bits == 64 {
				below = math.Nextafter(lower, math.Inf(-1))
			}
			values := []float64{0, math.Copysign(0, -1), 1.5, -1.5, 2.5, -2.5,
				math.NaN(), math.Inf(1), math.Inf(-1), lower, upper, below, math.Nextafter(upper, 0)}
			for mode := 0; mode < 4; mode++ {
				declaration := "func Value(input float64) " + row.typ
				body := fmt.Sprintf("MOVW $%d,control-2(SP)\nFLDCW control-2(SP)\nFMOVD input+0(FP),F0\n%s F0,ret+RESULT(FP)\n",
					0x037f|mode<<10, row.op)
				if !strings.HasSuffix(row.op, "P") {
					// Keep the non-pop store's real direction and balance only
					// afterwards; do not replace it with its popping sibling.
					body += "FINIT\n"
				}
				source := x86X87IntegerRoundingSource(t, target.arch, declaration, body, 16)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/RC%d/%s", target.triple, row.op, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, X87Software)
						if err != nil || ir == "" {
							t.Fatal("source-defined masked CW did not reach integer conversion", err)
						}
						ir = x86X87InlineActualValue(t, ir, "double", row.bits)
						for index, value := range values {
							t.Run(fmt.Sprintf("sample%d=%016x", index, math.Float64bits(value)), func(t *testing.T) {
								rounded := []func(float64) float64{math.RoundToEven, math.Floor, math.Ceil, math.Trunc}[mode](value)
								want := uint64(1) << uint(row.bits-1) // Masked invalid: integer indefinite, not saturation.
								if !math.IsNaN(rounded) && rounded >= lower && rounded < upper {
									want = uint64(int64(rounded))
									if row.bits < 64 {
										want &= uint64(1)<<uint(row.bits) - 1
									}
								}
								probe := fmt.Sprintf("\ndefine i%d @RoundProbe() {\n %%r = call i%d @Value(double 0x%016X)\n ret i%d %%r\n}\n",
									row.bits, row.bits, math.Float64bits(value), row.bits)
								x86ScalarFPNamedConstantResult(t, ir+probe, "RoundProbe", []uint64{want})
							})
						}
					})
				}
			}
		}
	}
	// FINIT plus an explicit known masked CW defines every control used here.
	// No default Software environment or unmasked trap contract is inferred.
}

type x86X87IntegerRoundingCase struct {
	name, declaration, body string
}

func x86X87IntegerRoundingCases() []x86X87IntegerRoundingCase {
	var rows []x86X87IntegerRoundingCase
	for _, width := range []struct {
		name, typ string
	}{{"W", "int16"}, {"L", "int32"}, {"V", "int64"}} {
		load, pop := "FMOV"+width.name, "FMOV"+width.name+"P"
		rows = append(rows, x86X87IntegerRoundingCase{
			name: "load-" + load, declaration: fmt.Sprintf("func Value(input %s) %s", width.typ, width.typ),
			body: load + " input+0(FP),F0\n" + pop + " F0,ret+RESULT(FP)\n",
		})
		rows = append(rows, x86X87IntegerRoundingCase{
			name: "store-pop-" + pop, declaration: "func Value(input float64) " + width.typ,
			body: "FMOVD input+0(FP),F0\n" + pop + " F0,ret+RESULT(FP)\n",
		})
		if width.name != "V" {
			rows = append(rows, x86X87IntegerRoundingCase{
				name: "store-nonpop-" + load, declaration: "func Value(input float64) " + width.typ,
				body: "FMOVD input+0(FP),F0\n" + load + " F0,ret+RESULT(FP)\nFINIT\n",
			})
		}
	}
	return append(rows, x86X87IntegerRoundingCase{
		name: "round-FRNDINT", declaration: "func Value(input float64) float64",
		body: "FMOVD input+0(FP),F0\nFRNDINT\nFMOVDP F0,ret+RESULT(FP)\n",
	})
}

func x86X87IntegerRoundingSource(t *testing.T, arch, declaration, body string, frame int) string {
	t.Helper()
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "NOP\nRET")
	if len(sig.Frame.Results) != 1 {
		t.Fatal("rounding fixture needs its actual single declared result")
	}
	body = strings.ReplaceAll(body, "RESULT", fmt.Sprint(sig.Frame.Results[0].Offset))
	_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, "FINIT\n"+body+"RET")
	if frame != 0 {
		source = strings.Replace(source, ",4,$0-", fmt.Sprintf(",4,$%d-", frame), 1)
	}
	return source
}

func TestX86X87IntegerRoundingCompleteDirectionsThreeAPIs(t *testing.T) {
	rows := x86X87IntegerRoundingCases()
	if len(rows) != 9 {
		t.Fatal("complete seven-name, nine-direction denominator changed")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range rows {
			source := x86X87IntegerRoundingSource(t, target.arch, row.declaration, row.body, 0)
			for _, mode := range []X87Mode{X87Auto, X87Hardware, X87Software} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, row.name, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, row.declaration, target.arch, target.triple, api, mode)
						if err != nil || ir == "" {
							t.Fatal("explicitly initialized complete integer-rounding row was rejected", err)
						}
					})
				}
			}
		}
	}
	// All Software control-dependent cases start FINIT. This does not decide
	// the separate API contract for an uninitialized virtual control word.
}

func TestX86X87IntegerRoundingBoundStorageAndStack(t *testing.T) {
	rows := []struct {
		name, declaration, body string
		good                    bool
	}{
		{"AUTO-W", "func Value(input int16) int16", "MOVW input+0(FP),AX\nMOVW AX,cell-2(SP)\nFMOVW cell-2(SP),F0\nFMOVWP F0,ret+RESULT(FP)\n", true},
		{"AUTO-L", "func Value(input int32) int32", "MOVL input+0(FP),AX\nMOVL AX,cell-4(SP)\nFMOVL cell-4(SP),F0\nFMOVLP F0,ret+RESULT(FP)\n", true},
		{"AUTO-V", "func Value(input int64) int64", "MOVL input+0(FP),AX\nMOVL AX,cell-8(SP)\nMOVL input_hi+4(FP),AX\nMOVL AX,cell-4(SP)\nFMOVV cell-8(SP),F0\nFMOVVP F0,ret+RESULT(FP)\n", true},
		{"AUTO-FRNDINT", "func Value(input float64) float64", "FMOVD input+0(FP),F0\nFMOVDP F0,cell-8(SP)\nFMOVD cell-8(SP),F0\nFRNDINT\nFMOVDP F0,ret+RESULT(FP)\n", true},
		{"unknown-F0", "func Value(input int16) int16", "FMOVWP F0,ret+RESULT(FP)\n", false},
		{"missing-result", "func Value(input int64) int64", "FMOVV input+0(FP),F0\nFINIT\n", false},
		{"partial-result", "func Value(input int16) int64", "FMOVW input+0(FP),F0\nFMOVWP F0,ret+RESULT(FP)\n", false},
		{"unbalanced-nonpop", "func Value(input int16) int16", "FMOVW input+0(FP),F0\nFMOVW F0,ret+RESULT(FP)\n", false},
		{"overflow-stack", "func Value(input int16) int16", strings.Repeat("FLD1\n", 9) + "FMOVWP F0,ret+RESULT(FP)\nFINIT\n", false},
		{"unwritten-AUTO", "func Value(input int16) int16", "FMOVW cell-2(SP),F0\nFMOVWP F0,ret+RESULT(FP)\n", false},
		{"padding", "func Value(a byte,b int64) int16", "FMOVW a+0(FP),F0\nFMOVWP F0,ret+RESULT(FP)\n", false},
		// A typed pointer alone supplies neither NUM pointee bytes nor the
		// independently paired native-read role. This is not invalid Go syntax.
		{"independent-native-read-role-unproved", "func Value(input *byte) int16", "MOVE input+0(FP),BX\nFMOVW (BX),F0\nFMOVWP F0,ret+RESULT(FP)\n", false},
		// The existing exact natural I16 parameter writer is a private shadow,
		// not a caller/native-frame write. A defined F0 may use that same role.
		{"whole-natural-I16-shadow", "func Value(input int16) int16", "FMOVW input+0(FP),F0\nFMOVWP F0,input+0(FP)\nMOVW input+0(FP),AX\nMOVW AX,ret+RESULT(FP)\n", true},
		{"unknown-CALL", "func Value(input int16) int16", "CALL ·unknown(SB)\nFINIT\nFMOVW input+0(FP),F0\nFMOVWP F0,ret+RESULT(FP)\n", false},
	}
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, row := range rows {
			body := strings.ReplaceAll(row.body, "MOVE", move)
			source := x86X87IntegerRoundingSource(t, target.arch, row.declaration, body, 16)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, row.declaration,
						target.arch, target.triple, api, X87Software)
					if row.good && (err != nil || ir == "") ||
						!row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("rounding changed independent storage/initialized-byte/stack authority", row.good, err)
					}
					if row.name == "whole-natural-I16-shadow" {
						actual := x86X87InlineActualValue(t, ir, "i16", 16)
						for _, input := range []uint16{0, 7, 0x7fff, 0x8000, 0xfffe} {
							probe := fmt.Sprintf("\ndefine i16 @ShadowProbe() {\n %%r = call i16 @Value(i16 %d)\n ret i16 %%r\n}\n", input)
							x86ScalarFPNamedConstantResult(t, actual+probe, "ShadowProbe", []uint64{uint64(input)})
						}
					}
				})
			}
		}
	}
}
