package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const arm64PrivateDistinctCallsiteSource = `TEXT ·Run(SB),4,$0-8
MOVD $1,R9
CALL bump<>(SB)
MOVD $42,R0
CALL bump<>(SB)
ADD R9,R0,R0
MOVD R0,ret+0(FP)
RET
TEXT bump<>(SB),4,$0-0
ADD $1,R9,R9
RET
`

func TestARM64PrivateRegisterDistinctCallsiteState(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	pkg := mustGoPackage(t, "test/privatecalls", "package privatecalls\nfunc Run() uint64\n")
	for _, test := range []struct {
		name, source string
		want         uint64
	}{
		{"two_static_calls", arm64PrivateDistinctCallsiteSource, 45},
		{"BL_alias", strings.ReplaceAll(arm64PrivateDistinctCallsiteSource, "CALL bump", "BL bump"), 45},
		{"named_label_collision", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"MOVD $1,R9", "__arm64_private_0:\n__arm64_private_0_:\n__arm64_private_1:\nMOVD $1,R9", 1), 45},
		{"no_frame_preserves_original_LR", strings.NewReplacer(
			"TEXT ·Run(SB),4,$0-8", "TEXT ·Run(SB),516,$0-8\nMOVD R30,R22",
			"MOVD R0,ret+0(FP)", "MOVD R22,R30\nMOVD R0,ret+0(FP)",
		).Replace(arm64PrivateDistinctCallsiteSource), 45},
		{"both_branches_define", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"MOVD $42,R0", "CBNZ R9,other\nMOVD $42,R0\nB join\nother:\nMOVD $42,R0\njoin:", 1), 45},
		{"second_static_call_in_loop", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"MOVD $42,R0\nCALL bump<>(SB)",
			"MOVD $42,R0\nMOVD $2,R8\nagain:\nCALL bump<>(SB)\nSUB $1,R8,R8\nCBNZ R8,again", 1), 46},
		{"distinct_callsite_flags", strings.NewReplacer(
			"MOVD $1,R9", "MOVD $1,R9\nADDS $0,R9,R9",
			"MOVD $42,R0", "MOVD $42,R0\nSUBS $0,R0,R0",
			"ADD $1,R9,R9", "ADC $0,R9,R9",
		).Replace(arm64PrivateDistinctCallsiteSource), 44},
	} {
		t.Run(test.name, func(t *testing.T) {
			runARM64LocalRegisterGoOracle(t, test.source, fmt.Sprintf(`package main
func Run() uint64
func main() { if Run() != %d { panic("original callsite state mismatch") } }
`, test.want), len(runner) != 0)
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			file, err = CoalesceARM64PrivateRegisterHelpers(file)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
			} {
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(target+"/"+api, func(t *testing.T) {
						ir := arm64PrivateCallsiteIR(t, pkg, file, test.source, api,
							Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs})
						compileLLVMToObject(t, llc, target, "callsite.ll", "callsite.o", ir)
						if target == triple {
							main := fmt.Sprintf("#include <stdint.h>\nextern uint64_t Run(void);\nint main(void) { return Run() == %d ? 0 : 1; }\n", test.want)
							compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "callsite-state", target, ir, main, runner)
						}
					})
				}
			}
		})
	}
}

func arm64PrivateCallsiteIR(t *testing.T, pkg GoPackage, file *File, source, api string, opt Options) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	var ir string
	var err error
	switch api {
	case "text":
		ir, err = Translate(file, opt)
	case "module":
		var module llvm.Module
		module, err = TranslateModuleInContext(ctx, file, opt)
		if !module.IsNil() {
			defer module.Dispose()
			ir = module.String()
		}
	case "GoModule":
		var result *GoModuleTranslation
		result, err = translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: opt.Goarch, TargetTriple: opt.TargetTriple, ResolveSym: opt.ResolveSym,
		})
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
			ir = result.Module.String()
		}
	default:
		t.Fatalf("unknown callsite API %q", api)
	}
	if err != nil {
		t.Fatalf("%s/%s: a closed helper lost its per-call reaching write: %v", opt.TargetTriple, api, err)
	}
	return ir
}

func TestARM64PrivateRegisterCallsiteSourceExpansion(t *testing.T) {
	const calls = 128
	source := "TEXT ·Run(SB),4,$0-8\nMOVD $1,R9\n" +
		strings.Repeat("CALL bump<>(SB)\n", calls) +
		"MOVD R9,ret+0(FP)\nRET\nTEXT bump<>(SB),4,$0-0\nADD $1,R9,R9\nRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(file, original) || len(prepared.Funcs) != 1 {
		t.Fatal("per-call source expansion mutated the original source")
	}
	fn := prepared.Funcs[0]
	cloneLength := len(original.Funcs[1].Instrs) // LABEL + leaf body + B (R30).
	if len(fn.Instrs) != len(original.Funcs[0].Instrs)+calls*cloneLength {
		t.Fatal("source expansion did not grow exactly once per static call")
	}
	labels := make(map[string]bool)
	for _, ins := range fn.Instrs {
		if ins.Op != "CALL" {
			continue
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpIdent || labels[ins.Args[0].Ident] {
			t.Fatalf("static calls share an indirect return edge: %+v", ins)
		}
		labels[ins.Args[0].Ident] = true
	}
	if len(labels) != calls {
		t.Fatal("source expansion dropped a static call")
	}
	again, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil || !reflect.DeepEqual(again, prepared) {
		t.Fatalf("identical complete source did not prepare deterministically: %v", err)
	}
	idempotent, err := CoalesceARM64PrivateRegisterHelpers(prepared)
	if err != nil || !reflect.DeepEqual(idempotent, prepared) {
		t.Fatalf("repeated preparation duplicated helper bodies: %v", err)
	}
}

func TestARM64PrivateRegisterCallsiteExpansionBudget(t *testing.T) {
	// Pin the reviewed duplication budget, independently of its implementation.
	const budget = 1 << 16
	for _, test := range []struct {
		name       string
		leafLength int
		calls      []int
		wantError  bool
	}{
		{"exact_budget", budget / 32, []int{32}, false},
		{"one_instruction_per_clone_over", budget/32 + 1, []int{32}, true},
		{"combined_roots_over", budget / 32, []int{16, 17}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var source strings.Builder
			for root, calls := range test.calls {
				fmt.Fprintf(&source, "TEXT ·Run%d(SB),4,$0-8\nMOVD $1,R9\n", root)
				source.WriteString(strings.Repeat("CALL bump<>(SB)\n", calls))
				source.WriteString("MOVD R9,ret+0(FP)\nRET\n")
			}
			source.WriteString("TEXT bump<>(SB),4,$0-0\n")
			source.WriteString(strings.Repeat("ADD $1,R9,R9\n", test.leafLength-2))
			source.WriteString("RET\n")
			goAssemblerOracleOutput(t, "arm64", source.String(), "", true)
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			original, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
			if !reflect.DeepEqual(file, original) {
				t.Fatal("expansion budget mutated the authenticated original source")
			}
			if test.wantError {
				if prepared != nil || !errors.Is(err, ErrProbeNeedsContext) ||
					!strings.Contains(err.Error(), "expansion budget") {
					t.Fatalf("unbounded source duplication did not fail closed: %v", err)
				}
			} else if err != nil || prepared == nil || len(prepared.Funcs) != len(test.calls) {
				t.Fatalf("source at the exact duplication budget was rejected: %v", err)
			}
		})
	}
}

func TestARM64PrivateRegisterCallsiteDoesNotSupplyUndefinedBits(t *testing.T) {
	pkg := mustGoPackage(t, "test/privatecalls", "package privatecalls\nfunc Run() uint64\n")
	tests := []struct{ name, source, witness string }{
		{"first_call_reads_missing", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"ADD $1,R9,R9", "ADD R0,R9,R9", 1), "R0"},
		{"caller_missing_before_second", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"MOVD $42,R0\n", "", 1), "R0"},
		{"one_branch_missing_before_second", strings.Replace(arm64PrivateDistinctCallsiteSource,
			"MOVD $42,R0", "CBNZ R9,missing\nMOVD $42,R0\nmissing:", 1), "R0"},
		{"same_static_loop_first_visit_missing", strings.NewReplacer(
			"CALL bump<>(SB)\nMOVD $42,R0\nCALL bump<>(SB)",
			"MOVD $2,R8\nagain:\nCALL bump<>(SB)\nMOVD $42,R0\nSUB $1,R8,R8\nCBNZ R8,again",
			"ADD $1,R9,R9", "ADD R0,R9,R9",
		).Replace(arm64PrivateDistinctCallsiteSource), "R0"},
	}
	for _, flag := range []struct {
		name, instruction, condition string
		missingMask                  uint8
	}{
		{"C", "ADC $0,R9,R9", "ADC", 0x2},
		{"N", "CSEL MI,R9,R9,R9", "MI", 0x8},
		{"Z", "CSEL EQ,R9,R9,R9", "EQ", 0x4},
		{"V", "CSEL VS,R9,R9,R9", "VS", 0x1},
	} {
		// The second call has a real ADDS producer. Its flags cannot supply
		// the first invocation of the same private helper on any CFG path.
		source := strings.NewReplacer(
			"MOVD $42,R0", "MOVD $42,R0\nADDS $1,R0,R0",
			"ADD $1,R9,R9", flag.instruction,
		).Replace(arm64PrivateDistinctCallsiteSource)
		witness := fmt.Sprintf("arm64 condition %s has unknown NZCV bits %#x on a path to block ",
			flag.condition, flag.missingMask)
		tests = append(tests, struct{ name, source, witness string }{
			"first_call_missing_flags_" + flag.name, source, witness,
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			goAssemblerOracleOutput(t, "arm64", test.source, "", true)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			translation, err := translateGoModuleInContext(ctx, pkg, []byte(test.source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
			})
			if translation != nil && !translation.Module.IsNil() {
				translation.Module.Dispose()
				t.Fatal("undefined source register emitted a module")
			}
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.witness) {
				t.Fatalf("a callsite manufactured defined register bits or flags: %v", err)
			}
		})
	}
}
