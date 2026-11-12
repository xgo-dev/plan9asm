package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func x86BoolTailRoutingProgram() (string, string) {
	var source, declarations strings.Builder
	for _, condition := range amd64RegisterBoolConditions {
		name := "Tail" + condition
		fmt.Fprintf(&source, "TEXT ·%s<ABIInternal>(SB),4,$0-17\nCMPQ AX,BX\nJMP body%s<>(SB)\n"+
			"TEXT body%s<>(SB),4,$0-0\n%s AL\nMOVBLZX AL,AX\nRET\n", name, name, name, condition)
		fmt.Fprintf(&declarations, "func %s(a,b uint64) bool\n", name)
	}
	return source.String(), declarations.String()
}

// Explicit standalone encoder permission is not an authenticated Go runtime
// entry. Retain all original roots/helpers and their relocations as one object.
func x86BoolTailRoutingGoObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "tails.s"), filepath.Join(dir, "tails.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(arm64ClosureGoAsmArgs(t), "-S", "-o", output, input)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local", "GOFLAGS=")
	listing, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, output, listing, err, ctx.Err(), true, "amd64"); failure != nil {
		t.Fatalf("complete original bool-tail Go object: %v\n%s", failure, listing)
	}
	if strings.Count(string(listing), " STEXT ") != 32 {
		t.Fatal("original sixteen roots/helpers were not all assembled")
	}
}

func TestX86BoolTailRoutingCompleteConditionsThreeTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source, declarations := x86BoolTailRoutingProgram()
	x86BoolTailRoutingGoObject(t, source)
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil || strings.Count(ir, "define i1 @Tail") != 16 {
					t.Fatal("AMD64 canonical tail entered a foreign custom-register proof", err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, text, level)
					}
				}
			})
		}
	}
}

func TestX86CustomHelperBoolTailRejectsForeignArchitecture(t *testing.T) {
	for _, arch := range []string{"", "amd64", "arm64"} {
		t.Run("mode="+arch, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			options.Goarch = arch
			source := &x86ABI0BoolCallSource{origin: file, original: x86DirectTailSnapshot(file), options: options}
			plan := &x86ABI0BoolCallPlan{source: source, function: file.Funcs[0], signature: options.Sigs["compare"]}
			err := source.prepareCustomRegisterTail(plan)
			if !errors.Is(err, ErrProbeNeedsContext) || source.customGraph != nil || plan.registerTail != nil {
				t.Fatal("foreign mode constructed a private 386 graph", err)
			}
		})
	}
}

func TestX86BoolTailRoutingDefaultModeAndSelectionRechecks(t *testing.T) {
	for _, arch := range []string{"", "amd64"} {
		for _, mutation := range []string{"none", "resolver", "source", "declaration"} {
			t.Run("mode="+arch+"/"+mutation, func(t *testing.T) {
				assembly, declarations := x86BoolTailRoutingProgram()
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				pkg := mustGoPackage(t, "bitview", "package bitview\n"+declarations)
				resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				options := Options{Goarch: arch, TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs}
				options.ResolveSym = func(symbol string) string {
					calls++
					if calls == 1 {
						switch mutation {
						case "resolver":
							return "foreign"
						case "source":
							file.Funcs[0].Instrs[1].Raw += " // changed during selection"
						case "declaration":
							sig := sigs[resolve(symbol)]
							sig.Ret = I32
							sigs[resolve(symbol)] = sig
						}
					}
					return resolve(symbol)
				}
				plan, err := prepareX86ABI0BoolCalls(file, options)
				if calls == 0 || plan != nil || mutation == "none" && err != nil ||
					mutation != "none" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("mode routing bypassed complete source/declaration observation", calls, plan != nil, err)
				}
			})
		}
	}
}

func TestX86BoolTailRoutingPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	source, declarations := x86BoolTailRoutingProgram()
	var wrappers, prototypes, checks strings.Builder
	for index, condition := range amd64RegisterBoolConditions {
		fmt.Fprintf(&wrappers, "define i32 @Probe%d(i64 %%a,i64 %%b) {\n"+
			"  %%v = call i1 @Tail%s(i64 %%a,i64 %%b)\n  %%r = zext i1 %%v to i32\n  ret i32 %%r\n}\n", index, condition)
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(uint64_t,uint64_t);\n", index)
		fmt.Fprintf(&checks, "        if (Probe%d(a,b) != want[%d]) {\n"+
			"            fprintf(stderr, \"tail condition %s a=%%llx b=%%llx\\n\",\n"+
			"                (unsigned long long)a, (unsigned long long)b);\n            return 1;\n        }\n", index, index, condition)
	}
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
int main(void) {
    const uint64_t values[] = {0, 1, 2, 3, UINT64_C(0x8000000000000000),
        UINT64_C(0x7fffffffffffffff), UINT64_MAX};
    unsigned seen[16] = {0};
    for (unsigned i = 0; i < 7; i++) for (unsigned j = 0; j < 7; j++) {
        uint64_t a = values[i], b = values[j], r = a - b;
        unsigned cf = a < b, zf = r == 0, sf = r >> 63;
        unsigned of = ((a ^ b) & (a ^ r)) >> 63;
        uint8_t parity = r;
        parity ^= parity >> 4;
        parity ^= parity >> 2;
        parity ^= parity >> 1;
        unsigned pf = (parity & 1) == 0;
        unsigned want[] = {!cf, cf, zf, sf == of, !zf && sf == of, !cf && !zf,
            zf || sf != of, cf || zf, sf != of, sf, !zf, !of, of, !pf, !sf, pf};
        for (unsigned k = 0; k < 16; k++) seen[k] |= 1U << want[k];
` + checks.String() + `
    }
    for (unsigned k = 0; k < 16; k++) if (seen[k] != 3) return 2;
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			input := ir + wrappers.String()
			for _, text := range []string{input, x86DwordProductIROptimize(t, input)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "bool-tail-routing", triple, text, driver, nil, level)
				}
			}
		})
	}
}
