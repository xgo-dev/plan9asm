package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

var x86OrderingHintTargets = []struct{ arch, triple string }{
	{"amd64", "x86_64-apple-darwin"},
	{"amd64", "x86_64-unknown-linux-gnu"},
	{"amd64", "x86_64-pc-windows-msvc"},
	{"386", "i386-unknown-linux-gnu"},
	{"386", "i686-pc-windows-msvc"},
}

func x86OrderingHintGoBytes(t *testing.T, arch, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "tool", "asm", "-S", "-p", "ordering", "-o", object, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "GOFLAGS=")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, arch); failure != nil {
		t.Fatalf("actual original Go object: %v\n%s", failure, output)
	}
	var code []byte
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, encoded, err := goAssemblyListingByteRow(line)
		if err != nil || offset != len(code) {
			t.Fatalf("noncontiguous original object listing: %s", line)
		}
		code = append(code, encoded...)
	}
	if len(code) == 0 {
		t.Fatal("actual original object listing lacks complete bytes")
	}
	return code
}

func TestX86OrderingHintsCompleteGoRowsAndDispatch(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") || len(x86OrderingHintSpecs) != 4 {
		t.Fatal("complete Go zero-operand family changed")
	}
	for _, row := range x86OrderingHintOracleRows {
		if !strings.Contains(string(table), row.registration) {
			t.Fatal("complete Go ordered row changed", row.registration)
		}
		for _, arch := range []string{"386", "amd64"} {
			for _, identity := range []Op{"", row.op, Op(strings.ToLower(string(row.op))), "MOVQ", Op(string(row.op) + ".BAD")} {
				t.Run(arch+"/"+string(row.op)+"/identity="+string(identity), func(t *testing.T) {
					ins := Instr{Op: identity}
					ctx, out := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := out.String(), ctx.tmp
					registers := fmt.Sprint(ctx.usedRegs)
					known, terminated, err := ctx.lowerX86OrderingHint(row.op, ins)
					invalid := identity != "" && !strings.EqualFold(string(identity), string(row.op))
					if !known || terminated || (err != nil) != invalid || invalid && (before != out.String() || temporary != ctx.tmp) {
						t.Fatal("identity rejection/emission boundary", identity, err)
					}
					if fmt.Sprint(ctx.usedRegs) != registers {
						t.Fatal("zero-operand source introduced implicit data registers", ctx.usedRegs)
					}
				})
			}
			for _, suffix := range []string{".Z", ".SAE", ".BCST", ".BAD"} {
				ins := Instr{Op: Op(string(row.op) + suffix)}
				if _, known, err := x86OrderingHintProperties(ins.Op, ins, arch); !known || err == nil {
					t.Fatal("invalid suffix was not closed", ins, err)
				}
			}
		}
		for _, arch := range []string{"", "arm", "arm64", "wasm"} {
			if _, known, err := x86OrderingHintProperties(row.op, Instr{Op: row.op}, arch); !known || err == nil {
				t.Fatal("unrelated architecture admitted an x86 form", arch, err)
			}
		}
	}
	ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
	before := output.String()
	if known, terminated, err := ctx.lowerX86OrderingHint("UNKNOWN", Instr{}); known || terminated || err != nil || before != output.String() {
		t.Fatal("unknown dispatch emitted a default instruction")
	}
}

func x86OrderingHintTranslateAPI(t *testing.T, api, source, declarations, arch, triple string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "ordering", declarations)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: resolve})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return translated.Module.String(), nil
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		return Translate(file, options)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return module.String(), nil
}

func TestX86OrderingHintsThreeAPIsFiveTargetNativeObjects(t *testing.T) {
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	for _, target := range x86OrderingHintTargets {
		for _, raw := range []bool{false, true} {
			var source, declarations strings.Builder
			declarations.WriteString("package ordering\n")
			for _, row := range x86OrderingHintOracleRows {
				name := strings.ToLower(string(row.op))
				fmt.Fprintf(&declarations, "func %s()\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", name)
				if raw {
					for _, value := range row.machine {
						fmt.Fprintf(&source, "BYTE $%d\n", value)
					}
				} else {
					fmt.Fprintln(&source, row.op)
				}
				source.WriteString("RET\n")
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/raw=%t/%s", target.triple, raw, api), func(t *testing.T) {
					ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						dir := t.TempDir()
						input, object := filepath.Join(dir, "ordering.ll"), filepath.Join(dir, "ordering.o")
						if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
							t.Fatal(err)
						}
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", "-o", object, input))
						disassembly := x86FloatCompareCaptureCommand(t, exec.Command(disassembler, "--disassemble", "--no-show-raw-insn", object))
						for _, row := range x86OrderingHintOracleRows {
							count := 0
							for _, line := range strings.Split(string(disassembly), "\n") {
								fields := strings.Fields(line)
								if len(fields) == 2 && strings.HasSuffix(fields[0], ":") && fields[1] == strings.ToLower(string(row.op)) {
									count++
								}
							}
							if count != 1 {
								t.Fatalf("%s object lost or duplicated native %s: count=%d\n%s", level, row.op, count, disassembly)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86RawPrefixThreeAPIClassification(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, row := range []struct {
			name    string
			code    []byte
			context bool
		}{
			{"invalid even with later ignored override", []byte{0xf0, 0x66, 0x0f, 0x31}, false},
			{"valid LOCK atomic effect unbound", []byte{0xf0, 0x01, 0x08}, true},
			{"legal ignored prefix", []byte{0x66, 0x66, 0x0f, 0x31}, false},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := "TEXT ·prefix(SB),4,$0-0\n" + x86RawDisplacementDirectives(row.code) + "RET\n"
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc prefix()\n", target.arch, target.triple)
					if row.name == "legal ignored prefix" {
						if err != nil || !strings.Contains(ir, "asm sideeffect \"rdtsc\"") {
							t.Fatal("legal ignored prefix lost its actual instruction", err)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "ignored.ll", "ignored.o", ir)
					} else if err == nil || ir != "" || errors.Is(err, ErrProbeNeedsContext) != row.context {
						t.Fatalf("invalid versus valid-unbound prefix classification: IR=%q/error=%v", ir, err)
					}
				})
			}
		}
	}
	physical, err := x86asm.Decode([]byte{0xf0, 0x0f, 0x31}, 64)
	if err != nil {
		t.Fatal(err)
	}
	physical.Prefix[0] |= x86asm.PrefixIgnored
	if err := decodedX86PrefixError(physical); err == nil || errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("synthetic Invalid|Ignored metadata tripwire washed invalidity", err)
	}
}
