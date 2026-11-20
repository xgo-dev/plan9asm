package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86UndefinedTrapCompleteTypedDispatchBoundaries(t *testing.T) {
	if len(x86UndefinedTrapSpecs) != 1 {
		t.Fatal("UNDEF and physical UD2 must share one canonical grammar")
	}
	spec := x86UndefinedTrapSpecs["UNDEF"]
	if spec.native != "ud2" || !bytes.Equal(spec.opBytes, []byte{0x0f, 0x0b}) {
		t.Fatal("undefined-instruction specification changed the architectural exception")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"UNDEF", "UD2", "undef", "ud2"} {
			for _, identity := range []Op{"", op, Op(strings.ToUpper(string(op))), "MOVQ", Op(string(op) + ".BAD")} {
				t.Run(arch+"/"+string(op)+"/identity="+string(identity), func(t *testing.T) {
					instruction := Instr{Op: identity, Raw: string(op)}
					before := fmt.Sprintf("%#v", instruction)
					ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					ir, temporary := output.String(), ctx.tmp
					known, terminated, err := ctx.lowerX86UndefinedTrap(op, instruction)
					invalid := identity != "" && !strings.EqualFold(string(identity), string(op))
					if !known || terminated == invalid || (err != nil) != invalid ||
						invalid && (ir != output.String() || temporary != ctx.tmp) ||
						before != fmt.Sprintf("%#v", instruction) {
						t.Fatal("undefined-instruction dispatch mutated input or emitted before rejection", err)
					}
				})
			}
			for _, suffix := range []string{".Z", ".SAE", ".BCST"} {
				instruction := Instr{Op: op, Raw: string(op) + suffix}
				if _, known, err := x86UndefinedTrapProperties(Op(string(op)+suffix), instruction, arch); !known || err == nil {
					t.Fatal("undefined-instruction grammar admitted an operand modifier", op, suffix)
				}
			}
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
		ctx.goarch = arch
		before, temporary := output.String(), ctx.tmp
		if known, terminated, err := ctx.lowerX86UndefinedTrap("UD2", Instr{Op: "UD2"}); !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
			t.Fatal("x86 undefined-instruction grammar admitted another architecture", arch, err)
		}
	}
	if _, known, err := x86UndefinedTrapProperties("INT", Instr{}, "amd64"); known || err != nil {
		t.Fatal("debug/software traps must not acquire the undefined-instruction grammar")
	}
}

func x86UndefinedTrapFixture(raw bool) string {
	op := "UNDEF\n"
	if raw {
		op = "BYTE $0x0f\nBYTE $0x0b\n"
	}
	return "TEXT ·fault(SB),4,$0-0\n" + op + "RET\n"
}

// Every API derives its signature from the same actual Go declaration, rather
// than using a manually supplied signature as its own correctness oracle.
func x86UndefinedTrapIR(t *testing.T, source, arch, triple, api string) string {
	t.Helper()
	pkg := mustGoPackage(t, "undefinedtrap", "package undefinedtrap\nfunc fault()\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: arch, TargetTriple: triple, ResolveSym: resolve,
		})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
		}
		if err != nil || translated == nil || translated.Module.IsNil() {
			t.Fatalf("Go module undefined-instruction consumer: %v", err)
		}
		return translated.Module.String()
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: signatures}
	if api == "text" {
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(err)
		}
		return ir
	}
	if api != "module" {
		t.Fatal("unknown undefined-instruction consumer", api)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil || module.IsNil() {
		t.Fatalf("LLVM module undefined-instruction consumer: %v", err)
	}
	return module.String()
}

func x86UndefinedTrapOptimizedIR(t *testing.T, ir string) string {
	t.Helper()
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt required")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.ll"), filepath.Join(dir, "optimized.ll")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	x86FloatCompareCaptureCommand(t, exec.Command(opt, "-S", "-passes=default<O2>", "-verify-each", input, "-o", output))
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestX86UndefinedTrapNamedRawThreeAPIsFiveTargetsRetainFaultObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump required")
	}
	physical := regexp.MustCompile(`(?m)\bud2\b`)
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		for _, raw := range []bool{false, true} {
			source := x86UndefinedTrapFixture(raw)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/raw=%t/%s", target.triple, raw, api), func(t *testing.T) {
					ir := x86UndefinedTrapIR(t, source, target.arch, target.triple, api)
					if strings.Count(ir, `asm sideeffect "ud2"`) != 1 || !strings.Contains(ir, "unreachable") {
						t.Fatal("consumer lost the exact non-returning architectural fault")
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							optimized := ir
							if level == "-O2" {
								optimized = x86UndefinedTrapOptimizedIR(t, ir)
							}
							dir := t.TempDir()
							input, object := filepath.Join(dir, "undefined.ll"), filepath.Join(dir, "undefined.o")
							if err := os.WriteFile(input, []byte(optimized), 0600); err != nil {
								t.Fatal(err)
							}
							x86FloatCompareCaptureCommand(t, exec.Command(llc, level,
								"-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
							decoded := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "-d", "--no-show-raw-insn", object))
							// LLVM 22's Darwin backend also traps the unreachable
							// terminator, after the explicit UD2. That unreachable
							// second UD2 does not change the observed exception.
							expected := 1
							if strings.Contains(target.triple, "darwin") {
								expected = 2
							}
							if len(physical.FindAll(decoded, -1)) != expected || strings.Contains(string(decoded), "int3") {
								t.Fatalf("actual object changed/discarded the undefined instruction:\n%s", decoded)
							}
						})
					}
				})
			}
		}
	}
}

const x86UndefinedTrapOriginalDriver = `package main

import (
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
        panic(err)
    }
    fault()
    os.Exit(91)
}
`

func x86UndefinedTrapBuildOriginal(t *testing.T, goos, arch string, raw bool) string {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module undefinedtrap\n\ngo 1.20\n", "main.go": x86UndefinedTrapOriginalDriver,
		"decl.go": "package main\nfunc fault()\n", "fault_" + arch + ".s": x86UndefinedTrapFixture(raw),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0",
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	return executable
}

func TestX86UndefinedTrap386OriginalNativeReferencesCompile(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			executable := x86UndefinedTrapBuildOriginal(t, "linux", "386", raw)
			sealed, err := x87IA32StaticExecutable(executable)
			if err != nil || sealed.verify() != nil {
				t.Fatalf("original IA32 undefined-instruction executable is not stable ELF32: %v", err)
			}
		})
	}
}

func TestX86UndefinedTrapTypedPropertiesDoNotMutateCanonicalMetadata(t *testing.T) {
	before := x86UndefinedTrapSpecs["UNDEF"]
	before.opBytes = append([]byte(nil), before.opBytes...)
	for _, op := range []Op{"UNDEF", "UD2"} {
		got, known, err := x86UndefinedTrapProperties(op, Instr{Op: op}, "amd64")
		if !known || err != nil || !reflect.DeepEqual(before, got) {
			t.Fatal("canonical and physical consumers disagree", op, got, err)
		}
	}
}
