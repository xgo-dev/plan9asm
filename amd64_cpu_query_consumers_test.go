package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86CPUQueryTypedGrammarAndDispatchBoundaries(t *testing.T) {
	if len(x86CPUQuerySpecs) != 2 {
		t.Fatal("complete official CPU-query family changed")
	}
	for _, op := range []Op{OpCPUID, OpXGETBV} {
		spec := x86CPUQuerySpecs[op]
		inputs, outputs, encoding := []Reg{AX, CX}, []Reg{AX, BX, CX, DX}, []byte{0xa2}
		if op == OpXGETBV {
			inputs, outputs, encoding = []Reg{CX}, []Reg{AX, DX}, []byte{0x01, 0xd0}
		}
		if spec.native != strings.ToLower(string(op)) || !reflect.DeepEqual(spec.inputs, inputs) ||
			!reflect.DeepEqual(spec.outputs, outputs) || !bytes.Equal(spec.opBytes, encoding) {
			t.Fatal("CPU-query typed syntax or implicit effect changed", op)
		}
		for _, arch := range []string{"386", "amd64", "", "arm", "arm64", "wasm"} {
			for _, suffix := range []string{"", ".Z", ".SAE", ".BCST"} {
				for _, identity := range []Op{"", op, Op(strings.ToLower(string(op))), "MOVQ", Op(string(op) + ".BAD")} {
					t.Run(arch+"/"+string(op)+suffix+"/identity="+string(identity), func(t *testing.T) {
						instruction := Instr{Op: identity, Raw: string(op) + suffix}
						before := fmt.Sprintf("%#v", instruction)
						ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
						ctx.goarch = arch
						ir, temporary := output.String(), ctx.tmp
						known, terminated, err := ctx.lowerX86CPUQuery(Op(string(op)+suffix), instruction)
						invalid := arch != "386" && arch != "amd64" || suffix != "" ||
							identity != "" && !strings.EqualFold(string(identity), string(op))
						if !known || terminated || (err != nil) != invalid ||
							invalid && (ir != output.String() || temporary != ctx.tmp) || before != fmt.Sprintf("%#v", instruction) {
							t.Fatal("CPU-query dispatch mutated input or emitted before rejection", err)
						}
					})
				}
			}
		}
	}
	if _, known, err := x86CPUQueryProperties("RDTSC", Instr{}, "amd64"); known || err != nil {
		t.Fatal("timestamps must not acquire the CPU-query grammar")
	}
}

func TestX86CPUQueryConstructedFileConsumersRetainParserGrammar(t *testing.T) {
	pkg := mustGoPackage(t, "cpuquery", "package cpuquery\nfunc query()\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{OpCPUID, OpXGETBV} {
			for _, operand := range []string{"AX", "(AX)", "$1", "AX,DX"} {
				t.Run(arch+"/"+string(op)+"/"+operand, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·query(SB),4,$0-0\n"+string(op)+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					file.Funcs[0].Instrs[1].Args, err = parseOperandsCSV(ArchAMD64, op, operand)
					if err != nil {
						t.Fatal(err)
					}
					before := fmt.Sprintf("%#v", file.Funcs[0])
					options := Options{Goarch: arch, ResolveSym: resolve, Sigs: signatures}
					if ir, err := Translate(file, options); err == nil || ir != "" {
						t.Fatal("constructed text consumer bypassed Go's zero-operand grammar", err)
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						defer module.Dispose()
						t.Fatal("constructed module consumer returned an invalid query module", err)
					}
					if err == nil || before != fmt.Sprintf("%#v", file.Funcs[0]) {
						t.Fatal("constructed module grammar changed its source or silently accepted it", err)
					}
				})
			}
		}
	}
}

func TestX86CPUQueryDescriptorCannotSupplyCallerOrStackPermission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, suffix := OpMOVQ, "Q"
		if arch == "386" {
			move, suffix = OpMOVL, "L"
		}
		for _, op := range []Op{OpCPUID, OpXGETBV} {
			instruction := Instr{Op: op, Raw: string(op)}
			if _, known, err := x86CPUQueryProperties(op, instruction, arch); !known || err != nil {
				t.Fatal("valid CPU-query grammar is not bound", op, err)
			}
			if x86SourceStackInstructionKnown(instruction, move, suffix, arch) {
				t.Fatal("implicit-register descriptor granted a native caller/stack contract", op)
			}
		}
	}
}

func x86CPUQueryIR(t *testing.T, source, arch, triple, api string) string {
	t.Helper()
	return x86CPUQueryIRFromDeclaration(t, source, "func query()\n", arch, triple, api)
}

func x86CPUQueryIRFromDeclaration(t *testing.T, source, declarations, arch, triple, api string) string {
	t.Helper()
	pkg := mustGoPackage(t, "cpuquery", "package cpuquery\n"+declarations)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: resolve})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
		}
		if err != nil || translated == nil || translated.Module.IsNil() {
			t.Fatalf("Go module CPU-query consumer: %v", err)
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
		t.Fatal("unknown CPU-query consumer", api)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil || module.IsNil() {
		t.Fatalf("LLVM module CPU-query consumer: %v", err)
	}
	return module.String()
}

func TestX86CPUQueryNamedRawThreeAPIsFiveTargetsProduceActualObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		for _, op := range []Op{OpCPUID, OpXGETBV} {
			for _, raw := range []bool{false, true} {
				body := string(op) + "\n"
				if raw {
					body = "BYTE $0x0f\n"
					encoding := []byte{0xa2}
					if op == OpXGETBV {
						encoding = []byte{0x01, 0xd0}
					}
					for _, value := range encoding {
						body += fmt.Sprintf("BYTE $%#x\n", value)
					}
				}
				source := "TEXT ·query(SB),4,$0-0\n" + body + "RET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				initialized := "TEXT ·query(SB),4,$0-0\nMOVL $0,AX\nMOVL $0,CX\n" + body + "RET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, initialized)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+string(op)+fmt.Sprint("/raw=", raw)+"/"+api, func(t *testing.T) {
						unbound, err := x86ScalarFPBitViewAPI(t, source, "func query()", target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || unbound != "" {
							t.Fatal("original uninitialized query acquired an entry-register contract", err)
						}
						ir := x86CPUQueryIR(t, initialized, target.arch, target.triple, api)
						for _, optimized := range []bool{false, true} {
							t.Run(fmt.Sprint("O2=", optimized), func(t *testing.T) {
								input := ir
								if optimized {
									input = x86UndefinedTrapOptimizedIR(t, input)
								}
								if strings.Count(input, "asm sideeffect \""+strings.ToLower(string(op))+"\"") != 1 {
									t.Fatal("whole CPU query was removed or duplicated")
								}
								dir := t.TempDir()
								ll, object := filepath.Join(dir, "query.ll"), filepath.Join(dir, "query.o")
								if err := os.WriteFile(ll, []byte(input), 0600); err != nil {
									t.Fatal(err)
								}
								x86FloatCompareCaptureCommand(t, exec.Command(llc, "-filetype=obj", "-mtriple="+target.triple, ll, "-o", object))
								actual := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "--disassemble", object))
								physical := regexp.MustCompile(`(?m)\b` + strings.ToLower(string(op)) + `\b`)
								if len(physical.FindAll(actual, -1)) != 1 {
									t.Fatalf("actual LLVM object lost native CPU-query identity:\n%s", actual)
								}
							})
						}
					})
				}
			}
		}
	}
}
