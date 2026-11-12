package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

const x86DirectTailTestGo = `package p
func First(a uint64) uint64
func Second(a, b uint32) uint64
`

const x86DirectTailTestASM = `TEXT ·First(SB),NOSPLIT,$0-16
 MOVQ a+0(FP),SI
 MOVQ $7,DI
 JMP shared<>(SB)
TEXT ·Second(SB),NOSPLIT,$0-16
 MOVL a+0(FP),SI
 MOVL b+4(FP),DI
 JMP shared<>(SB)
TEXT shared<>(SB),NOSPLIT,$0-0
 MOVQ SI,AX
 ADDQ DI,AX
 MOVQ AX,ret+8(FP)
 RET
`

func x86DirectTailTestInputs(t *testing.T) (*File, Options) {
	t.Helper()
	file, err := Parse(ArchAMD64, x86DirectTailTestASM)
	if err != nil {
		t.Fatal(err)
	}
	resolve := testResolveSym("example.com/tails")
	sigs, err := goSigsForAsmFile(mustGoPackage(t, "example.com/tails", x86DirectTailTestGo), file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
}

func TestX86DirectTailCanonicalBoolAndIndependentRootFrames(t *testing.T) {
	for _, test := range []struct {
		name, declarations, source string
		wantContext                bool
	}{
		{"canonical_bool", "func First(a uint64) bool", `TEXT ·First<ABIInternal>(SB),NOSPLIT,$0-9
 MOVQ AX,SI
 CMPQ SI,$0
 JMP pred<>(SB)
TEXT pred<>(SB),NOSPLIT,$0-0
 SETEQ AL
 MOVBLZX AL,AX
 RET
`, false},
		{"noncanonical_bool", "func First(a uint64) bool", `TEXT ·First<ABIInternal>(SB),NOSPLIT,$0-9
 JMP pred<>(SB)
TEXT pred<>(SB),NOSPLIT,$0-0
 MOVL $2,AX
 RET
`, true},
		{"unknown_bool_FLAGS", "func First(a uint64) bool", `TEXT ·First<ABIInternal>(SB),NOSPLIT,$0-9
 JMP pred<>(SB)
TEXT pred<>(SB),NOSPLIT,$0-0
 SETEQ AL
 RET
`, true},
		{"unknown_join", "func First(a uint64) uint64", `TEXT ·First<ABIInternal>(SB),NOSPLIT,$0-16
 CMPQ AX,$0
 JE shared
 MOVQ AX,SI
shared:
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
 MOVQ SI,AX
 RET
`, true},
		{"root_result_offsets_differ", "func First(a uint64) uint64\nfunc Second(a,b uint64) uint64", x86DirectTailTestASM, true},
		{"root_result_padding", "func First(a uint64) uint64\nfunc Second(a,b uint32) uint32", x86DirectTailTestASM, true},
		{"pointer_not_NUM", "func First(a *uint64) uint64\nfunc Second(a,b uint32) uint64", x86DirectTailTestASM, true},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(test.name+"/"+triple+"/"+api, func(t *testing.T) {
					pkg := mustGoPackage(t, "example.com/tails", "package p\n"+test.declarations)
					resolve := testResolveSym(pkg.Path)
					file, err := Parse(ArchAMD64, test.source)
					if err != nil {
						t.Fatal(err)
					}
					var module llvm.Module
					if api == "Go" {
						tr, goErr := TranslateGoModule(pkg, []byte(test.source), GoModuleOptions{
							GOARCH: "amd64", TargetTriple: triple, ResolveSym: resolve,
						})
						err = goErr
						if tr != nil {
							module = tr.Module
						}
					} else {
						sigs, sigErr := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
						if sigErr != nil {
							t.Fatal(sigErr)
						}
						opt := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
						if api == "text" {
							_, err = Translate(file, opt)
						} else {
							module, err = TranslateModule(file, opt)
						}
					}
					if !module.IsNil() {
						module.Dispose()
					}
					if test.wantContext {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("unclosed root state/result acquired continuation: %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86DirectTailPreparedSourceRejectsMutations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*File, *File, *Options)
	}{
		{"selected_DATA", func(_, prepared *File, _ *Options) { prepared.Data = []DataStmt{{Sym: "extra<>"}} }},
		{"selected_GLOBL", func(_, prepared *File, _ *Options) { prepared.Globl = []GloblStmt{{Sym: "extra<>"}} }},
		{"selected_prelude", func(_, prepared *File, _ *Options) { prepared.UnlinkedPrelude = []string{"NOP"} }},
		{"selected_arch", func(_, prepared *File, _ *Options) { prepared.Arch = ArchARM64 }},
		{"selected_duplicate", func(_, prepared *File, _ *Options) { prepared.Funcs = append(prepared.Funcs, prepared.Funcs[0]) }},
		{"original_Raw", func(original, _ *File, _ *Options) { original.Funcs[2].Instrs[1].Raw += " // changed" }},
		{"selected_Raw", func(_, prepared *File, _ *Options) { prepared.Funcs[2].Instrs[1].Raw += " // changed" }},
		{"resolver", func(_, _ *File, opt *Options) { opt.ResolveSym = func(s string) string { return "changed." + s } }},
		{"target_mode", func(_, _ *File, opt *Options) { opt.Goarch = "386" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, opt := x86DirectTailTestInputs(t)
			prepared, err := PrepareX86DirectTailSource(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(file, prepared, &opt)
			if _, err := PrepareX86DirectTailSource(prepared, opt); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed complete source/mapping retained graph: %v", err)
			}
		})
	}
}

func TestX86DirectTailGoModuleAuditsBeforeKeepFunc(t *testing.T) {
	for _, test := range []struct {
		name, source string
		wantContext  bool
	}{
		{"complete", x86DirectTailTestASM, false},
		{"dropped_root_unknown", strings.Replace(x86DirectTailTestASM, "MOVL b+4(FP),DI", "MOVQ R15,DI", 1), true},
		{"dead_helper_escape", x86DirectTailTestASM + "TEXT unused<>(SB),NOSPLIT,$0-0\n RET\n", true},
		{"dead_helper_CALL", x86DirectTailTestASM + "TEXT unused<>(SB),NOSPLIT,$0-0\n CALL foreign(SB)\n RET\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := mustGoPackage(t, "example.com/tails", x86DirectTailTestGo)
			tr, err := TranslateGoModule(pkg, []byte(test.source), GoModuleOptions{
				GOARCH: "amd64", GOOS: "linux", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: testResolveSym(pkg.Path), KeepFunc: func(source, _ string) bool { return source == "·First" },
			})
			if tr != nil {
				defer tr.Module.Dispose()
			}
			if test.wantContext {
				if err == nil || tr != nil {
					t.Fatalf("KeepFunc hid invalid complete source: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(tr.Functions) != 1 || tr.Functions[0].TextSymbol != "·First" ||
				strings.Contains(tr.Module.String(), "shared<>") || strings.Contains(tr.Module.String(), "call i64") {
				t.Fatalf("private source continuation became a callable/metadata entry: %v", tr.Functions)
			}
		})
	}
}

func TestX86DirectTailPrepareIsRequestLocal(t *testing.T) {
	file, opt := x86DirectTailTestInputs(t)
	before := x86DirectTailSnapshot(file)
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			prepared, err := PrepareX86DirectTailSource(file, opt)
			if err != nil {
				t.Error(err)
				return
			}
			if prepared == file || file.x86DirectTails != nil || prepared.x86DirectTails == nil {
				t.Error("graph was not attached exclusively to its request-local copy")
			}
		}()
	}
	wait.Wait()
	if !reflect.DeepEqual(file, before) {
		t.Fatal("concurrent prepares changed original source")
	}
}

func TestX86DirectTailOwnedContextsShareOriginalFile(t *testing.T) {
	file, opt := x86DirectTailTestInputs(t)
	before := x86DirectTailSnapshot(file)
	var wait sync.WaitGroup
	for i := 0; i < 4; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Error(err)
				return
			}
			defer module.Dispose()
			if strings.Contains(module.String(), "call i64") {
				t.Error("owned context lost its request-local continuation state")
			}
		}()
	}
	wait.Wait()
	if !reflect.DeepEqual(file, before) {
		t.Fatal("owned contexts mutated their common original File")
	}
	// Global-context public APIs retain their existing LLVM ownership boundary;
	// both independently consume exactly the same unchanged Parse result.
	if _, err := Translate(file, opt); err != nil {
		t.Fatal(err)
	}
	module, err := TranslateModule(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	module.Dispose()
}

func TestX86DirectTailPublicationRechecksOriginalSource(t *testing.T) {
	for _, api := range []string{"text", "module", "context"} {
		t.Run(api, func(t *testing.T) {
			file, opt := x86DirectTailTestInputs(t)
			file.Globl = []GloblStmt{{Sym: "marker<>", Flags: "RODATA", Size: 8}}
			file.Data = []DataStmt{{Sym: "marker<>", Width: 8, Value: 7}}
			baseResolve, armed, changed := opt.ResolveSym, false, false
			opt.ResolveSym = func(symbol string) string {
				if armed && symbol == "·marker<>" && !changed {
					changed = true
					file.Funcs[2].Instrs[1].Raw += " // source changed after prepare"
				}
				return baseResolve(symbol)
			}
			prepared, err := PrepareX86DirectTailSource(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			armed = true
			if api == "text" {
				ir, err := Translate(prepared, opt)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !changed {
					t.Fatalf("changed source published text: changed=%t error=%v", changed, err)
				}
				return
			}
			var module llvm.Module
			if api == "module" {
				module, err = TranslateModule(prepared, opt)
			} else {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err = TranslateModuleInContext(ctx, prepared, opt)
			}
			if !module.IsNil() {
				module.Dispose()
			}
			if !module.IsNil() || !errors.Is(err, ErrProbeNeedsContext) || !changed {
				t.Fatalf("changed source published module: changed=%t error=%v", changed, err)
			}
		})
	}
}

func TestX86DirectTailFailedIdentityCannotRevivePreparedGraph(t *testing.T) {
	file, opt := x86DirectTailTestInputs(t)
	prepared, err := PrepareX86DirectTailSource(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	raw := file.Funcs[2].Instrs[1].Raw
	file.Funcs[2].Instrs[1].Raw += " // changed"
	if _, err := PrepareX86DirectTailSource(prepared, opt); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed source retained a graph", err)
	}
	file.Funcs[2].Instrs[1].Raw = raw
	if _, err := PrepareX86DirectTailSource(prepared, opt); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restoring public source revived the rejected graph", err)
	}
}

const x86DirectTail386Go = `func First(a uint32) uint32
func Second(a,b uint16) uint32
`

const x86DirectTail386ASM = `TEXT ·First(SB),4,$0-8
 MOVL a+0(FP),SI
 MOVL $7,DI
 JMP sibling<>(SB)
TEXT ·Second(SB),4,$0-8
 MOVWLZX a+0(FP),SI
 MOVWLZX b+2(FP),DI
 JMP sibling<>(SB)
TEXT sibling<>(SB),4,$0-0
 MOVL SI,AX
 ADDL DI,AX
 MOVL AX,ret+4(FP)
 RET
`

func TestX86DirectTail386WholeSourceKeepsItsOwnTypedFrame(t *testing.T) {
	goAssemblerOracleOutput(t, "386", x86DirectTail386ASM, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86DirectTail386ASM, x86DirectTail386Go, "386", "i386-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "sibling") {
				t.Fatalf("386 First(a)=a+7 and Second(a,b)=u32(a)+u32(b) retained a separate helper instead of its root state:\n%s", ir)
			}
		})
	}
}

func TestX86DirectTailUnrelatedFunctionsRetainTheirOwnConsumers(t *testing.T) {
	for _, row := range []struct{ name, declaration, source string }{
		{"framed", "func Independent(a uint64) uint64", `TEXT ·Independent(SB),4,$8-16
 MOVQ a+0(FP),AX
 MOVQ AX,ret+8(FP)
 RET
`},
		{"CALL", "func Independent() uint64\nfunc Foreign() uint64", `TEXT ·Independent(SB),4,$0-8
 CALL ·Foreign(SB)
 MOVQ AX,ret+0(FP)
 RET
`},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				declaration := strings.TrimPrefix(x86DirectTailTestGo, "package p\n") + row.declaration
				// Establish the unrelated function's genuine old consumer before
				// placing it next to the complete shared-helper source.
				if _, err := x86ScalarFPBitViewAPI(t, row.source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Fatal("unrelated control is not independently supported", err)
				}
				if _, err := x86ScalarFPBitViewAPI(t, x86DirectTailTestASM+row.source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Fatal("tail graph stole an unrelated function's existing consumer", err)
				}
			})
		}
	}
}

func TestX86DirectTailKeepFuncCannotHideUnsupportedUnrelatedFunction(t *testing.T) {
	declarations := x86DirectTailTestGo + "func Unsupported(a uint64) bool\n"
	source := x86DirectTailTestASM + "TEXT ·Unsupported<ABIInternal>(SB),4,$0-9\n MOVL $2,AX\n RET\n"
	pkg := mustGoPackage(t, "example.com/tails", declarations)
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			opt := GoModuleOptions{GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)}
			if keep {
				opt.KeepFunc = func(symbol, _ string) bool { return symbol == "·First" }
			}
			tr, err := TranslateGoModule(pkg, []byte(source), opt)
			if tr != nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) || tr != nil {
				t.Fatalf("unsupported unrelated source silently disappeared: %v", err)
			}
		})
	}
}
