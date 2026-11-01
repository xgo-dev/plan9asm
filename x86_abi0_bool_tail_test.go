package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const x86ABI0BoolTailAssembly = "TEXT ·wrapper(SB),4,$0\nJMP ·leaf(SB)\nTEXT ·leaf(SB),4,$0-5\nMOVB x+0(FP),AX\nMOVB AX,ret+4(FP)\nRET\n"
const x86ABI0BoolTailDeclarations = "func wrapper(x bool) bool\nfunc leaf(x bool) bool\n"

func TestX86ABI0Mode32CanonicalBoolTypedTailThreeAPIs(t *testing.T) {
	for name, row := range map[string]struct {
		source, declarations string
		good                 bool
	}{
		"actual-samefile":    {x86ABI0BoolTailAssembly, x86ABI0BoolTailDeclarations, true},
		"declared-Go-target": {strings.Replace(x86ABI0BoolTailAssembly, "TEXT ·leaf(SB),4,$0-5\nMOVB x+0(FP),AX\nMOVB AX,ret+4(FP)\nRET\n", "", 1), x86ABI0BoolTailDeclarations, true},
		"raw-callee-2":       {strings.Replace(x86ABI0BoolTailAssembly, "MOVB AX,ret+4(FP)", "MOVB $2,ret+4(FP)", 1), x86ABI0BoolTailDeclarations, false},
		"caller-prior-write": {strings.Replace(x86ABI0BoolTailAssembly, "JMP ·leaf(SB)", "MOVB $1,ret+4(FP)\nJMP ·leaf(SB)", 1), x86ABI0BoolTailDeclarations, false},
		"callee-result-I8":   {strings.Replace(x86ABI0BoolTailAssembly, "MOVB AX,ret+4(FP)", "MOVB $3,ret+4(FP)", 1), strings.Replace(x86ABI0BoolTailDeclarations, "func leaf(x bool) bool", "func leaf(x bool) uint8", 1), false},
		"callee-input-I8":    {x86ABI0BoolTailAssembly, strings.Replace(x86ABI0BoolTailDeclarations, "func leaf(x bool)", "func leaf(x uint8)", 1), false},
		"offset-target":      {strings.Replace(x86ABI0BoolTailAssembly, "JMP ·leaf(SB)", "JMP ·leaf+1(SB)", 1), x86ABI0BoolTailDeclarations, false},
		"native-target":      {strings.Replace(x86ABI0BoolTailAssembly, "JMP ·leaf(SB)", "JMP ·leaf<ABIInternal>(SB)", 1), x86ABI0BoolTailDeclarations, false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declarations, "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("typed bool terminal did not retain its independent transport/canonical contract", row.good, len(ir), err)
				}
			})
		}
	}
}

func x86ABI0BoolTailParsed(t *testing.T) (*File, Options) {
	t.Helper()
	file, err := Parse(ArchAMD64, x86ABI0BoolTailAssembly)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "tailbool", "package tailbool\n"+x86ABI0BoolTailDeclarations)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
}

func TestX86ABI0Mode32CanonicalBoolTypedTailSourceReplayAndLayouts(t *testing.T) {
	for name, change := range map[string]func(*File, *Options){
		"caller-literal":  func(file *File, _ *Options) { file.Funcs[0].Instrs[1].Raw += " // changed" },
		"callee-literal":  func(file *File, _ *Options) { file.Funcs[1].Instrs[1].Raw += " // changed" },
		"caller-identity": func(file *File, _ *Options) { file.Funcs[0].Sym = "·other" },
		"callee-identity": func(file *File, _ *Options) { file.Funcs[1].Sym = "·other" },
		"callee-input-offset": func(_ *File, options *Options) {
			sig := options.Sigs["leaf"]
			sig.Frame.Params[0].Offset = 1
			options.Sigs["leaf"] = sig
		},
		"callee-result-offset": func(_ *File, options *Options) {
			sig := options.Sigs["leaf"]
			sig.Frame.Results[0].Offset = 5
			options.Sigs["leaf"] = sig
		},
		"callee-register-role": func(_ *File, options *Options) {
			sig := options.Sigs["leaf"]
			sig.ArgRegs = []Reg{AX}
			options.Sigs["leaf"] = sig
		},
		"copied-caller-signature": func(_ *File, options *Options) {
			sig := options.Sigs["leaf"]
			sig.x86BorrowedBoolTail = true
			options.Sigs["leaf"] = sig
		},
	} {
		for _, api := range []string{"text", "module"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				file, options := x86ABI0BoolTailParsed(t)
				source, err := prepareX86ABI0BoolCalls(file, options)
				if err != nil || source == nil || source.callers["·wrapper"].tail == nil {
					t.Fatal("actual canonical terminal source baseline", err)
				}
				options.x86BoolCallSource = source
				change(file, &options)
				published := false
				if api == "text" {
					ir, failure := Translate(file, options)
					published, err = ir != "", failure
				} else {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, failure := TranslateModuleInContext(ctx, file, options)
					published, err = !module.IsNil(), failure
					if !module.IsNil() {
						defer module.Dispose()
					}
				}
				if published || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed terminal source/type tuple published", published, err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolTypedTailCannotBorrowGoCaller(t *testing.T) {
	x86ABI0BoolTailCannotBorrowGoCaller(t, "386", "i386-unknown-linux-gnu")
}

func TestX86AMD64CanonicalBoolTypedTailCannotBorrowGoCaller(t *testing.T) {
	x86ABI0BoolTailCannotBorrowGoCaller(t, "amd64", "x86_64-unknown-linux-gnu")
}

func x86ABI0BoolTailCannotBorrowGoCaller(t *testing.T, arch, triple string) {
	t.Helper()
	source := []byte("TEXT ·wrapper(SB),4,$0\nJMP outside·target(SB)\n")
	pkg := mustGoPackage(t, "tailbool", "package tailbool\nfunc wrapper(x bool) bool\n")
	file, err := Parse(ArchAMD64, string(source))
	if err != nil {
		t.Fatal(err)
	}
	resolve := testResolveSym("tailbool")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil || !sigs["outside.target"].x86BorrowedBoolTail {
		t.Fatal("real unresolved Go target did not retain copied-caller denial", err)
	}
	cloned, err := numericalCloneSignatures(sigs)
	if err != nil || !cloned["outside.target"].x86BorrowedBoolTail {
		t.Fatal("public metadata copying erased the denial provenance", err)
	}
	// The positive declaration is independently derived from the target's
	// actual Go type, not copied from the caller or reconstructed as a token.
	calleePackage := mustGoPackage(t, "outside", "package outside\nfunc target(y bool) bool\n")
	word := x86ResultPointerWord(arch)
	calleeFile, err := Parse(ArchAMD64, fmt.Sprintf("TEXT ·target(SB),4,$0-%d\nMOVB y+0(FP),AX\nMOVB AX,ret+%d(FP)\nRET\n", word+1, word))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := goSigsForAsmFile(calleePackage, calleeFile, testResolveSym("outside"), arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []bool{false, true} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("actual-declaration=%t/%s", supplied, api), func(t *testing.T) {
				options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
				if supplied {
					options.Sigs = map[string]FuncSig{"tailbool.wrapper": sigs["tailbool.wrapper"], "outside.target": actual["outside.target"]}
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				published := false
				var err error
				if api == "text" {
					ir, failure := Translate(file, options)
					published, err = ir != "", failure
				} else if api == "module" {
					module, failure := TranslateModuleInContext(ctx, file, options)
					published, err = !module.IsNil(), failure
					if !module.IsNil() {
						defer module.Dispose()
					}
				} else {
					request := GoModuleOptions{GOARCH: arch, TargetTriple: options.TargetTriple, ResolveSym: resolve}
					if supplied {
						request.ManualSig = func(name string) (FuncSig, bool) { sig, found := actual[name]; return sig, found }
					}
					module, failure := translateGoModuleInContext(ctx, pkg, source, request)
					published, err = module != nil, failure
					if module != nil && !module.Module.IsNil() {
						defer module.Module.Dispose()
					}
				}
				if supplied && (!published || err != nil) || !supplied && (published || !errors.Is(err, ErrProbeNeedsContext)) {
					t.Fatal("caller-copy substituted for independent actual target declaration", supplied, published, err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolTypedTailCacheAndKeepSource(t *testing.T) {
	file, options := x86ABI0BoolTailParsed(t)
	source, err := prepareX86ABI0BoolCalls(file, options)
	if err != nil || source == nil || !source.tailProofs["·leaf"] {
		t.Fatal("complete source did not close its actual canonical leaf", err)
	}
	bytes, visits := source.budget.bytes, source.budget.visits
	if bytes == 0 || visits == 0 || len(source.callers["·wrapper"].bytes) != 0 {
		t.Fatal("terminal recreated outgoing backing or omitted the independent leaf proof")
	}
	for count := 0; count < 3; count++ {
		if err := source.verify(); err != nil || source.budget.bytes != bytes || source.budget.visits != visits {
			t.Fatal("readback repeated its cached byte/visit proof", err)
		}
	}
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], options.Sigs["wrapper"], "386"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("declaration-only observer borrowed a logical terminal capability", err)
	}
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprintf("KeepFunc/callee-raw=%t", bad), func(t *testing.T) {
			input := x86ABI0BoolTailAssembly
			if bad {
				input = strings.Replace(input, "MOVB AX,ret+4(FP)", "MOVB $3,ret+4(FP)", 1)
			}
			pkg := mustGoPackage(t, "tailbool", "package tailbool\n"+x86ABI0BoolTailDeclarations)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := translateGoModuleInContext(ctx, pkg, []byte(input), GoModuleOptions{GOARCH: "386", TargetTriple: options.TargetTriple,
				ResolveSym: options.ResolveSym, KeepFunc: func(original, _ string) bool { return original == "·wrapper" }})
			if module != nil && !module.Module.IsNil() {
				defer module.Module.Dispose()
			}
			if !bad && (module == nil || err != nil) || bad && (module != nil || !errors.Is(err, ErrProbeNeedsContext)) {
				t.Fatal("filter dropped the complete original canonical callee proof", bad, module != nil, err)
			}
		})
	}
}

func TestX86ABI0Mode32CanonicalBoolTypedTailFinalCallbacks(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, kind := range []string{"control", "source", "signature", "resolution"} {
			if api == "Go" && kind == "signature" {
				continue // Go derives the private map from the actual declaration.
			}
			t.Run(api+"/"+kind, func(t *testing.T) {
				run := func(trigger int, mutation string) (int, bool, error) {
					file, options := x86ABI0BoolTailParsed(t)
					input := []byte(x86ABI0BoolTailAssembly)
					calls := 0
					options.ResolveSym = func(symbol string) string {
						calls++
						if calls == trigger {
							switch mutation {
							case "source":
								if api == "Go" {
									input[0] = 'X'
								} else {
									file.Funcs[1].Instrs[1].Raw += " // changed"
								}
							case "signature":
								sig := options.Sigs["leaf"]
								sig.Frame.Results[0].Offset++
								options.Sigs["leaf"] = sig
							case "resolution":
								return "other"
							}
						}
						return strings.TrimPrefix(symbol, "·")
					}
					if api == "text" {
						ir, err := Translate(file, options)
						return calls, ir != "", err
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					if api == "module" {
						module, err := TranslateModuleInContext(ctx, file, options)
						if !module.IsNil() {
							defer module.Dispose()
						}
						return calls, !module.IsNil(), err
					}
					pkg := mustGoPackage(t, "tailbool", "package tailbool\n"+x86ABI0BoolTailDeclarations)
					module, err := translateGoModuleInContext(ctx, pkg, input, GoModuleOptions{GOARCH: "386", TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym})
					if module != nil && !module.Module.IsNil() {
						defer module.Module.Dispose()
					}
					return calls, module != nil, err
				}
				last, published, err := run(0, "")
				if last == 0 || !published || err != nil {
					t.Fatal("whole API baseline missed its final source callback", last, published, err)
				}
				reached, published, err := run(last, kind)
				if reached != last || kind == "control" && (!published || err != nil) || kind != "control" && (published || !errors.Is(err, ErrProbeNeedsContext)) {
					t.Fatal("last terminal callback changed source/declaration and published", last, reached, published, err)
				}
			})
		}
	}
}
