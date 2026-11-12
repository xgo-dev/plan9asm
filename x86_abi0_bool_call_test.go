package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const x86ABI0BoolCallDeclarations = "func caller(x bool) bool\nfunc callee(x bool) bool\n"

func x86ABI0BoolCallAssembly(caller, callee string) string {
	return "TEXT ·caller(SB),4,$16-5\n" + caller + "\nRET\nTEXT ·callee(SB),4,$0-5\n" + callee + "\nRET\n"
}

func x86ABI0BoolCallParsed(t *testing.T) (*File, Options) {
	t.Helper()
	file, err := Parse(ArchAMD64, x86ABI0BoolCallAssembly(x86ABI0BoolCallBody, x86ABI0BoolCallLeaf))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "boolcall", "package boolcall\n"+x86ABI0BoolCallDeclarations)
	resolve := func(s string) string { return strings.TrimPrefix(s, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
}

func TestX86ABI0Mode32CanonicalBoolCallOriginalIdentity(t *testing.T) {
	for name, change := range map[string]func(*File, *Options){
		"callee-original-literal": func(f *File, _ *Options) { f.Funcs[1].Instrs[2].Raw = "MOVB $3,ret+4(FP)" },
		"callee-frame-extent":     func(f *File, _ *Options) { f.Funcs[1].ArgSize = 1 },
		"missing-original-callee": func(f *File, _ *Options) { f.Funcs = f.Funcs[:1] },
		"resolved-collision":      func(_ *File, o *Options) { o.ResolveSym = func(string) string { return "caller" } },
		"callee-byte-input": func(_ *File, o *Options) {
			sig := o.Sigs["callee"]
			sig.Args = []LLVMType{I8}
			sig.Frame.Params[0].Type = I8
			o.Sigs["callee"] = sig
		},
		"callee-result-offset": func(_ *File, o *Options) {
			sig := o.Sigs["callee"]
			sig.Frame.Results[0].Offset = 3
			o.Sigs["callee"] = sig
		},
		"callee-custom-name":      func(_ *File, o *Options) { sig := o.Sigs["callee"]; sig.Name = "outside"; o.Sigs["callee"] = sig },
		"caller-short-frame":      func(f *File, _ *Options) { f.Funcs[0].FrameSize = 4 },
		"caller-original-literal": func(f *File, _ *Options) { f.Funcs[0].Instrs[2].Raw = "MOVB $2,0(SP)" },
		"target-64":               func(_ *File, o *Options) { o.TargetTriple = "x86_64-unknown-linux-gnu" },
	} {
		for _, api := range []string{"text", "module"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				file, opt := x86ABI0BoolCallParsed(t)
				change(file, &opt)
				if api == "text" {
					ir, err := Translate(file, opt)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("source/declaration mutation published text", len(ir), err)
					}
				} else {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := TranslateModuleInContext(ctx, file, opt)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if !module.IsNil() || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("source/declaration mutation published module", err)
					}
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolCallPlanStateAndCache(t *testing.T) {
	file, opt := x86ABI0BoolCallParsed(t)
	before := x86DirectTailSnapshot(file)
	source, err := prepareX86ABI0BoolCalls(file, opt)
	if err != nil || source == nil || !reflect.DeepEqual(before, file) {
		t.Fatal("plan did not retain unmodified complete source", err)
	}
	plan := source.callers["·caller"]
	fn := file.Funcs[0]
	if x86ABI0LogicalBoolFrameRole(fn, opt.Sigs["caller"], "386") {
		t.Fatal("standalone source acquired a CALL role without its plan")
	}
	fn.x86BoolCalls = plan
	if !x86ABI0LogicalBoolFrameRole(fn, opt.Sigs["caller"], "386") {
		t.Fatal("actual plan lost its logical source")
	}
	changed := fn
	changed.ArgSize++
	if x86ABI0LogicalBoolFrameRole(changed, opt.Sigs["caller"], "386") {
		t.Fatal("plan admitted a different original caller")
	}
	emitted := plan.signature
	emitted.Attrs = "#0"
	if !plan.bindLowering(file.Funcs[0], plan.signature, emitted, "386") || !plan.matches(fn, emitted, "386") {
		t.Fatal("exact declaration/feature-attribute projection was not retained")
	}
	bad := emitted
	bad.Args = []LLVMType{I8}
	if plan.bindLowering(file.Funcs[0], plan.signature, bad, "386") || plan.matches(fn, bad, "386") {
		t.Fatal("feature attrs projection changed actual argument transport")
	}
	bad = emitted
	bad.Name = "outside"
	if plan.bindLowering(file.Funcs[0], plan.signature, bad, "386") || plan.matches(fn, bad, "386") {
		t.Fatal("feature attrs projection changed source symbol")
	}
	bad = emitted
	bad.ArgRegs = []Reg{AX}
	if plan.bindLowering(file.Funcs[0], plan.signature, bad, "386") || plan.matches(fn, bad, "386") {
		t.Fatal("feature attrs projection changed ABI/native transport")
	}
	state := x86ResultState{boolCalls: plan, boolOutgoing: []bool{true, false, false, false, false}, boolOutgoingCanonical: []bool{true, false, false, false, false}}
	other := state.clone()
	other.boolOutgoingCanonical[0] = false
	if !state.boolOutgoingCanonical[0] || state.intersect(other).boolOutgoingCanonical[0] || !state.intersect(other).boolOutgoing[0] {
		t.Fatal("outgoing NUM/canonical domains conflated or shared mutable state")
	}
	// Repeating a call consumes the same independently cached readonly proof;
	// the source graph's byte/visit envelope is not enlarged or reset.
	bytes, visits := source.budget.bytes, source.budget.visits
	for i := 0; i < 2; i++ {
		if err := source.verify(); err != nil {
			t.Fatal(err)
		}
	}
	if bytes <= 0 || visits <= 0 || source.budget.bytes != bytes || source.budget.visits != visits {
		t.Fatal("cached leaf verification recreated its proof/budget")
	}
	second, err := Parse(ArchAMD64, x86ABI0BoolCallAssembly(strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "CALL ·callee(SB)\nCALL ·callee(SB)", 1), x86ABI0BoolCallLeaf))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := prepareX86ABI0BoolCalls(second, opt)
	if err != nil || repeated.budget.bytes != bytes || repeated.budget.visits != visits {
		t.Fatal("each call repeated the cached leaf proof", err)
	}
	state.gp[0], state.canonicalGP[0] = 255, 255
	state.xmm[0], state.vectorUpper[0], state.masks[0] = 65535, ^uint64(0), true
	state.flags = x86ByteFlagsAll
	state.pointerGP[0], state.callerAddressGP[0] = true, true
	state.boolFrameGP = new([16]x86ResultSlotAddress)
	state.boolFrameGP[0] = x86ResultSlotAddress{start: 0, end: 1, valid: true}
	var callOrdinal int
	for ordinal := range plan.calls {
		callOrdinal = ordinal
	}
	if accepted, known := x86ABI0BoolCallStep(callOrdinal, plan.function.Instrs[callOrdinal], &state, nil, 4, "386"); !accepted || !known {
		t.Fatal("actual canonical outgoing call did not execute its typed effect")
	}
	if state.gp[0] != 0 || state.canonicalGP[0] != 0 || state.xmm[0] != 0 || state.vectorUpper[0] != 0 || state.masks[0] || state.flags != 0 ||
		state.pointerGP[0] || state.callerAddressGP[0] || state.boolFrameGP[0].valid || !state.boolOutgoing[0] || !state.boolOutgoingCanonical[0] || !state.boolOutgoing[4] || !state.boolOutgoingCanonical[4] {
		t.Fatal("CALL preserved unknown machine effects or failed to write its actual declared result")
	}
}

const x86ABI0BoolCallBody = "MOVB x+0(FP),AX\nMOVB AX,0(SP)\nCALL ·callee(SB)\nMOVB 4(SP),AX\nMOVB AX,ret+4(FP)"
const x86ABI0BoolCallLeaf = "LEAL x+0(FP),AX\nMOVB (AX),BX\nMOVB BX,ret+4(FP)"

func TestX86ABI0Mode32CanonicalBoolSameFileCallThreeAPIs(t *testing.T) {
	for name, row := range map[string]struct {
		caller, callee string
		good           bool
	}{
		"readonly-leaf":                  {x86ABI0BoolCallBody, x86ABI0BoolCallLeaf, true},
		"constant-outgoing":              {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB $1,0(SP)", 1), x86ABI0BoolCallLeaf, true},
		"two-calls":                      {strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "CALL ·callee(SB)\nCALL ·callee(SB)", 1), x86ABI0BoolCallLeaf, true},
		"restore-raw-outgoing":           {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB $3,0(SP)\nMOVB 0(SP),AL\nTESTB AL,AL\nSETNE AL\nMOVB AL,0(SP)", 1), x86ABI0BoolCallLeaf, true},
		"callee-result-alias":            {x86ABI0BoolCallBody, "MOVB x+0(FP),BX\nLEAL ret+4(FP),AX\nMOVB BX,(AX)", true},
		"raw-outgoing-2":                 {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB $2,0(SP)", 1), x86ABI0BoolCallLeaf, false},
		"raw-outgoing-3":                 {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB $3,0(SP)", 1), x86ABI0BoolCallLeaf, false},
		"raw-outgoing-255":               {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB $255,0(SP)", 1), x86ABI0BoolCallLeaf, false},
		"undefined-outgoing":             {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)\n", "", 1), x86ABI0BoolCallLeaf, false},
		"padding":                        {strings.Replace(x86ABI0BoolCallBody, "0(SP)", "1(SP)", 1), x86ABI0BoolCallLeaf, false},
		"wider-outgoing":                 {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVL AX,0(SP)", 1), x86ABI0BoolCallLeaf, false},
		"unknown-callee":                 {strings.Replace(x86ABI0BoolCallBody, "·callee(SB)", "·outside(SB)", 1), x86ABI0BoolCallLeaf, false},
		"internal-callee":                {strings.Replace(x86ABI0BoolCallBody, "·callee(SB)", "·callee<ABIInternal>(SB)", 1), x86ABI0BoolCallLeaf, false},
		"callee-raw-return":              {x86ABI0BoolCallBody, "MOVB $2,ret+4(FP)", false},
		"callee-input-write":             {x86ABI0BoolCallBody, "MOVB $0,x+0(FP)\n" + x86ABI0BoolCallLeaf, false},
		"callee-alias-input-write":       {x86ABI0BoolCallBody, "LEAL x+0(FP),AX\nMOVB $1,(AX)\nMOVB $1,ret+4(FP)", false},
		"callee-recursive":               {x86ABI0BoolCallBody, "CALL ·callee(SB)\nMOVB $1,ret+4(FP)", false},
		"gp-clobber":                     {strings.Replace(x86ABI0BoolCallBody, "MOVB 4(SP),AX\n", "", 1), x86ABI0BoolCallLeaf, false},
		"flags-clobber":                  {strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "TESTB AX,AX\nCALL ·callee(SB)\nSETNE ret+4(FP)", 1), x86ABI0BoolCallLeaf, false},
		"mixed-outgoing":                 {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "TESTB AX,AX\nJE skip\nMOVB AX,0(SP)\nskip:", 1), x86ABI0BoolCallLeaf, false},
		"pointer-carrier-clobber":        {strings.Replace(x86ABI0BoolCallBody, "MOVB AX,0(SP)", "MOVB AX,0(SP)\nLEAL x+0(FP),DX", 1) + "\nMOVB (DX),BX", x86ABI0BoolCallLeaf, false},
		"result-overwrite-2":             {x86ABI0BoolCallBody + "\nMOVB $2,ret+4(FP)", x86ABI0BoolCallLeaf, false},
		"outgoing-load-overwrites-alias": {strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "LEAL x+0(FP),DX\nMOVB 0(SP),DL\nMOVB (DX),BX\nMOVB BX,0(SP)\nCALL ·callee(SB)", 1), x86ABI0BoolCallLeaf, false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, x86ABI0BoolCallAssembly(row.caller, row.callee), x86ABI0BoolCallDeclarations, "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("complete same-file canonical call contract", row.good, len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolCallFinalCallbacks(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, kind := range []string{"control", "source", "signature", "resolution"} {
			if api == "Go" && kind == "signature" {
				continue
			} // Go derives this private map from the actual declaration.
			t.Run(api+"/"+kind, func(t *testing.T) {
				run := func(trigger int, mutation string) (int, bool, error) {
					file, opt := x86ABI0BoolCallParsed(t)
					input := []byte(x86ABI0BoolCallAssembly(x86ABI0BoolCallBody, x86ABI0BoolCallLeaf))
					count := 0
					opt.ResolveSym = func(symbol string) string {
						count++
						name := strings.TrimPrefix(symbol, "·")
						if count == trigger {
							switch mutation {
							case "source":
								if api == "Go" {
									input[0] = 'X'
								} else {
									file.Funcs[1].Instrs[2].Raw += " // changed"
								}
							case "signature":
								sig := opt.Sigs["callee"]
								sig.Args = []LLVMType{I8}
								opt.Sigs["callee"] = sig
							case "resolution":
								return "outside"
							}
						}
						return name
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					if api == "text" {
						ir, err := Translate(file, opt)
						return count, ir != "", err
					}
					if api == "module" {
						m, err := TranslateModuleInContext(ctx, file, opt)
						if !m.IsNil() {
							defer m.Dispose()
						}
						return count, !m.IsNil(), err
					}
					pkg := mustGoPackage(t, "boolcall", "package boolcall\n"+x86ABI0BoolCallDeclarations)
					m, err := translateGoModuleInContext(ctx, pkg, input, GoModuleOptions{GOARCH: "386", TargetTriple: opt.TargetTriple, ResolveSym: opt.ResolveSym})
					if m != nil && !m.Module.IsNil() {
						defer m.Module.Dispose()
					}
					return count, m != nil, err
				}
				last, published, err := run(0, "")
				if err != nil || !published || last == 0 {
					t.Fatal("complete API baseline did not reach final source guard", last, published, err)
				}
				reached, published, err := run(last, kind)
				if reached != last || kind == "control" && (err != nil || !published) || kind != "control" && (!errors.Is(err, ErrProbeNeedsContext) || published) {
					t.Fatal("last user callback escaped original source/declaration guard", last, reached, published, err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolCallKeepsWholeSource(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			leaf := x86ABI0BoolCallLeaf
			if bad {
				leaf = "MOVB $3,ret+4(FP)"
			}
			pkg := mustGoPackage(t, "boolcall", "package boolcall\n"+x86ABI0BoolCallDeclarations)
			out, err := TranslateGoModule(pkg, []byte(x86ABI0BoolCallAssembly(x86ABI0BoolCallBody, leaf)), GoModuleOptions{
				GOARCH: "386", TargetTriple: "i386-unknown-linux-gnu",
				KeepFunc: func(original, _ string) bool { return original == "·caller" },
			})
			if out != nil {
				defer out.Module.Dispose()
			}
			if !bad && (err != nil || out == nil) || bad && (!errors.Is(err, ErrProbeNeedsContext) || out != nil) {
				t.Fatal("filter hid or removed complete callee contract", bad, err)
			}
		})
	}
}

func TestX86ABI0Mode32CanonicalBoolCallExistingFloatPredicate(t *testing.T) {
	body := "MOVSS x+0(FP),X0\nXORPS X1,X1\nCOMISS X1,X0\nSETNE AL\nMOVB AL,0(SP)\nCALL ·callee(SB)\nMOVB 4(SP),AX\nMOVB AX,ret+4(FP)"
	declarations := "func caller(x float32) bool\nfunc callee(x bool) bool\n"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86ABI0BoolCallAssembly(body, x86ABI0BoolCallLeaf), declarations, "386", "i386-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("existing typed scalar predicate lost its independently emitted feature attributes", len(ir), err)
			}
		})
	}
}
