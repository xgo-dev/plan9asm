package plan9asm

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Deliberately synthetic private comparison state. Public consumers below
// reject it: it has no live tool/source guard, archive or compiler producer.
func amd64ArgumentBoundModel(t *testing.T, parameters, body string, result ...types.Type) (Func, FuncSig, *amd64GoArgumentBinding) {
	t.Helper()
	input := amd64ArgumentEntryModel(t, parameters)
	if len(result) == 1 {
		pkg := types.NewPackage(input.Package.Path(), input.Package.Name())
		sig := types.NewSignatureType(nil, nil, nil, input.Declaration.Type().(*types.Signature).Params(),
			types.NewTuple(types.NewVar(token.NoPos, nil, "", result[0])), false)
		input.Package = pkg
		input.Declaration = types.NewFunc(token.NoPos, pkg, "Entry", sig)
		pkg.Scope().Insert(input.Declaration)
		var err error
		input.Signature, err = DeriveGoFuncABI0Signature(input.Native, input.Declaration, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
	}
	plan, err := amd64GoArgumentEntryPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, "TEXT ·Entry<ABIInternal>(SB),4,$0-128\n"+body+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	source := &GoX86NumericalReadSource{ready: true}
	source.identity = source
	owner := &GoX86NumericalReadBinding{source: source, originalSource: source, originalTypes: input.Package,
		options: Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: make(map[string]FuncSig)}}
	owner.originalBinding = owner
	entry := &amd64GoArgumentBinding{owner: owner, declaration: input.Declaration, symbol: file.Funcs[0].Sym, signature: input.Signature, plan: plan}
	entry.identity = entry
	entry.seal, err = entry.digest()
	if err != nil {
		t.Fatal(err)
	}
	sig := input.Signature
	sig.amd64GoArguments = entry
	owner.options.Sigs[sig.Name] = sig
	owner.capabilities = numericalCapabilities(owner.options.Sigs)
	return file.Funcs[0], sig, entry
}

func TestAMD64GoArgumentEntryDeclaredBytesAndConsumerRevocation(t *testing.T) {
	input := amd64ArgumentEntryModel(t, "a byte, b bool, p *byte, f float32, d float64")
	plan, err := amd64GoArgumentEntryPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	state, valid := amd64GoArgumentInitialState(plan)
	if !valid || state.gp[0] != 1 || state.gp[3] != 1 || state.canonicalGP[3] != 1 ||
		!state.pointerGP[1] || !state.callerAddressGP[1] || state.gp[1] != 0 ||
		state.xmm[0] != 0xf || state.xmm[1] != 0xff || state.gp[2] != 0 || state.pointerGP[2] ||
		len(state.fp) != 0 || len(state.auto) != 0 || state.flags != 0 {
		t.Fatalf("entry gained upper bytes, native backing, DX, FLAGS or stack facts: %#v", state)
	}
	for _, test := range []struct {
		name, parameters, body string
		accept                 bool
	}{
		{"slice-length", "a []byte", "MOVQ BX,AX", true},
		{"string-length", "a string", "MOVQ BX,AX", true},
		{"float64-bits", "a float64", "MOVQ X0,AX", true},
		{"integer32-overwrite", "a uint32", "MOVL AX,AX", true},
		{"bool-byte", "a bool", "MOVBQZX AL,AX", true},
		{"unknown-byte-upper", "a byte", "MOVQ AX,AX", false},
		{"unknown-float-upper", "a float32", "MOVQ X0,AX", false},
		{"pointer-not-numeric", "a *byte", "MOVQ AX,AX", false},
		{"unknown-DX-closure", "a []byte", "MOVQ 8(DX),AX", false},
		{"unknown-stack", "a []byte", "MOVQ (SP),AX", false},
		{"no-ABI0-parameter-home", "a []byte", "MOVQ a+0(FP),AX", false},
		{"unknown-FLAGS", "a bool", "SETEQ AL\nMOVBQZX AL,AX", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fn, sig, _ := amd64ArgumentBoundModel(t, test.parameters, test.body)
			err := checkAMD64RegisterResultInitialization(fn, sig,
				func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
					return x86ScalarFPResultTransfer(ins, state, owned, offset, arch)
				})
			if test.accept && err != nil || !test.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("declared-byte-only result proof: %v", err)
			}
		})
	}
	for _, name := range []string{"closed", "revoked-restored", "copied-token", "signature", "original-type", "carrier", "capability", "frame"} {
		t.Run(name, func(t *testing.T) {
			fn, sig, entry := amd64ArgumentBoundModel(t, "a string", "MOVQ BX,AX")
			if !entry.valid(fn, sig, "amd64") {
				t.Fatal("complete private comparison model was not usable")
			}
			switch name {
			case "closed":
				entry.owner.source.ready = false
			case "revoked-restored":
				entry.owner.source.revoked.Store(true)
				entry.owner.source.ready = true
			case "copied-token":
				copied := *entry
				entry = &copied
			case "signature":
				sig.Args = []LLVMType{I64}
			case "original-type":
				entry.plan.Arguments[0].Type = nil
			case "carrier":
				entry.plan.Arguments[0].Carriers[1].Register = DX
			case "capability":
				entry.owner.capabilities = nil
			case "frame":
				fn.FrameSize = 8
			}
			if entry.valid(fn, sig, "amd64") {
				t.Fatal("changed/revoked private argument association survived")
			}
		})
	}
	for _, test := range []struct {
		body   string
		accept bool
	}{{"MOVB AL,AL", true}, {"XORL AX,AX", true}, {"MOVB $2,AL", false}} {
		t.Run("bool-result/"+test.body, func(t *testing.T) {
			fn, sig, _ := amd64ArgumentBoundModel(t, "a bool", test.body, types.Typ[types.Bool])
			ctx := newX86Ctx(new(strings.Builder), fn, sig, nil, nil, "amd64", "x86_64-unknown-linux-gnu", false)
			err := ctx.scalarFPResultInitialized()
			if test.accept && err != nil || !test.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("argument role widened canonical bool result", err)
			}
		})
	}
}

func TestAMD64GoArgumentEntryEmissionUsesGroupedIndependentBanks(t *testing.T) {
	fn, sig, _ := amd64ArgumentBoundModel(t, "f float64, a struct { N byte; V [1]float32 }, b bool, s string",
		"MOVBQZX AL,AX\nMOVBQZX BL,BX\nMOVQ CX,CX\nMOVQ DI,DI\nMOVQ X0,R8\nMOVL X1,R9\nMOVQ $1,AX")
	var output strings.Builder
	ctx := newX86Ctx(&output, fn, sig, nil, nil, "amd64", "x86_64-unknown-linux-gnu", false)
	if err := ctx.emitAMD64GoArguments(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("prologue bypassed whole-source proof", err)
	}
	if err := ctx.scalarFPResultInitialized(); err != nil {
		t.Fatal("complete typed argument source proof", err)
	}
	if err := ctx.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	ir := output.String()
	for _, fragment := range []string{
		"bitcast double %arg0 to i64", "extractvalue { i8, [1 x float] } %arg1, 0",
		"extractvalue { i8, [1 x float] } %arg1, 1, 0", "zext i1 %arg2 to i64",
		"extractvalue { ptr, i64 } %arg3, 0", "extractvalue { ptr, i64 } %arg3, 1",
		"ptr %reg_AX", "ptr %reg_BX", "ptr %reg_CX", "ptr %reg_DI", "ptr %x0", "ptr %x1",
	} {
		if !strings.Contains(ir, fragment) {
			t.Errorf("missing grouped carrier %q in\n%s", fragment, ir)
		}
	}
	if strings.Contains(ir, "DX") || strings.Contains(ir, "inbounds") || strings.Contains(ir, "noalias") {
		t.Fatal("argument emission invented hidden/backing/alias authority", ir)
	}
}

func TestAMD64GoArgumentEntryPublicConsumersRequireLiveBinding(t *testing.T) {
	fn, sig, _ := amd64ArgumentBoundModel(t, "a string", "MOVQ BX,AX")
	file := &File{Arch: ArchAMD64, Funcs: []Func{fn}}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(string) string { return sig.Name }, Sigs: map[string]FuncSig{sig.Name: sig}}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			var err error
			switch api {
			case "text":
				_, err = Translate(file, options)
			case "module":
				context := llvm.NewContext()
				defer context.Dispose()
				module, failure := TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					module.Dispose()
				}
				err = failure
			case "Go":
				context := llvm.NewContext()
				defer context.Dispose()
				module, failure := translateGoModuleInContext(context, GoPackage{Path: sig.amd64GoArguments.declaration.Pkg().Path(), Types: sig.amd64GoArguments.declaration.Pkg()},
					[]byte("TEXT ·Entry<ABIInternal>(SB),4,$0-24\nMOVQ BX,AX\nRET\n"), GoModuleOptions{GOARCH: "amd64", TargetTriple: options.TargetTriple,
						ResolveSym: options.ResolveSym, ManualSig: func(string) (FuncSig, bool) { return sig, true }})
				if module != nil && !module.Module.IsNil() {
					module.Module.Dispose()
				}
				err = failure
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s borrowed a private comparison model without live original compiler/source proof: %v", api, err)
			}
		})
	}
	t.Run("no-direct-module-bypass", func(t *testing.T) {
		context := llvm.NewContext()
		defer context.Dispose()
		module, err := translateModuleDirectInContext(context, file, options)
		if !module.IsNil() {
			module.Dispose()
		}
		if !errors.Is(err, errDirectModuleUnsupported) {
			t.Fatal("linear module path bypassed typed whole-source proof", err)
		}
	})
	clone, err := numericalCloneSignatures(options.Sigs)
	if err != nil || clone[sig.Name].amd64GoArguments != sig.amd64GoArguments ||
		!reflect.DeepEqual(numericalSignatureShape(clone[sig.Name]), numericalSignatureShape(sig)) {
		t.Fatal("owned private identity and language shape were confused", fmt.Sprint(err))
	}
}
