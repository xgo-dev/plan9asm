//go:build go1.27

package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestGoX86SDKLiteralMinimumOriginalCompleteMapsBinding(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) { sdkLiteralMinimumCompleteMapsBinding(t, target) })
	}
}

func sdkLiteralMinimumCompleteMapsBinding(t *testing.T, target string) {
	source, err := numericalSDKMapsReadCapture(t, target, "memhash_amd64.s")
	if err != nil {
		t.Fatal("complete actual SDK source/native/owner precondition", err)
	}
	ctx := source.sdk.originalContext
	minimum, err := CaptureGoX86SDKLiteralAlignment(ctx, source.literals.owner)
	if err != nil {
		t.Fatal("independent original-linked minimum precondition", err)
	}
	t.Cleanup(func() { minimum.Close() })
	pkg, file, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "linked address-bit observation") {
		t.Fatal("ordinary bytes gained original linked address bits", err)
	}
	bound, err := source.BindNumericalReadsWithLiteralAlignment(ctx, pkg, file, options, minimum)
	if err != nil {
		t.Fatal("complete original source/minimum/declaration binding", err)
	}
	if len(bound.Sigs) != len(file.Funcs) || len(file.Funcs) != len(source.file.Funcs) ||
		bound.NumericalReads.literalMinimum == nil || len(bound.NumericalReads.literalMinimum.Minima) != 2 {
		t.Fatal("minimum binding omitted original functions or inventories")
	}
	seen := 0
	for _, fact := range bound.NumericalReads.literalAccesses {
		if fact.LowBits != nil {
			if fact.LowBits.Mask != 31 && fact.LowBits.Mask != 15 || fact.LowBits.Value != 0 || fact.Function != pkg.Path+".checkMasksAndShiftsAlignment" {
				t.Fatal("address predicate exceeded actual original minimum", fact)
			}
			seen++
		}
	}
	if seen != 2 {
		t.Fatal("complete original OR/TEST predicate inventory", seen)
	}
	frozen, frozenOptions, err := freezeNumericalReadInputs(file, bound)
	if err != nil || len(frozen.Funcs) != len(file.Funcs) || len(frozen.Data) != len(file.Data) || len(frozen.Globl) != len(file.Globl) {
		t.Fatal("whole original normalized source/initializer inventories changed", err)
	}
	proved := 0
	for _, fn := range frozen.Funcs {
		name := frozenOptions.ResolveSym(fn.Sym)
		if name != pkg.Path+".checkMasksAndShiftsAlignment" {
			continue
		}
		consumer := &amd64Ctx{fpScalarSource: fn, sig: frozenOptions.Sigs[name], goarch: "amd64", targetTriple: options.TargetTriple}
		if err := consumer.checkLoweredScalarFPResultInitialization(); err != nil {
			t.Fatal("complete original masked predicate/canonical bool result proof", err)
		}
		proved++
	}
	if proved != 1 {
		t.Fatal("full source lost its actual declared predicate", proved)
	}
	// The separately tested caller-address rule now composes with this minimum
	// and the existing paired native-read/result observer. Translate the whole
	// inventory, never a cropped predicate; this is not native SDK execution.
	_, err = Translate(file, bound)
	if err != nil {
		t.Fatal("complete original maps logical translation", err)
	}
	t.Logf("complete original %d TEXT/maps binding retained; logical translation only, not native SDK entry/execution or benchmark completion", len(file.Funcs))
}

func TestGoX86SDKLiteralMinimumJoinFactoryIdentityAndLifetime(t *testing.T) {
	for _, mutation := range []string{"copy", "generation", "owner", "source", "higher-floor", "closed", "owner-closed", "source-closed"} {
		t.Run(mutation, func(t *testing.T) {
			source, err := numericalSDKMapsReadCapture(t, "amd64", "memhash_amd64.s")
			if err != nil {
				t.Fatal(err)
			}
			ctx := source.sdk.originalContext
			minimum, err := CaptureGoX86SDKLiteralAlignment(ctx, source.literals.owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { minimum.Close() })
			joined, err := captureNumericalSDKLiteralMinimum(ctx, source, minimum)
			if err != nil || len(joined.Minima) != 2 {
				t.Fatal("genuine same-source producer join", err)
			}
			switch mutation {
			case "copy":
				joined.alignment = &GoX86SDKLiteralAlignment{identity: minimum.identity} // No copied mutex/state.
			case "generation":
				joined.Generation++
			case "owner":
				original := minimum.owner
				minimum.owner = nil
				t.Cleanup(func() { minimum.owner = original })
			case "source":
				original := source.literals.source
				source.literals.source = nil
				t.Cleanup(func() { source.literals.source = original })
			case "higher-floor":
				for name := range joined.Minima {
					joined.Minima[name] *= 2
				}
			case "closed":
				if err := minimum.Close(); err != nil {
					t.Fatal(err)
				}
			case "owner-closed":
				if err := source.literals.owner.Close(); err != nil {
					t.Fatal(err)
				}
			case "source-closed":
				if err := source.literals.source.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := joined.verify(ctx, source); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("foreign/changed/closed factory or claimed higher floor retained authority", mutation, err)
			}
		})
	}
}

func TestGoX86SDKLiteralMinimumResolverReentry(t *testing.T) {
	for _, action := range []string{"Readback", "Close"} {
		t.Run(action, func(t *testing.T) {
			source, err := numericalSDKMapsReadCapture(t, "amd64", "memhash_amd64.s")
			if err != nil {
				t.Fatal(err)
			}
			ctx := source.sdk.originalContext
			minimum, err := CaptureGoX86SDKLiteralAlignment(ctx, source.literals.owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { minimum.Close() })
			pkg, file, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
			resolve := options.ResolveSym
			var once sync.Once
			var nested error
			options.ResolveSym = func(symbol string) string {
				once.Do(func() {
					if action == "Close" {
						nested = minimum.Close()
					} else {
						_, nested = minimum.Readback(ctx)
					}
				})
				return resolve(symbol)
			}
			bound, err := source.BindNumericalReadsWithLiteralAlignment(ctx, pkg, file, options, minimum)
			if nested != nil {
				t.Fatal("independent callback replay/close failed", nested)
			}
			if action == "Close" {
				if !errors.Is(err, ErrProbeNeedsContext) || bound.NumericalReads != nil {
					t.Fatal("reentrant close published a minimum predicate", err)
				}
			} else if err != nil {
				t.Fatal("resolver replay held a producer/source lock", err)
			}
			if err := source.literals.source.Verify(ctx); err != nil {
				t.Fatal("borrower callback disposed original source", err)
			}
		})
	}
}

func TestGoX86SDKLiteralMinimumOpaqueEffectsDoNotInitializeGP(t *testing.T) {
	file, err := Parse(ArchAMD64, x86SDKLiteralLowBitFixture)
	if err != nil {
		t.Fatal(err)
	}
	state := x86ResultState{}
	state.pointerGP[0], state.pointerGP[3] = true, true
	before := state.gp
	for _, ordinal := range []int{3, 4} {
		ins := file.Funcs[0].Instrs[ordinal]
		bits := &x86SDKLiteralLowBits{Operation: ins.Op, Mask: 15, Bytes: 8}
		if !x86ResultSDKLiteralLowBitStep(ins, bits, &state, "amd64") || !reflect.DeepEqual(state.gp, before) {
			t.Fatal("low-bit predicate manufactured full initialized GP bytes", ins, state)
		}
	}
	if state.flags&x86ByteFlagZF == 0 || state.flags&x86ByteFlagAF != 0 {
		t.Fatal("TEST defined/killed FLAGS changed", state.flags)
	}
}
