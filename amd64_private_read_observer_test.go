package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The actual declaration stays pointer-only Void. Its existing caller producer
// must not be rebound to the scalar result declaration of a different entry.
const x86PrivateReadObserverAssembly = `TEXT ·kernel(SB),4,$0-32
MOVQ a+0(FP),DI
MOVOU (DI),X1
PEXTRD $0,X1,AX
BYTE $0xc3
`

func x86PrivateReadObserverFixture(t *testing.T) (GoPackage, *File, Options, Func) {
	t.Helper()
	goAssemblerOracleOutput(t, "amd64", x86PrivateReadObserverAssembly, "", true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, x86PrivateReadObserverAssembly)
	resolve := func(symbol string) string {
		return strings.Replace(symbol, "·", "caller.", 1)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs["caller.kernel"]
	if sig.Ret != Void || len(sig.Frame.Results) != 0 || len(sig.Args) != 4 ||
		sig.x86CallerRegions == nil || sig.x86CallerRegions.calls != 1 {
		t.Fatal("fixture lacks the actual pointer-only Void declaration and closed caller")
	}
	for _, argument := range sig.Args {
		if argument != Ptr {
			t.Fatal("fixture changed the existing pointer-only caller domain")
		}
	}
	if !x86CallerRegionSourceMatches(sig, file.Funcs[0], "amd64") {
		t.Fatal("actual caller signature does not match the complete original source")
	}
	options := Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: resolve, Sigs: sigs,
	}
	normalized, err := normalizeX86RawFile(file, "amd64", options)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Funcs) != 1 || !x86CallerNormalizedSourceMatches(normalized.Funcs[0], sig) {
		t.Fatal("normalized function lacks the same whole-source/signature caller proof")
	}
	fn := normalized.Funcs[0]
	found := 0
	for ordinal, ins := range fn.Instrs {
		if ins.Op != "MOVOU" {
			continue
		}
		found++
		access, present := ins.x86CallerMemory[0]
		if !present || access.write || access.width != 16 || !x86CallerMemoryCertified(ins, 0) ||
			len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != DI ||
			ins.Args[0].Mem.Off != 0 || ins.Args[1].Kind != OpReg || ins.Args[1].Reg != "X1" {
			t.Fatalf("instruction %d lacks its exact operand-0 numerical read16 certificate", ordinal)
		}
		t.Logf("same Void declaration and whole normalized source certify instruction %d operand 0 read16", ordinal)
	}
	if found != 1 {
		t.Fatal("fixture did not contain exactly one certified whole128 source read")
	}
	return pkg, file, options, fn
}

func TestX86PrivateReadObserverSameVoidCallerReadCertificate(t *testing.T) {
	pkg, file, options, fn := x86PrivateReadObserverFixture(t)

	// These are existing successful translations, not the regression's RED.
	// No scalar result, incoming native backing or new caller permission is
	// manufactured to make this observational fixture reach the private query.
	t.Run("existing-text-control", func(t *testing.T) {
		ir, err := Translate(file, options)
		if err != nil || ir == "" {
			t.Fatalf("existing certified Void text translation: %v", err)
		}
	})
	t.Run("existing-module-control", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil || module.IsNil() {
			t.Fatalf("existing certified Void module translation: %v", err)
		}
	})
	t.Run("existing-Go-control", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(x86PrivateReadObserverAssembly), GoModuleOptions{
			FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: options.TargetTriple,
			ResolveSym: options.ResolveSym,
		})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
		}
		if err != nil || translated == nil || translated.Module.IsNil() {
			t.Fatalf("existing certified Void Go translation: %v", err)
		}
	})

	sig := options.Sigs["caller.kernel"]
	if !x86CallerNormalizedSourceMatches(fn, sig) {
		t.Fatal("API controls changed the exact source/signature prerequisite")
	}
	if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("public declaration-only query acquired private Void/native admission: %v", err)
	}
	if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
		t.Errorf("same-source private observer discarded an existing exact read16 certificate: %v", err)
	}
}

func TestX86PrivateReadObserverMissingOrChangedAuthorityRemainsContext(t *testing.T) {
	_, _, options, fn := x86PrivateReadObserverFixture(t)
	for _, change := range []string{"missing-caller", "missing-source", "changed-operand", "changed-width", "changed-signature"} {
		t.Run(change, func(t *testing.T) {
			changed, sig := fn, options.Sigs["caller.kernel"]
			changed.Instrs = append([]Instr(nil), fn.Instrs...)
			for ordinal := range changed.Instrs {
				changed.Instrs[ordinal].Args = append([]Operand(nil), fn.Instrs[ordinal].Args...)
			}
			switch change {
			case "missing-caller":
				sig.x86CallerRegions = nil
			case "missing-source":
				changed.x86SourceStack = nil
			case "changed-signature":
				sig.Args = append([]LLVMType(nil), sig.Args...)
				sig.Args[0] = I64
			case "changed-operand", "changed-width":
				for ordinal := range changed.Instrs {
					ins := &changed.Instrs[ordinal]
					if ins.Op != "MOVOU" {
						continue
					}
					if change == "changed-operand" {
						ins.Args[0].Mem.Off++
					} else {
						ins.Op = "MOVSD"
					}
				}
			}
			if x86CallerNormalizedSourceMatches(changed, sig) {
				t.Fatal("mutated fixture retained the whole source/signature prerequisite")
			}
			if err := checkX86ScalarFPResultInitialization(changed, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private read observer borrowed absent or stale authority: %v", err)
			}
		})
	}
}

func TestX86PrivateReadObserverNonVoidDeclarationCannotBorrowCallerCertificate(t *testing.T) {
	source := strings.Replace(x86CallerFixtureSource,
		"func kernel(a, b, res, length unsafe.Pointer)",
		"func kernel(a, b, res, length unsafe.Pointer) uint32", 1)
	assembly := strings.Replace(x86PrivateReadObserverAssembly, "$0-32", "$0-36", 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, source, assembly)
	resolve := func(symbol string) string {
		return strings.Replace(symbol, "·", "caller.", 1)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs["caller.kernel"]
	if sig.Ret != I32 || len(sig.Frame.Results) != 1 || sig.x86CallerRegions != nil ||
		x86GoCallerRegionCandidate(file.Funcs[0], sig) {
		t.Fatal("actual scalar-result declaration borrowed the pointer-only Void caller certificate")
	}
	if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("non-Void native read acquired unproduced numerical backing: %v", err)
	}
}
