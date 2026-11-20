//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ordinaryGoFrameCallAssembly = `TEXT ·Value(SB),4,$48-16
	MOVQ a+0(FP),AX
	MOVQ AX,0(SP)
	MOVQ $37,32(SP)
	CALL ·Callee(SB)
	MOVQ 8(SP),AX
	ADDQ 32(SP),AX
	MOVQ AX,ret+8(FP)
	RET
`

const ordinaryGoFrameCallDeclarations = `func Value(a uint64) uint64
//go:noinline
func Callee(a uint64) uint64 { return (a ^ 11) + 17 }
`

func ordinaryGoFrameCallObjects(t *testing.T, ir string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const target = "x86_64-unknown-linux-gnu"
	compileLLVMToObject(t, llc, target, "ordinary-call.ll", "ordinary-call.o", ir)
	compileLLVMToObject(t, llc, target, "ordinary-call-opt.ll", "ordinary-call-opt.o", x86MulDivRoundOptimize(t, ir))
}

func ordinaryGoFrameCallFixture(t *testing.T, declaration, assembly string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	pkg, request := goAMD64FrameTypedFixture(t, declaration, assembly)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make(map[string]FuncSig)
	for _, name := range []string{"Value", "Callee"} {
		if fn, ok := pkg.Types.Scope().Lookup(name).(*types.Func); ok {
			sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, fn, "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			signatures[sig.Name] = sig
		}
	}
	return pkg, request, file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: testResolveSym(pkg.Path), Sigs: signatures,
	}
}

func ordinaryGoFrameCallOriginalPackage(t *testing.T, request GoAMD64FrameCaptureRequest) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	env := append(append([]string(nil), request.Environment...),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
	archive := filepath.Join(t.TempDir(), "original.a")
	output, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
		"build", "-o", archive, ".")
	if err != nil {
		t.Fatalf("stock Go rejected the complete Go-body/assembly package: %v\n%s", err, output)
	}
	if info, err := os.Stat(archive); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatal("stock Go did not produce the complete package archive", err)
	}
}

func TestGoAMD64FrameOrdinaryGoCalleeCaptureAndObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	pkg, request, file, options := ordinaryGoFrameCallFixture(t,
		ordinaryGoFrameCallDeclarations, ordinaryGoFrameCallAssembly)
	callee := options.Sigs[pkg.Path+".Callee"]
	if len(callee.Args) != 1 || callee.Args[0] != I64 || callee.Ret != I64 ||
		len(callee.Frame.Params) != 1 || callee.Frame.Params[0].Offset != 0 ||
		len(callee.Frame.Results) != 1 || callee.Frame.Results[0].Offset != 8 {
		t.Fatal("the independently expected ABI0 outgoing/result slots changed", callee)
	}
	// This compiles both the real Go callee and its assembly caller. The
	// archive is not a claim of runtime execution or memory-effect proof.
	ordinaryGoFrameCallOriginalPackage(t, request)
	listing := frameRelocationOriginal(t, pkg, request)
	if !strings.Contains(string(listing), "t=R_CALL "+pkg.Path+".Callee+0") {
		t.Fatal("the independent assembler omitted the direct ABI0 callee identity", string(listing))
	}
	leaves, err := goAMD64FramePrivateLeaves(file, pkg)
	if err != nil || len(leaves) != 0 {
		t.Fatal("a Go implementation was reclassified as a private assembly leaf", leaves, err)
	}
	t.Run("unbound-three-APIs", func(t *testing.T) {
		fixedLocalAPIs(t, pkg, file, options, func(t *testing.T, ir string, err error) {
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("callee signatures alone authorized the original physical source frame", err, ir)
			}
		})
	})
	// Each API owns its bounded capture/binding lifetime. Old production must
	// fail here at Capture, not pass as an intentional source rejection.
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil || !strings.Contains(ir, "call i64 @\""+pkg.Path+".Callee\"(i64 ") ||
				strings.Contains(ir, "define i64 @\""+pkg.Path+".Callee\"") {
				t.Fatal("ordinary Go call was dropped, inlined as a private leaf, or assigned another ABI", err, ir)
			}
			ordinaryGoFrameCallObjects(t, ir)
		})
	t.Run("narrow-ABI0-slots", func(t *testing.T) {
		declaration := "func Value(a uint64) uint64\nfunc Callee(a uint8) uint8 { return (a ^ 11) + 17 }\n"
		assembly := strings.Replace(ordinaryGoFrameCallAssembly, "MOVQ 8(SP),AX", "MOVBQZX 8(SP),AX", 1)
		pkg, request, _, options := ordinaryGoFrameCallFixture(t, declaration, assembly)
		ordinaryGoFrameCallOriginalPackage(t, request)
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "call i8 @\""+pkg.Path+".Callee\"(i8 ") {
					t.Fatal("narrow argument/result transport lost its exact typed CALL", err, ir)
				}
				ordinaryGoFrameCallObjects(t, ir)
			})
	})
}

func TestGoAMD64FrameOrdinaryCallOutgoingAndClobberBoundaries(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, test := range []struct {
		name, before, after string
	}{
		{"missing-argument", "\tMOVQ AX,0(SP)\n", ""},
		{"partial-argument", "\tMOVQ AX,0(SP)\n", "\tMOVL AX,0(SP)\n"},
		{"wrong-argument-slot", "\tMOVQ AX,0(SP)\n", "\tMOVQ AX,16(SP)\n"},
		{"private-address-argument", "\tMOVQ AX,0(SP)\n", "\tLEAQ 32(SP),AX\n\tMOVQ AX,0(SP)\n"},
		{"old-GP-result", "\tMOVQ 8(SP),AX\n", ""},
		{"old-vector", "\tCALL ·Callee(SB)\n\tMOVQ 8(SP),AX\n", "\tPXOR X0,X0\n\tCALL ·Callee(SB)\n\tMOVQ X0,AX\n"},
		{"old-FLAGS", "\tCALL ·Callee(SB)\n\tMOVQ 8(SP),AX\n", "\tCMPQ AX,$0\n\tCALL ·Callee(SB)\n\tMOVQ $0,AX\n\tSETCS AL\n"},
		{"old-outgoing-input", "\tMOVQ 8(SP),AX\n", "\tMOVQ 0(SP),AX\n"},
		{"overwritten-frame-pointer", "\tCALL ·Callee(SB)\n", "\tMOVQ $0,BP\n\tCALL ·Callee(SB)\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := strings.Replace(ordinaryGoFrameCallAssembly, test.before, test.after, 1)
			pkg, request, file, options := ordinaryGoFrameCallFixture(t, ordinaryGoFrameCallDeclarations, assembly)
			ordinaryGoFrameCallOriginalPackage(t, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("a legal original CALL did not reach its independent state boundary", err)
			}
			defer func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			}()
			if _, err := owner.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary Go CALL acquired undefined bytes or retained physical scratch facts", err)
			}
		})
	}
}

func TestGoAMD64FrameOrdinaryCallSourceAndSuppliedABIStayBound(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, change := range []string{"Go-body-mutation", "register-ABI", "result-type", "parameter-slot"} {
		t.Run(change, func(t *testing.T) {
			pkg, request, file, options := ordinaryGoFrameCallFixture(t,
				ordinaryGoFrameCallDeclarations, ordinaryGoFrameCallAssembly)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("canonical ordinary CALL must capture before testing an independent boundary", err)
			}
			defer func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			}()
			if callee, found := owner.functions[pkg.Path+".Callee"]; found && callee.privateLeaf {
				t.Fatal("the Go body acquired a private physical entry")
			}
			if change == "Go-body-mutation" {
				path := filepath.Join(request.Directory, "value.go")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				after := bytes.Replace(before, []byte("+ 17"), []byte("+ 19"), 1)
				if bytes.Equal(before, after) {
					t.Fatal("source mutation did not alter the actual implementation")
				}
				if err := os.WriteFile(path, after, 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("a changed implementation retained the captured call source")
				}
				return
			}
			callee := options.Sigs[pkg.Path+".Callee"]
			switch change {
			case "register-ABI":
				callee.ArgRegs = []Reg{AX}
			case "result-type":
				callee.Ret = I32
			case "parameter-slot":
				callee.Frame.Params = append([]FrameSlot(nil), callee.Frame.Params...)
				callee.Frame.Params[0].Offset++
			}
			options.Sigs[callee.Name] = callee
			if _, err := owner.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("supplied signature changed the actual ABI0 callee contract", err)
			}
		})
	}
}
