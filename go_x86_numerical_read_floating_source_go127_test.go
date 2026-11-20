//go:build go1.27

package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This is an actual ordinary owned module and complete original Go archive,
// not a fabricated SDK token or an ABIInternal argument-carrier observation.
func numericalFloatingSourceFixture(t *testing.T, arch, declarations, body string, functions int) (
	context.Context, *GoX86NumericalReadSource, GoPackage, *File, Options,
) {
	t.Helper()
	ownerRequest, readRequest := numericalMutableFixture(t, arch, "MOVB DATA+3(SB),AL")
	goSource := "package consumer\n" + declarations
	if err := os.WriteFile(filepath.Join(readRequest.Directory, "value.go"), []byte(goSource), 0600); err != nil {
		t.Fatal(err)
	}
	assembly := "#include \"textflag.h\"\n#include \"local.h\"\n" + body
	if err := os.WriteFile(filepath.Join(readRequest.Directory, readRequest.AssemblyFile), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	actual, err := goasmcmd.Run(ctx, readRequest.Directory, readRequest.Environment, readRequest.GoBinary,
		"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
	var selected goAMD64FrameSelection
	if err != nil || json.Unmarshal(actual, &selected) != nil || selected.Export == "" ||
		selected.ImportPath != readRequest.PackagePath || !reflect.DeepEqual(selected.SFiles, []string{readRequest.AssemblyFile}) {
		t.Fatal("independent actual original Go package/archive prerequisite failed", err, selected)
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil || len(archive) == 0 {
		t.Fatal("actual original compiler/ASM archive is absent", err)
	}
	builtins, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(readRequest.GoBinary)),
		"src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	members, err := gostaticstorage.ObserveX86AssemblyArchive(archive, builtins, readRequest.Target, selected.SFiles)
	if err != nil || len(members) != 3 || len(members[2].Texts) != functions {
		t.Fatal("independent complete original archive/ABI0 TEXT prerequisite failed", err, len(members))
	}
	for _, text := range members[2].Texts {
		if text.ABI != 0 || len(text.Code) == 0 || text.Size != int64(len(text.Code)) {
			t.Fatal("ordinary scalar source acquired a different native ABI", text)
		}
	}
	t.Logf("original %s sourceSHA=%x archiveSHA=%x ASMentries=%d", arch,
		sha256.Sum256([]byte(goSource+assembly)), sha256.Sum256(archive), functions)
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal("actual independent mutable numerical owner prerequisite failed", err)
	}
	t.Cleanup(owner.Close)
	readRequest.Owners = []*GoNumericalStorageOwner{owner}
	source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
	if err != nil {
		t.Fatal("complete original Go/source/native/numerical-read observation failed", err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	if len(source.file.Funcs) != functions || len(source.reads) != functions {
		t.Fatal("the complete original source/read inventory was cropped", len(source.file.Funcs), len(source.reads), functions)
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filepath.Join(readRequest.Directory, "value.go"), goSource, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check(readRequest.PackagePath, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal("independent original scalar typecheck failed", err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}
	options := Options{Goarch: arch, TargetTriple: numericalSDKTargetTriple(readRequest.Target),
		Sigs: make(map[string]FuncSig), ResolveSym: func(symbol string) string { return numericalNativeName(symbol, pkg.Path) }}
	for _, fn := range source.file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		declared, ok := typed.Scope().Lookup(name).(*types.Func)
		if !ok {
			t.Fatal("complete actual declaration is absent", name)
		}
		sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, declared, arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	return ctx, source, pkg, source.file, options
}

func numericalFloatingSourceBody(arch string) string {
	var body strings.Builder
	for _, name := range []string{"Direct32", "Direct64", "Named32", "Named64", "Alias32", "Alias64"} {
		move, width := "MOVSS", int64(4)
		if strings.HasSuffix(name, "64") {
			move, width = "MOVSD", 8
		}
		result := width
		if arch == "amd64" && result == 4 {
			result = 8
		}
		fmt.Fprintf(&body, "TEXT ·%s(SB),NOSPLIT,$0-%d\nMOVB DATA+3(SB),AL\n%s x+0(FP),X0\n%s X0,ret+%d(FP)\nRET\n",
			name, result+width, move, move, result)
	}
	return body.String()
}

func TestGoX86NumericalReadOrdinaryFloatingScalarSourceDeclarations(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, source, pkg, file, options := numericalFloatingSourceFixture(t, arch,
				numericalFloatingDeclarations, numericalFloatingSourceBody(arch), 6)
			for name, sig := range options.Sigs {
				floating, width, result := LLVMType("float"), int64(4), int64(4)
				if strings.HasSuffix(name, "64") {
					floating, width, result = LLVMType("double"), 8, 8
				} else if arch == "amd64" {
					result = 8
				}
				if !reflect.DeepEqual(sig.Args, []LLVMType{floating}) || sig.Ret != floating ||
					len(sig.Frame.Params) != 1 || sig.Frame.Params[0].Type != floating || sig.Frame.Params[0].Offset != 0 ||
					len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != floating || sig.Frame.Results[0].Offset != result ||
					frameTypeSize(floating, int64(goWordSize(arch))) != width {
					t.Fatal("ordinary actual F32/F64 ABI0 slots were replaced by integer bits", name, sig)
				}
			}
			declarations, err := source.numericalDeclarations(ctx, pkg, arch)
			if err != nil || len(declarations) != 6 {
				t.Fatal("ordinary numerical source cannot observe the complete actual floating declarations", err, len(declarations))
			}
			for name, declaration := range declarations {
				if !reflect.DeepEqual(declaration.signature, options.Sigs[name]) ||
					declaration.transport == goAMD64FrameNumericTransport || !strings.Contains(declaration.languageType, "float") {
					t.Fatal("floating language identity became integer transport or changed its actual layout", name, declaration)
				}
			}
			bound, err := source.BindNumericalReads(ctx, pkg, file, options)
			if err != nil || bound.NumericalReads == nil {
				t.Fatal("actual floating source declaration did not join its independent numerical read", err)
			}
			for name, sig := range bound.Sigs {
				if !reflect.DeepEqual(sig, options.Sigs[name]) || len(sig.ArgRegs) != 0 ||
					sig.amd64GoArguments != nil || sig.x86FixedLocal != nil || sig.x86CallerRegions != nil {
					t.Fatal("ordinary floating declaration gained register/caller/native-frame authority", name)
				}
			}
			numericalFloatingSourceDriftGuards(t, ctx, source, pkg, file, options)
		})
	}
}

func numericalFloatingSourceDriftGuards(t *testing.T, ctx context.Context, source *GoX86NumericalReadSource,
	pkg GoPackage, file *File, options Options,
) {
	t.Helper()
	for _, numericOnly := range []bool{false, true} {
		if declarations, err := source.guard.typedDeclarationsForArchRole(pkg, numericOnly, options.Goarch, false, nil); declarations != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("numerical scalar observation widened the ordinary/native fixed-local frame issuer", numericOnly, err)
		}
	}
	for _, change := range []struct{ name, from, to string }{
		{"same-width integer", "float64", "uint64"},
		{"precision", "float32", "float64"},
	} {
		fset := token.NewFileSet()
		syntax, err := parser.ParseFile(fset, "supplied.go", "package consumer\n"+
			strings.ReplaceAll(numericalFloatingDeclarations, change.from, change.to), 0)
		if err != nil {
			t.Fatal(err)
		}
		typed, err := (&types.Config{Sizes: types.SizesFor("gc", options.Goarch)}).Check(pkg.Path, fset, []*ast.File{syntax}, nil)
		if err != nil {
			t.Fatal(err)
		}
		changed := GoPackage{Path: pkg.Path, Types: typed, Syntax: []*ast.File{syntax}}
		if declarations, err := source.numericalDeclarations(ctx, changed, options.Goarch); declarations != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed same-size/precision language source retained the observed declaration", change.name, err)
		}
	}
	for _, change := range []string{"integer signature", "slot", "register ABI"} {
		changed := options
		var err error
		changed.Sigs, err = numericalCloneSignatures(options.Sigs)
		if err != nil {
			t.Fatal(err)
		}
		name := pkg.Path + ".Direct64"
		sig := changed.Sigs[name]
		switch change {
		case "integer signature":
			sig.Args[0], sig.Ret = I64, I64
			sig.Frame.Params[0].Type, sig.Frame.Results[0].Type = I64, I64
		case "slot":
			sig.Frame.Params[0].Offset++
		case "register ABI":
			sig.ArgRegs = []Reg{"X0"}
		}
		changed.Sigs[name] = sig
		if bound, err := source.BindNumericalReads(ctx, pkg, file, changed); bound.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed floating ABI/layout acquired the observed source binding", change, err)
		}
	}
	changedFile := *file
	changedFile.Funcs = append([]Func(nil), file.Funcs...)
	changedFile.Funcs[0].Sym += "<ABIInternal>"
	if bound, err := source.BindNumericalReads(ctx, pkg, &changedFile, options); bound.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("ordinary floating ABI0 source changed to an unobserved ABIInternal entry", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("negative supplied declarations changed the actual immutable source", err)
	}
}

func TestGoX86NumericalReadFloatingScalarDoesNotAdmitCompositeSourceRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, typ := range []struct {
			name, spelling string
			bytes          int64
		}{
			{"string", "string", 2 * int64(goWordSize(arch))},
			{"complex", "complex64", 8},
			{"aggregate", "[2]uint32", 8},
			{"floating-pointee", "*float64", int64(goWordSize(arch))},
			{"floating-slice", "[]float32", 3 * int64(goWordSize(arch))},
		} {
			t.Run(arch+"/"+typ.name, func(t *testing.T) {
				body := fmt.Sprintf("TEXT ·Feature(SB),NOSPLIT,$0-%d\nMOVB DATA+3(SB),AL\nMOVL $0,ret+%d(FP)\nRET\n",
					typ.bytes+4, typ.bytes)
				ctx, source, pkg, _, _ := numericalFloatingSourceFixture(t, arch,
					"func Feature(x "+typ.spelling+") uint32\n", body, 1)
				if declarations, err := source.numericalDeclarations(ctx, pkg, arch); declarations != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("ordinary floating scalar role admitted actual string/complex/aggregate source", typ.name, err)
				}
			})
		}
	}
}

func TestGoX86NumericalReadOriginalSDKMathExpFloatingABI0(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "math")
	original, err := os.ReadFile(filepath.Join(request.Directory, "exp_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complete original SDK math/exp ASM SHA256=%x", sha256.Sum256(original))
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment, SDKGlobals: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "math", Name: "useFMA"}},
	})
	if err != nil {
		t.Fatal("independent actual SDK choice-byte owner prerequisite failed", err)
	}
	t.Cleanup(owner.Close)
	data, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("complete actual original SDK source/archive/layout prerequisite failed", err)
	}
	t.Cleanup(func() {
		if err := data.Close(); err != nil {
			t.Error(err)
		}
	})
	literals, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, data)
	if err != nil {
		t.Fatal("complete original SDK literal owner prerequisite failed", err)
	}
	t.Cleanup(func() {
		if err := literals.Close(); err != nil {
			t.Error(err)
		}
	})
	pkg, file, options := numericalSDKLiteralPackage(t, data, "exp_amd64.s")
	sig := options.Sigs["math.archExp"]
	if len(file.Funcs) != 1 || !reflect.DeepEqual(sig.Args, []LLVMType{"double"}) || sig.Ret != "double" ||
		len(sig.Frame.Params) != 1 || sig.Frame.Params[0].Type != "double" || sig.Frame.Params[0].Offset != 0 ||
		len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != "double" || sig.Frame.Results[0].Offset != 8 {
		t.Fatal("original SDK ordinary float64 declaration/ABI0 layout changed", sig)
	}
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment, AssemblyFile: "exp_amd64.s",
		Owners: []*GoNumericalStorageOwner{owner}, ReadonlyLiterals: literals,
	})
	if err != nil {
		t.Fatal("complete original SDK native/numerical-read capture failed", err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	if len(source.reads) != 1 || source.reads[0].width != 1 || source.reads[0].variable.NativeName != "math.useFMA" {
		t.Fatal("float64 parameters or literal pools acquired numerical global-read identity", source.reads)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil || bound.NumericalReads == nil {
		t.Fatal("ordinary original SDK float64 declaration cannot bind its actual choice-byte read", err)
	}
	if !reflect.DeepEqual(bound.Sigs["math.archExp"], sig) || len(sig.ArgRegs) != 0 ||
		sig.amd64GoArguments != nil || sig.x86FixedLocal != nil || sig.x86CallerRegions != nil {
		t.Fatal("ordinary SDK floating ABI0 source acquired another entry/caller/frame role")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete original SDK source/read binding changed its live source", err)
	}
}
