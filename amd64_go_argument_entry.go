package plan9asm

import (
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// This comparison model cannot create a binding or source token. The live
// factory supplies its complete original type graph and independently observed
// assembler definition, after verifying the registered compiler ABI rules.
type amd64GoArgumentEntryInput struct {
	Package                        *types.Package
	Declaration                    *types.Func
	Signature                      FuncSig
	Native, Target, Goarch         string
	GOAMD64, GOEXPERIMENT, GOFLAGS string
	SymABI                         []byte
	Original, Expanded             gostaticstorage.TextRecord
	Aliases                        *numericalCompilerAliasDirectory
	Standard                       bool
}

func amd64GoArgumentEntryPlan(input amd64GoArgumentEntryInput) (*amd64GoArgumentPlan, error) {
	fail := func() (*amd64GoArgumentPlan, error) {
		return nil, amd64GoArgumentContext("original declaration/compiler ABI/profile association differs")
	}
	fn, pkg := input.Declaration, input.Package
	if pkg == nil || fn == nil || fn.Pkg() != pkg || pkg.Scope().Lookup(fn.Name()) != fn ||
		input.Goarch != "amd64" || !strings.HasSuffix(input.Target, "/amd64") || numericalSDKTargetTriple(input.Target) == "" ||
		input.GOAMD64 != "v1" || input.GOEXPERIMENT != "" || input.GOFLAGS != "" {
		return fail()
	}
	declaration, valid := fn.Type().(*types.Signature)
	if !valid {
		return fail()
	}
	plan, err := planAMD64GoArguments(declaration)
	if err != nil || plan.requireRegisters() != nil {
		return fail() // Neither actual stack arguments nor reserved spill homes.
	}
	if declaration.Results().Len() != 1 {
		return fail()
	}
	resultBuilder := amd64GoArgumentBuilder{sizes: types.SizesFor("gc", "amd64")}
	result, err := resultBuilder.shape(declaration.Results().At(0).Type(), 0)
	if err != nil || result.stack || len(result.leaves) != 1 || len(result.leaves[0].Path) != 0 ||
		(result.leaves[0].Kind != amd64GoArgumentInteger && result.leaves[0].Kind != amd64GoArgumentBoolean) {
		return fail() // LLVM flattening is not a scalar Go result declaration.
	}
	expected, err := DeriveGoFuncABI0Signature(input.Native, fn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil || !reflect.DeepEqual(numericalSignatureShape(input.Signature), expected) || len(expected.Frame.Results) != 1 {
		return fail()
	}
	switch expected.Ret {
	case I1, I8, I16, I32, I64:
	default:
		return fail() // Results retain their independently closed existing role.
	}
	if input.Native != gosym.PackagePrefix(pkg.Path())+"."+fn.Name() &&
		(input.Aliases == nil || input.Aliases.association(input.Native, 1, input.Standard) != nil) {
		return fail()
	}
	if !amd64GoArgumentDefinition(input.SymABI, input.Native) {
		return fail()
	}
	original := input.Original
	if original.Name != input.Native || original.ABI != 1 || original.Kind != 1 ||
		original.Namespace != gostaticstorage.TextSymbolNonpkgDefinition || original.Size <= 0 ||
		original.Size != int64(len(original.Code)) || !reflect.DeepEqual(original, input.Expanded) {
		return fail()
	}
	return plan, nil
}

func amd64GoArgumentDefinition(symABI []byte, native string) bool {
	if len(symABI) == 0 || len(symABI) > 16<<20 || native == "" {
		return false
	}
	definitions := make(map[string]bool)
	found := false
	for _, line := range strings.Split(string(symABI), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "def" && fields[0] != "ref" ||
			fields[2] != "ABI0" && fields[2] != "ABIInternal" {
			return false
		}
		if fields[0] != "def" {
			continue
		}
		if definitions[fields[1]] || len(definitions) >= gostaticstorage.ObjectSymbolInventoryLimit {
			return false
		}
		definitions[fields[1]] = true
		if fields[1] == native {
			found = fields[2] == "ABIInternal"
		}
	}
	return found
}
