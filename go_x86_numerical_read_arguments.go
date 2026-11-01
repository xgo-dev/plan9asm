package plan9asm

import (
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func amd64GoArgumentNeedsBinding(sig FuncSig) bool {
	for _, arg := range sig.Args {
		switch arg {
		case I8, I16, I32, I64, Ptr:
		default:
			return true
		}
	}
	return false
}

func (binding *GoX86NumericalReadBinding) bindAMD64GoArguments() error {
	source := binding.source
	if source.role != numericalSBSDKSource || binding.options.Goarch != "amd64" || source.sdkAssemblyJoin() == nil {
		return nil
	}
	needed := false
	for _, fn := range source.file.Funcs {
		needed = needed || strings.HasSuffix(fn.Sym, "<ABIInternal>") && amd64GoArgumentNeedsBinding(binding.options.Sigs[binding.resolve(fn.Sym)])
	}
	if !needed {
		return nil
	}
	if !reflect.DeepEqual(source.native.ArgumentRules, amd64GoArgumentCompilerSchema) {
		return amd64GoArgumentContext("source did not retain the complete selected compiler argument ABI rules")
	}
	joined := source.sdkAssemblyJoin()
	generated, err := gostaticstorage.ObserveX86SDKCompilerText(joined.Observation.Header.CompilerObject,
		joined.Observation.ObjectInputs.BuiltinSource, source.request.Target, joined.Observation.ObjectInputs.Referenced)
	if err != nil || joined.Observation.Objects == nil || len(joined.Observation.Objects.Members) < 2 || len(source.native.ArchiveMembers) < 2 {
		return amd64GoArgumentContext("missing complete original compiler/assembly archive")
	}
	member := joined.Observation.Objects.Members[1]
	originalMember := source.native.ArchiveMembers[1]
	if member.Name != "_go_.o" || originalMember.Name != member.Name || originalMember.Offset != member.Offset ||
		originalMember.Size != member.Size || originalMember.Flags != member.Flags || !reflect.DeepEqual(originalMember.Texts, member.Texts) {
		return amd64GoArgumentContext("selected compiler member differs from complete original archive")
	}
	aliases, err := numericalCompilerAliasIndex(joined.Observation.Header.SymABI, generated, member.Texts)
	if err != nil {
		return err
	}
	pkg := binding.packageInput
	names, err := numericalGoDeclarationLinknames(pkg.Syntax, pkg.Types)
	if err != nil {
		return err
	}
	entries, _, err := numericalTypedSourceDeclarations(source.file, pkg.Path, "amd64", source.role, names, source.native.CompilerAliases)
	if err != nil {
		return err
	}
	for _, fn := range source.file.Funcs {
		native := binding.resolve(fn.Sym)
		sig, found := binding.options.Sigs[native]
		if !found || !strings.HasSuffix(fn.Sym, "<ABIInternal>") || !amd64GoArgumentNeedsBinding(sig) {
			continue
		}
		if sig.x86CallerRegions != nil || sig.x86FixedLocal != nil || sig.amd64GoArguments != nil || fn.FrameSize != 0 {
			return amd64GoArgumentContext("argument carriers cannot borrow a caller/frame/native role")
		}
		declaration := entries[native]
		actual, valid := pkg.Types.Scope().Lookup(declaration.local).(*types.Func)
		if !valid || !declaration.entry || declaration.abi != 1 {
			return amd64GoArgumentContext("argument carrier lacks its original typed entry declaration")
		}
		index := -1
		for ordinal, text := range source.native.OriginalText {
			if text.Name == native && text.ABI == 1 {
				if index != -1 {
					return amd64GoArgumentContext("repeated actual source TEXT")
				}
				index = ordinal
			}
		}
		if index < 0 || index >= len(source.native.ExpandedText) {
			return amd64GoArgumentContext("argument entry lacks complete original/expanded TEXT")
		}
		plan, err := amd64GoArgumentEntryPlan(amd64GoArgumentEntryInput{
			Package: pkg.Types, Declaration: actual, Signature: sig, Native: native,
			Target: source.request.Target, Goarch: source.guard.env["GOARCH"], GOAMD64: source.guard.env["GOAMD64"],
			GOEXPERIMENT: source.guard.env["GOEXPERIMENT"], GOFLAGS: source.guard.env["GOFLAGS"],
			SymABI: joined.Observation.Header.SymABI, Original: source.native.OriginalText[index], Expanded: source.native.ExpandedText[index],
			Aliases: aliases, Standard: source.native.CompilerAliases[native].Standard,
		})
		if err != nil {
			return err
		}
		entry := &amd64GoArgumentBinding{owner: binding, declaration: actual, symbol: fn.Sym, signature: sig, plan: plan}
		entry.identity = entry
		entry.seal, err = entry.digest()
		if err != nil {
			return err
		}
		sig.amd64GoArguments = entry
		binding.options.Sigs[native] = sig
	}
	return nil
}
