package main

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// Reuse the actual packages.Load pre-type/export selection. The private
// producer inventory must agree before typechecking and again afterwards;
// ordinary package capture remains untouched.
func (consumer *featureConsumer) bindActualTestDependencies(ordinary, selected *packages.Package) error {
	if consumer.Input.TestDependencySourceProtocol == "" {
		return nil // Historical consumer inputs retain their original contract.
	}
	dependency := consumer.Input.TestDependencies
	if dependency == nil || dependency.Protocol != gotoolprofile.TestDependencyProtocol {
		return fmt.Errorf("actual test declaration lacks a pre-load source-only closure")
	}
	if err := gotoolprofile.ValidateTestDependencyPreload(consumer.Input, dependency, consumer.Proof.CustomTags); err != nil {
		return err
	}
	var actual []gotoolprofile.TestSourcePackage
	var foreign []gotoolprofile.TestSourcePackage
	var captureErr error
	boundEmbeds := make(map[string]testDependencyEmbedGuard)
	packages.Visit([]*packages.Package{selected}, func(pkg *packages.Package) bool {
		if captureErr != nil {
			return false
		}
		if pkg.Module == nil || pkg.Module.Path != consumer.Input.Module {
			source, err := consumer.foreignTestSourcePackage(pkg)
			if err != nil {
				captureErr = err
				return false
			}
			foreign = append(foreign, source)
			boundEmbeds[pkg.ID] = testDependencyEmbedGuard{Source: source, Root: consumer.TestModuleGuards[source.SourceRootID].Root}
			return true
		}
		if !reflect.DeepEqual(pkg.Module, ordinary.Module) || pkg.PkgPath != consumer.Input.Module && !strings.HasPrefix(pkg.PkgPath, consumer.Input.Module+"/") {
			captureErr = fmt.Errorf("test dependency has a different actual module/version/source identity")
			return false
		}
		var template *gotoolprofile.PackageProof
		for index := range consumer.Proof.Packages {
			if consumer.Proof.Packages[index].PackagePath == ordinary.PkgPath {
				template = &consumer.Proof.Packages[index]
			}
		}
		if template == nil {
			captureErr = fmt.Errorf("test dependency lacks its actual ordinary source role")
			return false
		}
		proof := *template
		proof.PackagePath, proof.Macros, proof.SourceSHA256 = pkg.PkgPath, nil, make(map[string]string)
		capture := func(files []string, assembly bool) []string {
			var result []string
			for _, filename := range files {
				if assembly && filepath.Ext(filename) != ".s" {
					continue
				}
				name, err := consumer.sourceName(filename)
				if err != nil {
					captureErr = err
					return nil
				}
				proof.SourceSHA256[name] = consumer.Input.Sources[name]
				result = append(result, name)
			}
			sort.Strings(result)
			return result
		}
		proof.GoFiles = capture(pkg.GoFiles, false)
		proof.CompiledGoFiles = capture(pkg.CompiledGoFiles, false)
		proof.SFiles = capture(pkg.OtherFiles, true)
		imports := make(map[string]string)
		for spelling, imported := range pkg.Imports {
			imports[spelling] = imported.PkgPath
		}
		embed, err := captureTestPackageEmbedSelection(proof, consumer.Dir, pkg)
		if err != nil {
			captureErr = err
			return false
		}
		source := gotoolprofile.TestSourcePackage{Package: proof, VariantID: pkg.ID, ImportMap: imports, Embed: embed}
		actual = append(actual, source)
		boundEmbeds[pkg.ID] = testDependencyEmbedGuard{Source: source, Root: consumer.Dir}
		return true
	}, nil)
	if captureErr != nil {
		return captureErr
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i].Package.PackagePath < actual[j].Package.PackagePath })
	sort.Slice(foreign, func(i, j int) bool { return foreign[i].Package.PackagePath < foreign[j].Package.PackagePath })
	if !reflect.DeepEqual(actual, dependency.Packages) || !reflect.DeepEqual(foreign, dependency.ExternalPackages) ||
		len(consumer.TestModuleGuards) != len(dependency.SourceModules) {
		for _, pair := range []struct {
			actual, expected []gotoolprofile.TestSourcePackage
		}{
			{actual: actual, expected: dependency.Packages},
			{actual: foreign, expected: dependency.ExternalPackages},
		} {
			for index, source := range pair.actual {
				if index < len(pair.expected) && !reflect.DeepEqual(source.Embed, pair.expected[index].Embed) {
					return fmt.Errorf("actual same-profile embed inventory differs: package=%s actual=%+v expected=%+v", source.Package.PackagePath, source.Embed, pair.expected[index].Embed)
				}
			}
		}
		return fmt.Errorf("actual same-profile test dependency selection differs from complete pre-load inventory")
	}
	consumer.Proof.TestDependencies = dependency
	consumer.TestEmbedGuards = boundEmbeds
	return consumer.verifySources()
}

func (consumer *featureConsumer) queryMissingSignatureSources(pkg *packages.Package, file *plan9asm.File, asm string,
	resolve func(string) string, goarch string,
) ([]gotoolprofile.SignatureRequest, error) {
	requests, err := assemblySignatureRequests(pkg.PkgPath, file, resolve)
	if err != nil {
		return nil, err
	}
	filename, err := consumer.sourceName(asm)
	if err != nil {
		return nil, err
	}
	var result []gotoolprofile.SignatureRequest
	for symbol, request := range requests {
		internal := strings.HasSuffix(request.original, "<ABIInternal>")
		_, _, found, err := tryDeclSig(pkg.Types.Scope(), request.original, symbol,
			linknameRemoteToLocal(pkg.Syntax), goarch, pkg.TypesSizes, internal)
		if err != nil {
			return nil, err
		}
		if found || strings.Contains(request.original, "<>") || !strings.HasPrefix(symbol, pkg.PkgPath+".") {
			continue
		}
		name := strings.TrimPrefix(symbol, pkg.PkgPath+".")
		candidate, err := consumer.testDeclarationCandidate(pkg, filepath.Dir(asm), name)
		if err != nil {
			return nil, err
		}
		if candidate {
			result = append(result, gotoolprofile.SignatureRequest{
				File: filename, Symbol: symbol, Callee: request.callee, ABIInternal: internal,
			})
		}
	}
	return result, consumer.verifySources()
}
