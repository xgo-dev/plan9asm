package gotoolprofile

import (
	"fmt"
	"go/build"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"
)

// ValidateSelection checks the compact compiler-consumption evidence against
// the producer's original source/profile inputs. Actual reobservation and ZIP
// byte comparison happen in production, not in this offline replay.
func ValidateSelection(input *ConsumerInput, proof *SelectionProof, tags []string, requireObject bool) error {
	return ValidateSelectionWithABI(input, proof, tags, requireObject, nil)
}

// Only a caller which independently validated exact target ABI exclusions may
// permit their missing LLVM outputs. Default consumers never grant this path.
func ValidateSelectionWithABI(input *ConsumerInput, proof *SelectionProof, tags []string, requireObject bool, abi map[string]bool) error {
	if input == nil || input.Protocol != ConsumerProtocol || input.ID != ProfileID(input.Observed) {
		return fmt.Errorf("missing canonical compiler feature input")
	}
	if err := Validate(input.Observed); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != ConsumerProtocol || proof.ProfileID != input.ID || !equalDiscoveryStrings(proof.CustomTags, tags) || len(proof.Packages) == 0 {
		return fmt.Errorf("compiler consumption differs from the source-required profile/tag scope")
	}
	if !reflect.DeepEqual(input.RegisteredAsmFiles, proof.RegisteredAsmFiles) {
		return fmt.Errorf("actual package registration differs from the complete selected assembly scope")
	}
	if err := ValidateCPPIncludeSearch(input, proof); err != nil {
		return err
	}
	selectedFiles, filePackages, err := validatePackageSelection(input, proof.Packages, tags)
	if err != nil {
		return err
	}
	if input.GeneratedHeaders != nil || proof.GeneratedHeaders != nil {
		if err := ValidateGeneratedHeaderAgreement(input, input.GeneratedHeaders, proof.GeneratedHeaders, tags); err != nil {
			return err
		}
		if !reflect.DeepEqual(proof.Packages, proof.GeneratedHeaders.Packages) {
			return fmt.Errorf("actual generated header was compiled from a different package selection")
		}
	}
	if err := ValidateSignatureSources(input, proof, tags); err != nil {
		return err
	}
	return validateAssemblyConsumption(input, proof, selectedFiles, filePackages, requireObject, abi)
}

// ValidatePackageSelection checks actual package selection before CPP or LLVM
// emission. It establishes no translation outcome: the report reader must
// separately discharge every source-required scope with an output or a concrete
// same-scope source diagnostic.
func ValidatePackageSelection(input *ConsumerInput, packages []PackageProof, tags []string) error {
	if input == nil || input.Protocol != ConsumerProtocol || input.Observed == nil || input.ID != ProfileID(input.Observed) || len(packages) == 0 {
		return fmt.Errorf("missing canonical actual package-selection input")
	}
	if err := Validate(input.Observed); err != nil {
		return err
	}
	_, _, err := validatePackageSelection(input, packages, tags)
	return err
}

// Metadata-only queries reuse source selection without manufacturing CPP or
// LLVM outputs. Their separate protocol can never satisfy ValidateSelection.
func validatePackageSelection(input *ConsumerInput, packages []PackageProof, tags []string) (map[string]bool, map[string]PackageProof, error) {
	ctx, err := ordinaryPackageSelectionContext(input, tags)
	if err != nil {
		return nil, nil, err
	}
	macros := func(pkg PackageProof) error {
		return ValidateOrdinaryAssemblerMacros(pkg.Macros, input.Observed, pkg.PackagePath)
	}
	return validatePackageSelectionContext(input, packages, input.AsmFiles, input.RegisteredAsmFiles, ctx, macros)
}

// Both public protocol readers retain their own validated scope/context. This
// common replay does not choose a mode or turn an ordinary observation into one.
func validatePackageSelectionContext(input *ConsumerInput, packages []PackageProof, assembly, registered []string, ctx build.Context, validateMacros func(PackageProof) error) (map[string]bool, map[string]PackageProof, error) {
	selectedFiles, seenPackages := make(map[string]bool), make(map[string]bool)
	filePackages := make(map[string]PackageProof)
	requiredAssembly := make(map[string]bool)
	for _, file := range assembly {
		requiredAssembly[file] = true
	}
	if registered != nil {
		if len(registered) == 0 || !sort.StringsAreSorted(registered) {
			return nil, nil, fmt.Errorf("noncanonical complete package assembly registration")
		}
		requiredAssembly = make(map[string]bool)
		for _, file := range registered {
			if requiredAssembly[file] || path.Ext(file) != ".s" || input.Sources[file] == "" ||
				input.Sources[file] == bytesSHA256(nil) {
				return nil, nil, fmt.Errorf("duplicate, empty or unhashed package assembly registration: %s", file)
			}
			requiredAssembly[file] = true
		}
		for _, file := range assembly {
			if !requiredAssembly[file] {
				return nil, nil, fmt.Errorf("translation file lies outside the complete package registration: %s", file)
			}
		}
	}
	for _, pkg := range packages {
		if err := ValidatePackageModule(input, pkg); err != nil {
			return nil, nil, err
		}
		if pkg.PackagePath != input.Module && !strings.HasPrefix(pkg.PackagePath, input.Module+"/") || seenPackages[pkg.PackagePath] {
			return nil, nil, fmt.Errorf("actual selected package has a different or duplicate module role")
		}
		seenPackages[pkg.PackagePath] = true
		if err := validateMacros(pkg); err != nil {
			return nil, nil, err
		}
		if len(pkg.GoFiles) == 0 || len(pkg.CompiledGoFiles) == 0 || len(pkg.SFiles) == 0 {
			return nil, nil, fmt.Errorf("compiler consumption lacks actual ordinary Go/ASM selection")
		}
		usedSources := make(map[string]string)
		for _, files := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.SFiles} {
			if !sort.StringsAreSorted(files) {
				return nil, nil, fmt.Errorf("noncanonical actual selected source order")
			}
			for index, file := range files {
				if index > 0 && file == files[index-1] || input.Sources[file] == "" || input.Sources[file] != pkg.SourceSHA256[file] {
					return nil, nil, fmt.Errorf("actual selected source has no exact original SHA: %s", file)
				}
				usedSources[file] = pkg.SourceSHA256[file]
				wantedPath := input.Module
				if path.Dir(file) != "." {
					wantedPath += "/" + path.Dir(file)
				}
				if pkg.PackagePath != wantedPath {
					return nil, nil, fmt.Errorf("actual package role differs from the original source directory: %s", file)
				}
				if path.Ext(file) == ".go" || path.Ext(file) == ".s" {
					selected, err := ctx.MatchFile(path.Dir(file), path.Base(file))
					if err != nil || !selected || strings.HasSuffix(file, "_test.go") {
						return nil, nil, fmt.Errorf("actual source selection contradicts its original feature constraints: %s: %v", file, err)
					}
				}
			}
		}
		if !reflect.DeepEqual(usedSources, pkg.SourceSHA256) {
			return nil, nil, fmt.Errorf("actual package source hash map has missing/extra consumption")
		}
		for _, file := range pkg.SFiles {
			if selectedFiles[file] || path.Ext(file) != ".s" {
				return nil, nil, fmt.Errorf("duplicate/non-ASM actual selected file")
			}
			// Go-selected zero-byte siblings have no translation count.
			if !requiredAssembly[file] && (input.Sources[file] != bytesSHA256(nil) || input.Headers[file] != "") {
				return nil, nil, fmt.Errorf("nonempty Go-selected assembly lies outside the tested scope: %s", file)
			}
			selectedFiles[file] = true
			filePackages[file] = pkg
		}
	}
	for file := range requiredAssembly {
		if !selectedFiles[file] {
			return nil, nil, fmt.Errorf("registered assembly lacks actual same-profile package selection: %s", file)
		}
	}
	return selectedFiles, filePackages, nil
}

func ordinaryPackageSelectionContext(input *ConsumerInput, tags []string) (build.Context, error) {
	minor, err := goMinor(input.Observed.GoVersion)
	if err != nil {
		return build.Context{}, err
	}
	ctx := build.Default
	ctx.JoinPath = path.Join
	ctx.GOOS, ctx.GOARCH = input.Observed.Environment["GOOS"], input.Observed.Environment["GOARCH"]
	ctx.Compiler, ctx.CgoEnabled, ctx.BuildTags = "gc", false, tags
	ctx.ToolTags, ctx.ReleaseTags = input.Observed.ToolTags, nil
	for version := 1; version <= minor; version++ {
		ctx.ReleaseTags = append(ctx.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	ctx.OpenFile = func(name string) (io.ReadCloser, error) {
		header, found := input.Headers[name]
		if !found {
			return nil, fmt.Errorf("actual Go file has no original selection header: %s", name)
		}
		return io.NopCloser(strings.NewReader(header)), nil
	}
	return ctx, nil
}

func validateAssemblyConsumption(input *ConsumerInput, proof *SelectionProof, selectedFiles map[string]bool, filePackages map[string]PackageProof, requireObject bool, abi map[string]bool) error {
	consumed, err := validateCPPConsumption(input, proof, selectedFiles, filePackages)
	if err != nil {
		return err
	}
	outputs := make(map[string]bool)
	seenParts := make(map[string]bool)
	for _, output := range proof.Outputs {
		key := output.File + "\x00" + output.Part
		if !consumed[output.File] || abi[output.File] || seenParts[key] || path.Base(output.Part) != output.Part || !strings.HasSuffix(output.Part, ".ll") || !discoverySHA256Pattern.MatchString(output.IR) || requireObject && !discoverySHA256Pattern.MatchString(output.Object) {
			return fmt.Errorf("missing, duplicate or unselected LLVM IR/object consumption")
		}
		seenParts[key], outputs[output.File] = true, true
	}
	for _, file := range input.AsmFiles {
		if !selectedFiles[file] || !consumed[file] || !outputs[file] && !abi[file] {
			return fmt.Errorf("source-required file lacks actual package/CPP/LLVM consumption: %s", file)
		}
	}
	if len(consumed) != len(input.AsmFiles) || len(outputs)+len(abi) != len(input.AsmFiles) {
		return fmt.Errorf("compiler consumption differs from the exact file/profile scope")
	}
	return nil
}

// Preflight reuses only the source/CPP portion. It never manufactures an LLVM
// output or satisfies the separate translation consumption gate.
func validateCPPConsumption(input *ConsumerInput, proof *SelectionProof, selectedFiles map[string]bool, filePackages map[string]PackageProof) (map[string]bool, error) {
	if err := ValidateCPPIncludeSearch(input, proof); err != nil {
		return nil, err
	}
	consumed := make(map[string]bool)
	for _, cpp := range proof.CPP {
		if consumed[cpp.File] || !selectedFiles[cpp.File] || !discoverySHA256Pattern.MatchString(cpp.ExpandedSHA256) || !discoverySHA256Pattern.MatchString(cpp.TypedExpandedSHA256) || len(cpp.Inputs) == 0 {
			return nil, fmt.Errorf("missing, duplicate or unselected actual CPP consumption")
		}
		consumed[cpp.File] = true
		if input.CPPOriginals != nil {
			pkg := filePackages[cpp.File]
			var header []byte
			if proof.GeneratedHeaders != nil {
				for _, actual := range proof.GeneratedHeaders.Headers {
					if actual.PackagePath == pkg.PackagePath {
						var err error
						header, err = CanonicalGeneratedHeader(actual.Definitions)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			actual, used, required, err := ReplayCPPOriginal(input, cpp.File, pkg.PackagePath, pkg.Macros.Defines, header)
			if err != nil || ValidateCPPExpandedOperands(input, cpp.File, required) != nil ||
				cpp.ExpandedSearchMisses == nil || !reflect.DeepEqual(cpp.ExpandedSearchMisses, required) ||
				cpp.ExpandedSHA256 != bytesSHA256([]byte(actual.Output)) || !reflect.DeepEqual(used, cpp.Inputs) {
				return nil, fmt.Errorf("actual CPP differs from the independent original graph/expanded operands: %v", err)
			}
		}
		for id, digest := range cpp.Inputs {
			origin, file, present := strings.Cut(id, "/")
			wanted := input.Sources[file]
			if origin == "tool" {
				wanted = input.ToolSources[file]
			}
			if origin == "generated" {
				wanted = generatedCPPSourceSHA(proof.GeneratedHeaders, filePackages[cpp.File].PackagePath, file)
			}
			if !present || origin != "module" && origin != "tool" && origin != "generated" || wanted == "" || digest != wanted {
				return nil, fmt.Errorf("actual CPP source differs from exact original input: %s", id)
			}
		}
		if cpp.Inputs["module/"+cpp.File] != input.Sources[cpp.File] {
			return nil, fmt.Errorf("actual CPP proof omits its assembly source")
		}
		if err := ValidateEmptyAssembly(input, cpp, filePackages[cpp.File]); err != nil {
			return nil, err
		}
	}
	for _, file := range input.AsmFiles {
		if !selectedFiles[file] || !consumed[file] {
			return nil, fmt.Errorf("source-required file lacks actual package/CPP consumption: %s", file)
		}
	}
	if len(consumed) != len(input.AsmFiles) {
		return nil, fmt.Errorf("CPP consumption differs from the exact file/profile scope")
	}
	return consumed, nil
}

func ValidatePackageModule(input *ConsumerInput, pkg PackageProof) error {
	if input == nil || pkg.ModulePath != input.Module || pkg.ModuleVersion != input.Version {
		return fmt.Errorf("actual Go package module/version differs from the explicit consumer input")
	}
	if metadata := input.ProxyGoMod; metadata != nil {
		if err := ValidateProxyGoMod(metadata); err != nil {
			return err
		}
		if input.Sources["go.mod"] != "" || input.Module != metadata.Module || input.SourceModule != metadata.Module || input.Version != metadata.Version ||
			pkg.GoModOrigin != metadata.Protocol || pkg.GoModSHA256 != metadata.SHA256 || pkg.GoModSum != metadata.GoModSum {
			return fmt.Errorf("actual package lacks the independent authenticated proxy metadata origin")
		}
	} else if pkg.GoModOrigin != "" || pkg.GoModSHA256 != "" || pkg.GoModSum != "" {
		return fmt.Errorf("package proxy metadata has no independently authenticated source proof")
	}
	module := input.SourceModule
	if module == "" {
		module = input.Module
	}
	if pkg.SourceModule != module || pkg.SourceVersion != input.Version {
		return fmt.Errorf("actual Go replacement source module/version differs from exact original inputs")
	}
	if input.SourceModule != "" {
		if pkg.SourceRole != "module" && pkg.SourceRole != "version_replace" {
			return fmt.Errorf("original exact-module proof cannot be relabeled from main/owned-local sources")
		}
	} else if (pkg.SourceRole != "main" && pkg.SourceRole != "owned_local_replace") ||
		(pkg.SourceRole == "main" && input.Version != "") {
		return fmt.Errorf("explicit own-source consumer lacks an exact main/local role")
	}
	return nil
}
