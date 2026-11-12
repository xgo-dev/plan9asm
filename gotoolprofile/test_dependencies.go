package gotoolprofile

import (
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const SignatureQueryProtocol = "actual_go_missing_signature_query_v1"
const TestDependencyProtocol = "actual_go_test_declaration_source_closure_v3"

// A query binds only ordinary types and parsed CPP references. No test export,
// signature layout, LLVM output or translation outcome is asserted here.
type SignatureQueryProof struct {
	Protocol  string             `json:"protocol"`
	Selection *SelectionProof    `json:"selection"`
	Requests  []SignatureRequest `json:"requests"`
}

type SignatureRequest struct {
	File        string `json:"file"`
	Symbol      string `json:"symbol"`
	Callee      bool   `json:"callee,omitempty"`
	ABIInternal bool   `json:"abi_internal,omitempty"`
}

// Source-only packages never enter the ordinary Go/ASM package inventory.
// ImportMap retains all edges, including those leaving this exact module.
type SourcePackageProof struct {
	Package   PackageProof      `json:"package"`
	VariantID string            `json:"variant_id"`
	ImportMap map[string]string `json:"import_map"`
	// Empty only for this candidate's authenticated original module. Foreign
	// roots are classified by actual Go Module/Replace, never import prefixes.
	SourceRootID string              `json:"source_root_id,omitempty"`
	ExportSHA256 string              `json:"export_sha256,omitempty"`
	Builtin      string              `json:"builtin,omitempty"`
	Embed        *TestEmbedSelection `json:"embed_selection"`
}

// Historical test callers retain their name; this record alone grants no
// test-variant, embed or compiler permission. The enclosing role validates it.
type TestSourcePackage = SourcePackageProof

type TestDependencyProof struct {
	Protocol         string               `json:"protocol"`
	Query            *SignatureQueryProof `json:"query"`
	Packages         []TestSourcePackage  `json:"source_packages"`
	ExternalPackages []TestSourcePackage  `json:"external_source_packages,omitempty"`
	SourceModules    []TestModuleSource   `json:"dependency_source_roots,omitempty"`
}

// This authenticates source-only preload metadata, never a type/layout,
// translated instruction or LLVM object. Final consumption remains separate.
func ValidateTestDependencyPreload(input *ConsumerInput, dependency *TestDependencyProof, tags []string) error {
	if dependency == nil || dependency.Protocol != TestDependencyProtocol || dependency.Query == nil ||
		len(dependency.Query.Requests) == 0 || len(dependency.Packages) == 0 || len(dependency.Packages) > 4096 {
		return fmt.Errorf("missing bounded test-declaration source-only preload")
	}
	if err := ValidateSignatureQuery(input, dependency.Query, tags); err != nil {
		return err
	}
	roots := make(map[string]bool)
	for _, request := range dependency.Query.Requests {
		for _, pkg := range dependency.Query.Selection.Packages {
			if containsString(pkg.SFiles, request.File) {
				roots[pkg.PackagePath] = true
			}
		}
	}
	return validateTestSourceClosure(input, dependency, roots, tags)
}

func ValidateSignatureQuery(input *ConsumerInput, query *SignatureQueryProof, tags []string) error {
	if input == nil || input.Protocol != ConsumerProtocol || input.Observed == nil || input.ID != ProfileID(input.Observed) ||
		input.SignatureSourceProtocol != SignatureSourceProtocol || query == nil || query.Protocol != SignatureQueryProtocol || query.Selection == nil {
		return fmt.Errorf("missing actual missing-signature preflight")
	}
	proof := query.Selection
	if proof.Protocol != ConsumerProtocol || proof.SignatureSourceProtocol != input.SignatureSourceProtocol || proof.TestDependencySourceProtocol != input.TestDependencySourceProtocol ||
		proof.ProfileID != input.ID || !equalDiscoveryStrings(proof.CustomTags, tags) ||
		len(proof.Outputs) != 0 || len(proof.TestDeclarations) != 0 || proof.TestDependencies != nil ||
		!reflect.DeepEqual(input.RegisteredAsmFiles, proof.RegisteredAsmFiles) {
		return fmt.Errorf("signature preflight has a different source/profile role or claims translation")
	}
	if err := Validate(input.Observed); err != nil {
		return err
	}
	selected, packages, err := validatePackageSelection(input, proof.Packages, tags)
	if err != nil {
		return err
	}
	if input.GeneratedHeaders != nil || proof.GeneratedHeaders != nil {
		if err := ValidateGeneratedHeaderAgreement(input, input.GeneratedHeaders, proof.GeneratedHeaders, tags); err != nil {
			return err
		}
	}
	if _, err := validateCPPConsumption(input, proof, selected, packages); err != nil {
		return err
	}
	seen := make(map[string]bool)
	previous := ""
	for _, request := range query.Requests {
		key := request.File + "\x00" + request.Symbol
		pkg, found := packages[request.File]
		if !found || !strings.HasPrefix(request.Symbol, pkg.PackagePath+".") || seen[key] || key <= previous {
			return fmt.Errorf("signature query has an unbound/duplicate/noncanonical source reference")
		}
		seen[key], previous = true, key
	}
	for _, cpp := range proof.CPP {
		if len(cpp.Signatures) != 0 {
			return fmt.Errorf("preflight cannot claim final typed signature consumption")
		}
	}
	return nil
}

func ValidateTestDependencies(input *ConsumerInput, proof *SelectionProof, tags []string) error {
	if input.TestDependencySourceProtocol == "" {
		if proof.TestDependencySourceProtocol != "" || input.TestDependencies != nil || proof.TestDependencies != nil {
			return fmt.Errorf("historical signature sources cannot acquire test dependency closure evidence")
		}
		return nil
	}
	if input.TestDependencySourceProtocol != TestDependencyProtocol || proof.TestDependencySourceProtocol != TestDependencyProtocol {
		return fmt.Errorf("missing/changed current test dependency source protocol")
	}
	if input.TestDependencies == nil && proof.TestDependencies == nil {
		if len(proof.TestDeclarations) != 0 {
			return fmt.Errorf("actual test declaration lacks its pre-load missing-reference/source closure")
		}
		return nil // No extra source closure is needed for an ordinary declaration.
	}
	dependency := input.TestDependencies
	if dependency == nil || !reflect.DeepEqual(dependency, proof.TestDependencies) || dependency.Protocol != TestDependencyProtocol ||
		dependency.Query == nil || len(dependency.Query.Requests) == 0 || len(dependency.Packages) == 0 || len(dependency.Packages) > 4096 {
		return fmt.Errorf("test dependency source-only contract is missing/changed/unconsumed")
	}
	queryInput := *input
	queryInput.TestDependencies = nil
	if err := ValidateTestDependencyPreload(&queryInput, dependency, tags); err != nil {
		return err
	}
	if !reflect.DeepEqual(dependency.Query.Selection.Packages, proof.Packages) {
		return fmt.Errorf("signature preflight and final ordinary package identity disagree")
	}
	byFile := make(map[string]CPPProof)
	for _, cpp := range dependency.Query.Selection.CPP {
		byFile[cpp.File] = cpp
	}
	consumed := make(map[string]SignatureRequest)
	for _, cpp := range proof.CPP {
		previous, found := byFile[cpp.File]
		if !found || previous.ExpandedSHA256 != cpp.ExpandedSHA256 || previous.TypedExpandedSHA256 != cpp.TypedExpandedSHA256 ||
			!reflect.DeepEqual(previous.Inputs, cpp.Inputs) || previous.Emission != cpp.Emission {
			return fmt.Errorf("test signature preflight differs from actual normalized CPP consumption")
		}
		if !reflect.DeepEqual(previous.EmptyAssembly, cpp.EmptyAssembly) ||
			!reflect.DeepEqual(previous.DataOnlyAssembly, cpp.DataOnlyAssembly) {
			return fmt.Errorf("test signature preflight differs from actual native assembly evidence")
		}
		for _, source := range cpp.Signatures {
			if source.Role == "inpackage_test_decl" {
				key := cpp.File + "\x00" + source.Symbol
				consumed[key] = SignatureRequest{File: cpp.File, Symbol: source.Symbol, Callee: source.Callee, ABIInternal: source.ABIInternal}
			}
		}
	}
	if len(consumed) != len(dependency.Query.Requests) {
		return fmt.Errorf("test query contains missing/extra final signature references")
	}
	for _, request := range dependency.Query.Requests {
		actual, found := consumed[request.File+"\x00"+request.Symbol]
		if !found || actual != request {
			return fmt.Errorf("test query entry/callee reference was not consumed")
		}
	}
	for _, test := range proof.TestDeclarations {
		var root *TestSourcePackage
		for index := range dependency.Packages {
			if dependency.Packages[index].Package.PackagePath == test.PackagePath {
				root = &dependency.Packages[index]
			}
		}
		if root == nil || !reflect.DeepEqual(root.ImportMap, test.ImportMap) || !reflect.DeepEqual(root.Package.SourceSHA256, test.SourceSHA256) {
			return fmt.Errorf("actual test export differs from its complete pre-load source/ImportMap role")
		}
		for _, imported := range test.Imports {
			var selected *TestSourcePackage
			all := append(append([]TestSourcePackage(nil), dependency.Packages...), dependency.ExternalPackages...)
			for index := range all {
				if all[index].Package.PackagePath == imported.PackagePath {
					selected = &all[index]
				}
			}
			wanted := make(map[string]string)
			if selected != nil {
				for _, file := range selected.Package.CompiledGoFiles {
					wanted[file] = selected.Package.SourceSHA256[file]
				}
			}
			if selected == nil || !reflect.DeepEqual(wanted, imported.GoSHA256) ||
				selected.Package.ModulePath != imported.ModulePath || selected.Package.ModuleVersion != imported.Version ||
				selected.Package.SourceModule != imported.SourceModule || selected.Package.SourceVersion != imported.SourceVersion ||
				selected.Package.SourceRole != imported.SourceRole ||
				selected.SourceRootID != "" && selected.ExportSHA256 != imported.ExportSHA256 {
				return fmt.Errorf("actual test export dependency differs from its complete source/module/export closure")
			}
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func testSourceOnlyZeroAssembly(view *ConsumerInput, pkg PackageProof, dir string) bool {
	if len(pkg.SFiles) == 0 {
		return false
	}
	empty := bytesSHA256(nil)
	for _, file := range pkg.SFiles {
		header, present := view.Headers[file]
		if path.Dir(file) != dir || !containsString(view.Directories[dir], path.Base(file)) ||
			view.Sources[file] != empty || pkg.SourceSHA256[file] != empty ||
			!present || header != "" {
			return false
		}
	}
	// Zero bytes cannot replace an instruction/object scope. Keep the full
	// actual SFiles list: MatchFile, source membership and the independent
	// consumer still verify it below. Nonzero symbol-free units are not zero.
	return true
}

func validateTestSourceClosure(input *ConsumerInput, dependency *TestDependencyProof, roots map[string]bool, tags []string) error {
	modules, err := testDependencySourceModules(input, dependency)
	if err != nil {
		return err
	}
	return validatePackageSourceClosure(input, dependency.Packages, dependency.ExternalPackages, modules, roots, tags, true)
}

// The bool is private and fixed by two distinct role validators. Shared source
// selection does not move permission from the test role to the ordinary role.
func validatePackageSourceClosure(input *ConsumerInput, local, external []SourcePackageProof, modules map[string]TestModuleSource, roots map[string]bool, tags []string, testVariants bool) error {
	minor, err := goMinor(input.Observed.GoVersion)
	if err != nil {
		return err
	}
	ctx := build.Default
	ctx.JoinPath = path.Join // Original-source maps use portable module-relative keys.
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = input.Observed.Environment["GOOS"], input.Observed.Environment["GOARCH"], "gc", false
	ctx.BuildTags, ctx.ToolTags, ctx.ReleaseTags = tags, input.Observed.ToolTags, nil
	for version := 1; version <= minor; version++ {
		ctx.ReleaseTags = append(ctx.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	packages := append(append([]SourcePackageProof(nil), local...), external...)
	if len(packages) > 4096 {
		return fmt.Errorf("test dependency package closure exceeds its bounded scope")
	}
	byPath := make(map[string]TestSourcePackage)
	usedModules := make(map[string]map[string]bool)
	for index, source := range packages {
		pkg := source.Package
		if (index < len(local)) != (source.SourceRootID == "") {
			return fmt.Errorf("test dependency changed original versus external package source roles")
		}
		view, err := testDependencyPackageInput(input, source, modules)
		if err != nil {
			return err
		}
		ctx.OpenFile = func(name string) (io.ReadCloser, error) {
			header, found := view.Headers[name]
			if !found {
				return nil, fmt.Errorf("test dependency source lacks its original selection/import header")
			}
			return io.NopCloser(strings.NewReader(header)), nil
		}
		start := 0
		if index >= len(local) {
			start = len(local)
		}
		builtin := source.Builtin == "go_typechecker_unsafe_v1"
		if index > start && pkg.PackagePath <= packages[index-1].Package.PackagePath || byPath[pkg.PackagePath].VariantID != "" ||
			pkg.Macros != nil || source.ImportMap == nil ||
			!builtin && !reflect.DeepEqual(pkg.GoFiles, pkg.CompiledGoFiles) || len(pkg.GoFiles) == 0 || !sort.StringsAreSorted(pkg.GoFiles) {
			return fmt.Errorf("noncanonical actual test source-only package")
		}
		wantedID := pkg.PackagePath
		if testVariants && roots[pkg.PackagePath] {
			wantedID += " [" + pkg.PackagePath + ".test]"
		}
		if source.VariantID != wantedID {
			return fmt.Errorf("test dependency has a different actual package/test-variant identity")
		}
		dir := strings.TrimPrefix(strings.TrimPrefix(pkg.PackagePath, pkg.ModulePath), "/")
		if dir == "" {
			dir = "."
		}
		if testVariants && source.SourceRootID == "" && !roots[pkg.PackagePath] && len(pkg.SFiles) != 0 &&
			!containsString(input.OrdinaryAsmPackages, dir) && !testSourceOnlyZeroAssembly(view, pkg, dir) {
			return fmt.Errorf("source-only test dependency cannot replace another assembly translation scope: "+
				"package=%s module=%s@%s source_root=%q directory=%s selected_asm=%q ordinary_asm_packages=%q target=%s profile=%s tags=%q",
				pkg.PackagePath, pkg.ModulePath, pkg.ModuleVersion, source.SourceRootID, dir,
				pkg.SFiles, input.OrdinaryAsmPackages, input.Observed.Target, input.ID, tags)
		}
		if view.Directories[dir] == nil {
			return fmt.Errorf("test dependency lacks a complete original source directory")
		}
		embedDirectories, err := ValidateTestEmbedSelection(pkg, source.Embed, view)
		if err != nil {
			return err
		}
		if source.SourceRootID != "" {
			if usedModules[source.SourceRootID] == nil {
				usedModules[source.SourceRootID] = make(map[string]bool)
			}
			for ancestor := dir; ; ancestor = path.Dir(ancestor) {
				usedModules[source.SourceRootID][ancestor] = true
				if ancestor == "." {
					break
				}
			}
			for directory := range embedDirectories {
				usedModules[source.SourceRootID][directory] = true
			}
		}
		clause, err := parser.ParseFile(token.NewFileSet(), pkg.GoFiles[0], view.Headers[pkg.GoFiles[0]], parser.PackageClauseOnly)
		if err != nil {
			return fmt.Errorf("test dependency lacks a bound package clause")
		}
		var wantedGo, wantedAsm []string
		imports := make(map[string]bool)
		for _, name := range view.Directories[dir] {
			file := path.Join(dir, name)
			if path.Ext(name) != ".go" && path.Ext(name) != ".s" || strings.HasSuffix(name, "_test.go") && (!testVariants || !roots[pkg.PackagePath]) {
				continue
			}
			selected, err := ctx.MatchFile(dir, name)
			if err != nil {
				return err
			}
			if !selected {
				continue
			}
			if path.Ext(name) == ".s" {
				wantedAsm = append(wantedAsm, file)
				continue
			}
			syntax, err := parser.ParseFile(token.NewFileSet(), file, view.Headers[file], parser.ImportsOnly)
			if err != nil {
				return fmt.Errorf("test dependency has an unbound source/import header")
			}
			if syntax.Name.Name != clause.Name.Name {
				if strings.HasSuffix(name, "_test.go") && syntax.Name.Name == clause.Name.Name+"_test" {
					continue // External tests never acquire the in-package role.
				}
				return fmt.Errorf("test dependency changed its exact package identity")
			}
			wantedGo = append(wantedGo, file)
			for _, imported := range syntax.Imports {
				spelling, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return fmt.Errorf("test dependency has an invalid original import spelling")
				}
				if spelling == "C" {
					return fmt.Errorf("source-only test dependency requires a proven non-cgo source role")
				}
				imports[spelling] = true
			}
		}
		sort.Strings(wantedGo)
		sort.Strings(wantedAsm)
		if !reflect.DeepEqual(wantedGo, pkg.GoFiles) || !reflect.DeepEqual(wantedAsm, pkg.SFiles) || len(imports) != len(source.ImportMap) {
			return fmt.Errorf("test dependency source/ImportMap inventory contradicts original target/tag selection")
		}
		for spelling := range imports {
			if source.ImportMap[spelling] == "" {
				return fmt.Errorf("test dependency omits an actual original source import")
			}
		}
		used := make(map[string]string)
		for _, files := range [][]string{pkg.GoFiles, pkg.SFiles} {
			for n, file := range files {
				if n > 0 && file <= files[n-1] || path.Dir(file) != dir || view.Sources[file] == "" || view.Sources[file] != pkg.SourceSHA256[file] {
					return fmt.Errorf("test dependency source differs from exact pre-load bytes")
				}
				used[file] = view.Sources[file]
			}
		}
		if !reflect.DeepEqual(used, pkg.SourceSHA256) {
			return fmt.Errorf("test dependency omitted/added source consumption")
		}
		byPath[pkg.PackagePath] = source
	}
	if len(usedModules) != len(modules) {
		return fmt.Errorf("test dependency contains an unrelated source-module root")
	}
	for id, module := range modules {
		for dir := range module.Directories {
			if !usedModules[id][dir] {
				return fmt.Errorf("test dependency contains an unrelated source-module directory")
			}
		}
	}
	visited := make(map[string]bool)
	var visit func(string) error
	visit = func(name string) error {
		if visited[name] {
			return nil
		}
		source, found := byPath[name]
		if !found {
			return fmt.Errorf("actual test dependency module/import closure is truncated: %s", name)
		}
		visited[name] = true
		for spelling, destination := range source.ImportMap {
			if spelling == "" || destination == "" {
				return fmt.Errorf("test dependency has an incomplete actual ImportMap")
			}
			if err := visit(destination); err != nil {
				return err
			}
		}
		return nil
	}
	for root := range roots {
		if err := visit(root); err != nil {
			return err
		}
	}
	if len(visited) != len(byPath) {
		return fmt.Errorf("test source-only inventory contains an unrelated package")
	}
	return nil
}
