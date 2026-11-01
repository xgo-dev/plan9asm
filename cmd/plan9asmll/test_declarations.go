package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/asmsig"
	"golang.org/x/tools/go/packages"
)

func (consumer *featureConsumer) bindSignatureSources(pkg *packages.Package, file *plan9asm.File, asm string,
	resolve func(string) string, goarch string, sigs map[string]plan9asm.FuncSig, sizes map[string]int64,
) ([]gotoolprofile.SignatureSource, error) {
	if consumer.Input.SignatureSourceProtocol == "" {
		return nil, nil // Historical consumer inputs never gain a new source role.
	}
	if consumer.Input.SignatureSourceProtocol != gotoolprofile.SignatureSourceProtocol {
		return nil, fmt.Errorf("unknown signature-source protocol")
	}
	requests, err := assemblySignatureRequests(pkg.PkgPath, file, resolve)
	if err != nil {
		return nil, err
	}
	roles, known := make(map[string]string), make(map[string]bool)
	for symbol, requested := range requests {
		role := "asm_fallback"
		_, _, ordinary, err := tryDeclSig(pkg.Types.Scope(), requested.original, symbol,
			linknameRemoteToLocal(pkg.Syntax), goarch, pkg.TypesSizes, strings.HasSuffix(requested.original, "<ABIInternal>"))
		if err != nil {
			return nil, err
		}
		if ordinary {
			role = "ordinary_decl"
			known[symbol] = true
		} else {
			derived, size, found, err := consumer.testDeclarationSignature(pkg, filepath.Dir(asm), requested.original, symbol, goarch)
			if err != nil {
				return nil, err
			}
			if found {
				sigs[symbol], sizes[symbol], role = derived, size, "inpackage_test_decl"
				known[symbol] = true
			}
		}
		// Existing ordinary callee inference is unchanged. Supplemental proof
		// records callees only when an actual missing test declaration was used.
		if !requested.callee || role == "inpackage_test_decl" {
			roles[symbol] = role
		}
	}
	asmsig.RefineTailForwarders(file, sigs, resolve, known)
	var sources []gotoolprofile.SignatureSource
	for symbol, role := range roles {
		layout, err := json.Marshal(sigs[symbol])
		if err != nil {
			return nil, err
		}
		sources = append(sources, gotoolprofile.SignatureSource{
			Symbol: symbol, Role: role, Callee: requests[symbol].callee, ABIInternal: strings.HasSuffix(requests[symbol].original, "<ABIInternal>"), LayoutSHA256: gotoolprofile.SignatureLayoutSHA256(layout),
		})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Symbol < sources[j].Symbol })
	return sources, nil
}

// The same actual export/typecheck proof owns early signature selection and
// final source-role retention. A syntax candidate alone grants no layout.
func (consumer *featureConsumer) testDeclarationSignature(pkg *packages.Package, dir, original, symbol, goarch string) (plan9asm.FuncSig, int64, bool, error) {
	var empty plan9asm.FuncSig
	if consumer.Input.SignatureSourceProtocol == "" {
		return empty, 0, false, nil
	}
	if consumer.Input.SignatureSourceProtocol != gotoolprofile.SignatureSourceProtocol {
		return empty, 0, false, fmt.Errorf("unknown signature-source protocol")
	}
	if strings.Contains(original, "<>") || !strings.HasPrefix(symbol, pkg.PkgPath+".") {
		return empty, 0, false, nil
	}
	name := strings.TrimPrefix(symbol, pkg.PkgPath+".")
	candidate, err := consumer.testDeclarationCandidate(pkg, dir, name)
	if err != nil || !candidate {
		return empty, 0, false, err
	}
	testPkg, err := consumer.loadTestDeclarationPackage(pkg)
	if err != nil {
		return empty, 0, false, err
	}
	decl, err := consumer.typedBodylessTestDeclaration(testPkg, name)
	if err != nil {
		return empty, 0, false, err
	}
	derived, size, found, err := tryDeclSig(testPkg.Types.Scope(), original, symbol,
		linknameRemoteToLocal(testPkg.Syntax), goarch, testPkg.TypesSizes, strings.HasSuffix(original, "<ABIInternal>"))
	if err != nil || !found {
		return empty, 0, false, fmt.Errorf("derive actual test declaration %s: %v (found=%v)", symbol, err, found)
	}
	layout, err := json.Marshal(derived)
	if err != nil {
		return empty, 0, false, err
	}
	decl.Symbol, decl.Layout = symbol, layout
	if err := consumer.retainTestDeclaration(pkg.PkgPath, decl); err != nil {
		return empty, 0, false, err
	}
	return derived, size, true, nil
}

type assemblySignatureRequest struct {
	original string
	callee   bool
}

// Both preflight and final consumption derive requests from the same parsed
// CPP. Neither follows dynamic, foreign, private or offset/alias targets.
func assemblySignatureRequests(packagePath string, file *plan9asm.File, resolve func(string) string) (map[string]assemblySignatureRequest, error) {
	requests := make(map[string]assemblySignatureRequest)
	for _, fn := range file.Funcs {
		symbol := resolve(stripABISuffix(fn.Sym))
		requests[symbol] = assemblySignatureRequest{original: fn.Sym}
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			switch strings.ToUpper(string(ins.Op)) {
			case "CALL", "BL", "JMP", "B", "WASMCALL", "CALLNORESUME":
			default:
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			target := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(target, "(SB)") {
				continue
			}
			base, offset := splitSymPlusOff(strings.TrimSuffix(target, "(SB)"))
			if offset != 0 || strings.Contains(base, "<>") {
				continue
			}
			symbol := resolve(stripABISuffix(base))
			name := strings.TrimPrefix(symbol, packagePath+".")
			if !strings.HasPrefix(symbol, packagePath+".") || !token.IsIdentifier(name) {
				continue
			}
			if previous, exists := requests[symbol]; exists {
				if strings.HasSuffix(previous.original, "<ABIInternal>") != strings.HasSuffix(base, "<ABIInternal>") {
					return nil, fmt.Errorf("test declaration has conflicting source ABI selectors: %s", symbol)
				}
				continue
			}
			requests[symbol] = assemblySignatureRequest{original: base, callee: true}
		}
	}
	return requests, nil
}

// Parsing here decides only whether an authenticated selected test file has
// a candidate name. All types/layouts come from the subsequent actual export
// and typechecked package, never from this syntax prefilter.
func (consumer *featureConsumer) testDeclarationCandidate(pkg *packages.Package, dir, name string) (bool, error) {
	if candidates, present := consumer.TestDeclarationCandidates[pkg.PkgPath]; present {
		issue, found := candidates[name]
		return found, issue
	}
	candidates := make(map[string]error)
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = consumer.Observed.Environment["GOOS"], consumer.Observed.Environment["GOARCH"], false
	ctx.BuildTags, ctx.ToolTags = consumer.Proof.CustomTags, consumer.Observed.ToolTags
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		selected, err := ctx.MatchFile(dir, entry.Name())
		if err != nil {
			return false, err
		}
		if !selected {
			continue
		}
		filename := filepath.Join(dir, entry.Name())
		if _, err := consumer.sourceName(filename); err != nil {
			return false, err
		}
		syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return false, fmt.Errorf("actual selected test declaration syntax: %w", err)
		}
		for _, node := range syntax.Decls {
			decl, ok := node.(*ast.FuncDecl)
			if !ok {
				continue
			}
			declName := decl.Name.Name
			if syntax.Name.Name != pkg.Name || decl.Body != nil || decl.Recv != nil {
				if _, valid := candidates[declName]; !valid {
					candidates[declName] = fmt.Errorf("missing ordinary declaration %s has no in-package bodyless test role", declName)
				}
				continue
			}
			candidates[declName] = nil
		}
	}
	if consumer.TestDeclarationCandidates == nil {
		consumer.TestDeclarationCandidates = make(map[string]map[string]error)
	}
	consumer.TestDeclarationCandidates[pkg.PkgPath] = candidates
	issue, found := candidates[name]
	return found, issue
}

func (consumer *featureConsumer) loadTestDeclarationPackage(ordinary *packages.Package) (*packages.Package, error) {
	if cached := consumer.TestDeclarationPackages[ordinary.PkgPath]; cached != nil {
		return cached, consumer.verifySources()
	}
	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedModule | packages.NeedDeps |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax |
			packages.NeedTypesInfo | packages.NeedCompiledGoFiles | packages.NeedExportFile |
			packages.NeedEmbedFiles | packages.NeedEmbedPatterns,
		Context: consumer.Context, Env: consumer.Env, Dir: consumer.WorkDir, Tests: true,
		BuildFlags: []string{"-mod=mod"},
	}
	if tags := consumer.Proof.CustomTags; len(tags) != 0 {
		config.BuildFlags = append(config.BuildFlags, "-tags="+strings.Join(tags, ","))
	}
	variantID := ordinary.PkgPath + " [" + ordinary.PkgPath + ".test]"
	selectVariant := func(pkgs []*packages.Package) (*packages.Package, error) {
		var selected *packages.Package
		for _, pkg := range pkgs {
			if pkg.ID == variantID {
				if selected != nil {
					return nil, fmt.Errorf("duplicate actual in-package test variant")
				}
				selected = pkg
			}
		}
		if selected == nil || selected.PkgPath != ordinary.PkgPath || selected.Name != ordinary.Name ||
			!reflect.DeepEqual(selected.Module, ordinary.Module) {
			return nil, fmt.Errorf("actual Go did not select the original same-module in-package test variant")
		}
		return selected, nil
	}
	preConfig := *config
	preConfig.Mode &^= packages.NeedTypes | packages.NeedTypesSizes | packages.NeedTypesInfo | packages.NeedSyntax
	before, err := packages.Load(&preConfig, ordinary.PkgPath)
	if err != nil {
		return nil, err
	}
	pre, err := selectVariant(before)
	if err != nil {
		return nil, err
	}
	if err := consumer.bindActualTestDependencies(ordinary, pre); err != nil {
		return nil, err
	}
	allowed := map[string]bool{variantID: true}
	guard, err := consumer.captureTestSourceLoadGuard(consumer.Context, []*packages.Package{pre}, allowed)
	if err != nil {
		return nil, err
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	driverDigest, err := gotoolprofile.FileSHA256(binary)
	if err != nil || driverDigest != consumer.Observed.DriverSHA256 {
		return nil, fmt.Errorf("test declaration driver differs from its actual registered tool: %v", err)
	}
	guard.Sources[binary] = driverDigest
	compileOrigin := consumer.Observed.ToolBinaryOrigins["compile"]
	if !strings.HasPrefix(compileOrigin, "goroot/") {
		return nil, fmt.Errorf("test declaration lacks an actual GOROOT compiler origin")
	}
	compileBinary := filepath.Join(consumer.Root, filepath.FromSlash(strings.TrimPrefix(compileOrigin, "goroot/")))
	guard.Sources[compileBinary] = consumer.Observed.ToolBinarySHA256["compile"]
	if err := verifyGeneratedHeaderCompiler(consumer, binary); err != nil {
		return nil, err
	}
	loaded, err := packages.Load(config, ordinary.PkgPath)
	if err != nil {
		return nil, err
	}
	var diagnostics []string
	packages.Visit(loaded, nil, func(pkg *packages.Package) {
		for _, issue := range pkg.Errors {
			diagnostics = append(diagnostics, issue.Error())
		}
	})
	if len(diagnostics) != 0 {
		sort.Strings(diagnostics)
		return nil, fmt.Errorf("actual same-profile Go test export/typecheck:\n%s", strings.Join(diagnostics, "\n"))
	}
	if err := verifyGeneratedHeaderCompiler(consumer, binary); err != nil {
		return nil, err
	}
	selected, err := selectVariant(loaded)
	if err != nil {
		return nil, err
	}
	if err := consumer.bindActualTestDependencies(ordinary, selected); err != nil {
		return nil, err
	}
	after, err := consumer.captureTestSourceLoadGuard(consumer.Context, []*packages.Package{selected}, allowed)
	if err != nil {
		return nil, err
	}
	after.Sources[binary] = driverDigest
	after.Sources[compileBinary] = consumer.Observed.ToolBinarySHA256["compile"]
	if !reflect.DeepEqual(guard, after) {
		return nil, fmt.Errorf("test declaration dependency/source selection changed during actual export/typecheck")
	}
	if selected.Types == nil || selected.TypesSizes == nil || selected.TypesInfo == nil || selected.ExportFile == "" {
		return nil, fmt.Errorf("actual test variant lacks complete typechecked/export metadata")
	}
	proof := gotoolprofile.TestDeclarationProof{
		Protocol: gotoolprofile.TestDeclarationProtocol, PackagePath: ordinary.PkgPath, VariantID: variantID,
		ProfileID: consumer.ID, CustomTags: consumer.Proof.CustomTags, Target: consumer.Observed.Target,
		GoVersion: consumer.Observed.GoVersion, DriverSHA256: consumer.Observed.DriverSHA256,
		CompileToolSHA256: consumer.Observed.ToolBinarySHA256["compile"], SourceSHA256: make(map[string]string),
		ImportMap: make(map[string]string),
	}
	proof.ExportSHA256, err = gotoolprofile.FileSHA256(selected.ExportFile)
	if err != nil {
		return nil, err
	}
	guard.Sources[selected.ExportFile] = proof.ExportSHA256
	capture := func(files []string, assembly bool) ([]string, error) {
		var result []string
		for _, filename := range files {
			if assembly && filepath.Ext(filename) != ".s" {
				continue
			}
			name, err := consumer.sourceName(filename)
			if err != nil {
				return nil, err
			}
			proof.SourceSHA256[name] = consumer.Input.Sources[name]
			result = append(result, name)
		}
		sort.Strings(result)
		return result, nil
	}
	if proof.GoFiles, err = capture(selected.GoFiles, false); err != nil {
		return nil, err
	}
	if proof.CompiledGoFiles, err = capture(selected.CompiledGoFiles, false); err != nil {
		return nil, err
	}
	if proof.SFiles, err = capture(selected.OtherFiles, true); err != nil {
		return nil, err
	}
	imports, exports, _, sourceGuard, err := generatedHeaderImportsForRole(consumer, selected, true)
	if err != nil {
		return nil, err
	}
	proof.Imports = imports
	for name, dep := range selected.Imports {
		proof.ImportMap[name] = dep.PkgPath
	}
	for name, digest := range exports {
		guard.Sources[name] = digest
	}
	for name, digest := range sourceGuard {
		guard.Sources[name] = digest
	}
	if err := consumer.retainGeneratedGuard(guard.Sources); err != nil {
		return nil, err
	}
	if err := consumer.verifySources(); err != nil {
		return nil, err
	}
	consumer.Proof.TestDeclarations = append(consumer.Proof.TestDeclarations, proof)
	sort.Slice(consumer.Proof.TestDeclarations, func(i, j int) bool {
		return consumer.Proof.TestDeclarations[i].PackagePath < consumer.Proof.TestDeclarations[j].PackagePath
	})
	if consumer.TestDeclarationPackages == nil {
		consumer.TestDeclarationPackages = make(map[string]*packages.Package)
	}
	consumer.TestDeclarationPackages[ordinary.PkgPath] = selected
	return selected, nil
}

func (consumer *featureConsumer) typedBodylessTestDeclaration(pkg *packages.Package, name string) (gotoolprofile.TestDeclaration, error) {
	var result gotoolprofile.TestDeclaration
	object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	if !ok || object.Pkg() != pkg.Types || object.Type() == nil {
		return result, fmt.Errorf("test variant has no actual typed function %s", name)
	}
	for _, syntax := range pkg.Syntax {
		for _, node := range syntax.Decls {
			decl, ok := node.(*ast.FuncDecl)
			if !ok || decl.Name.Name != name {
				continue
			}
			filename := pkg.Fset.PositionFor(decl.Pos(), false).Filename
			file, err := consumer.sourceName(filename)
			if err != nil || !strings.HasSuffix(file, "_test.go") || decl.Body != nil || decl.Recv != nil || pkg.TypesInfo.Defs[decl.Name] != object {
				return result, fmt.Errorf("function %s has no exact selected bodyless test declaration identity: %v", name, err)
			}
			return gotoolprofile.TestDeclaration{File: file, GoType: types.TypeString(object.Type(), func(pkg *types.Package) string { return pkg.Path() })}, nil
		}
	}
	return result, fmt.Errorf("typed test declaration %s was not present in the selected original syntax", name)
}

func (consumer *featureConsumer) retainTestDeclaration(pkg string, decl gotoolprofile.TestDeclaration) error {
	for index := range consumer.Proof.TestDeclarations {
		proof := &consumer.Proof.TestDeclarations[index]
		if proof.PackagePath != pkg {
			continue
		}
		for _, previous := range proof.Declarations {
			if previous.Symbol == decl.Symbol {
				if !reflect.DeepEqual(previous, decl) {
					return fmt.Errorf("test declaration changed across entry/callee consumers: %s", decl.Symbol)
				}
				return nil
			}
		}
		proof.Declarations = append(proof.Declarations, decl)
		sort.Slice(proof.Declarations, func(i, j int) bool { return proof.Declarations[i].Symbol < proof.Declarations[j].Symbol })
		return nil
	}
	return fmt.Errorf("test declaration has no actual stock-Go export proof")
}

func (consumer *featureConsumer) refreshTestDeclarationReferences() {
	for cppIndex := range consumer.Proof.CPP {
		for index := range consumer.Proof.CPP[cppIndex].Signatures {
			source := &consumer.Proof.CPP[cppIndex].Signatures[index]
			if source.Role != "inpackage_test_decl" {
				continue
			}
			for _, proof := range consumer.Proof.TestDeclarations {
				for _, decl := range proof.Declarations {
					if decl.Symbol == source.Symbol {
						source.TestProofSHA256 = gotoolprofile.TestDeclarationSHA256(proof)
					}
				}
			}
		}
	}
}
