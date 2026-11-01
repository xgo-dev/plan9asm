package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"
)

const SignatureSourceProtocol = "actual_go_signature_sources_v1"
const TestDeclarationProtocol = "actual_go_inpackage_test_bodyless_declarations_v1"

// Ordinary assembly selection remains ordinary. This separate witness binds
// only missing declarations to a real stock-Go in-package test export and to
// the complete same-profile typechecked source set. It grants no test execution.
type TestDeclarationProof struct {
	Protocol          string            `json:"protocol"`
	PackagePath       string            `json:"package_path"`
	VariantID         string            `json:"variant_id"`
	ProfileID         string            `json:"profile_id"`
	CustomTags        []string          `json:"custom_tags,omitempty"`
	Target            string            `json:"target"`
	GoVersion         string            `json:"go_version"`
	DriverSHA256      string            `json:"driver_sha256"`
	CompileToolSHA256 string            `json:"compile_tool_sha256"`
	ExportSHA256      string            `json:"export_sha256"`
	GoFiles           []string          `json:"go_files"`
	CompiledGoFiles   []string          `json:"compiled_go_files"`
	SFiles            []string          `json:"s_files"`
	SourceSHA256      map[string]string `json:"source_sha256"`
	Imports           []ImportExport    `json:"imports,omitempty"`
	ImportMap         map[string]string `json:"import_map"`
	Declarations      []TestDeclaration `json:"declarations"`
}

type TestDeclaration struct {
	Symbol string          `json:"symbol"`
	File   string          `json:"file"`
	GoType string          `json:"go_type"`
	Layout json.RawMessage `json:"layout"`
}

// Each actual TEXT and supplemental direct callee records its used signature. A test role
// refers to the shared witness rather than copying its sources for each file.
type SignatureSource struct {
	Symbol          string `json:"symbol"`
	Role            string `json:"role"`
	Callee          bool   `json:"callee,omitempty"`
	ABIInternal     bool   `json:"abi_internal,omitempty"`
	LayoutSHA256    string `json:"layout_sha256"`
	TestProofSHA256 string `json:"test_proof_sha256,omitempty"`
}

func TestDeclarationSHA256(proof TestDeclarationProof) string {
	data, _ := json.Marshal(proof)
	return bytesSHA256(data)
}

// A pretty-printed report may indent RawMessage layout bytes. Hash the same
// canonical token stream used by the typed producer, not JSON presentation.
func SignatureLayoutSHA256(layout json.RawMessage) string {
	var compact bytes.Buffer
	if err := json.Compact(&compact, layout); err != nil {
		return ""
	}
	return bytesSHA256(compact.Bytes())
}

func ValidateSignatureSources(input *ConsumerInput, proof *SelectionProof, tags []string) error {
	if input.SignatureSourceProtocol == "" {
		if proof.SignatureSourceProtocol != "" || len(proof.TestDeclarations) != 0 {
			return fmt.Errorf("legacy selection cannot acquire supplemental declaration evidence")
		}
		for _, cpp := range proof.CPP {
			if len(cpp.Signatures) != 0 || cpp.DataOnlyAssembly != nil {
				return fmt.Errorf("legacy selection cannot acquire signature-source evidence")
			}
		}
		return nil
	}
	if input.SignatureSourceProtocol != SignatureSourceProtocol || proof.SignatureSourceProtocol != SignatureSourceProtocol {
		return fmt.Errorf("missing or changed current signature-source protocol")
	}
	if err := ValidateTestDependencies(input, proof, tags); err != nil {
		return err
	}
	byDigest := make(map[string]TestDeclarationProof)
	declared := make(map[string]TestDeclaration)
	for index, test := range proof.TestDeclarations {
		if index > 0 && test.PackagePath <= proof.TestDeclarations[index-1].PackagePath {
			return fmt.Errorf("noncanonical supplemental declaration package inventory")
		}
		if err := validateTestDeclaration(input, proof.Packages, test, tags); err != nil {
			return err
		}
		digest := TestDeclarationSHA256(test)
		byDigest[digest] = test
		for _, decl := range test.Declarations {
			if _, exists := declared[decl.Symbol]; exists {
				return fmt.Errorf("duplicate supplemental declaration symbol")
			}
			declared[decl.Symbol] = decl
		}
	}
	used, entries := make(map[string]bool), make(map[string]bool)
	bound := make(map[string]SignatureSource)
	for _, cpp := range proof.CPP {
		if cpp.Emission == "data_only" {
			if cpp.DataOnlyAssembly == nil || len(cpp.Signatures) != 0 {
				return fmt.Errorf("data-only assembly requires a native witness and no function signatures")
			}
		} else if cpp.Emission != "symbol_free" && len(cpp.Signatures) == 0 {
			return fmt.Errorf("current assembly consumption lacks signature-source inventory")
		}
		for index, source := range cpp.Signatures {
			if source.Symbol == "" || !discoverySHA256Pattern.MatchString(source.LayoutSHA256) ||
				index > 0 && source.Symbol <= cpp.Signatures[index-1].Symbol {
				return fmt.Errorf("noncanonical or duplicated consumed signature source")
			}
			if source.Callee && source.Role != "inpackage_test_decl" {
				return fmt.Errorf("supplemental callee lacks an actual test declaration")
			}
			if !source.Callee {
				if entries[source.Symbol] {
					return fmt.Errorf("duplicated assembly entry signature source")
				}
				entries[source.Symbol] = true
			}
			comparison := source
			comparison.Callee = false
			if previous, exists := bound[source.Symbol]; exists && previous != comparison {
				return fmt.Errorf("entry/callee signature evidence disagrees across source files")
			}
			bound[source.Symbol] = comparison
			switch source.Role {
			case "ordinary_decl", "asm_fallback":
				if source.TestProofSHA256 != "" {
					return fmt.Errorf("ordinary/fallback signature falsely claims a test role")
				}
			case "inpackage_test_decl":
				test, found := byDigest[source.TestProofSHA256]
				decl, present := declared[source.Symbol]
				want := input.Module
				if path.Dir(cpp.File) != "." {
					want += "/" + path.Dir(cpp.File)
				}
				if !found || !present || test.PackagePath != want || SignatureLayoutSHA256(decl.Layout) != source.LayoutSHA256 {
					return fmt.Errorf("consumed signature differs from its exact test declaration/type/layout")
				}
				used[source.Symbol] = true
			default:
				return fmt.Errorf("unknown signature-source role")
			}
		}
	}
	if len(used) != len(declared) {
		return fmt.Errorf("supplemental test declaration was not consumed by assembly")
	}
	return nil
}

func validateTestDeclaration(input *ConsumerInput, packages []PackageProof, test TestDeclarationProof, tags []string) error {
	observed := input.Observed
	if test.Protocol != TestDeclarationProtocol || test.ProfileID != input.ID || !equalDiscoveryStrings(test.CustomTags, tags) ||
		test.Target != observed.Target || test.GoVersion != observed.GoVersion || test.DriverSHA256 != observed.DriverSHA256 ||
		test.CompileToolSHA256 != observed.ToolBinarySHA256["compile"] || !discoverySHA256Pattern.MatchString(test.ExportSHA256) ||
		test.VariantID != test.PackagePath+" ["+test.PackagePath+".test]" || len(test.Declarations) == 0 {
		return fmt.Errorf("supplemental declaration has a different actual Go test/profile/export/tool role")
	}
	var ordinary *PackageProof
	for index := range packages {
		if packages[index].PackagePath == test.PackagePath {
			ordinary = &packages[index]
		}
	}
	if ordinary == nil || !reflect.DeepEqual(ordinary.SFiles, test.SFiles) || !reflect.DeepEqual(test.GoFiles, test.CompiledGoFiles) {
		return fmt.Errorf("test variant differs from its original ordinary package/assembly identity")
	}
	minor, err := goMinor(observed.GoVersion)
	if err != nil {
		return err
	}
	ctx := build.Default
	ctx.JoinPath = path.Join
	ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = observed.Environment["GOOS"], observed.Environment["GOARCH"], "gc", false
	ctx.BuildTags, ctx.ToolTags, ctx.ReleaseTags = tags, observed.ToolTags, nil
	for version := 1; version <= minor; version++ {
		ctx.ReleaseTags = append(ctx.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	ctx.OpenFile = func(name string) (io.ReadCloser, error) {
		header, found := input.Headers[name]
		if !found {
			return nil, fmt.Errorf("test source has no original selection header")
		}
		return io.NopCloser(strings.NewReader(header)), nil
	}
	ordinaryClause, err := parser.ParseFile(token.NewFileSet(), ordinary.GoFiles[0], input.Headers[ordinary.GoFiles[0]], parser.PackageClauseOnly)
	if err != nil {
		return fmt.Errorf("ordinary package lacks its bound package clause")
	}
	ordinaryName := ordinaryClause.Name.Name
	wantedGo := append([]string(nil), ordinary.GoFiles...)
	dir := path.Dir(ordinary.GoFiles[0])
	for _, name := range input.Directories[dir] {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file := path.Join(dir, name)
		selected, err := ctx.MatchFile(dir, name)
		if err != nil {
			return err
		}
		if !selected {
			continue
		}
		clause, err := parser.ParseFile(token.NewFileSet(), file, input.Headers[file], parser.PackageClauseOnly)
		if err != nil {
			return fmt.Errorf("selected test source has no bound original package clause")
		}
		if clause.Name.Name == ordinaryName {
			wantedGo = append(wantedGo, file)
		}
	}
	sort.Strings(wantedGo)
	if !reflect.DeepEqual(wantedGo, test.GoFiles) {
		return fmt.Errorf("test variant omits/adds actual original same-package Go sources")
	}
	sources, testFiles := make(map[string]string), make(map[string]bool)
	for _, files := range [][]string{test.GoFiles, test.SFiles} {
		if len(files) == 0 || !sort.StringsAreSorted(files) {
			return fmt.Errorf("test declaration lacks canonical actual selected source")
		}
		for index, name := range files {
			if index > 0 && name == files[index-1] || input.Sources[name] == "" || test.SourceSHA256[name] != input.Sources[name] {
				return fmt.Errorf("test declaration source differs from original ZIP bytes")
			}
			sources[name] = test.SourceSHA256[name]
			if path.Ext(name) != ".go" {
				continue
			}
			selected, err := ctx.MatchFile(path.Dir(name), path.Base(name))
			clause, parseErr := parser.ParseFile(token.NewFileSet(), name, input.Headers[name], parser.PackageClauseOnly)
			want := input.Module
			if path.Dir(name) != "." {
				want += "/" + path.Dir(name)
			}
			if err != nil || !selected || parseErr != nil || clause.Name.Name != ordinaryName || want != test.PackagePath {
				return fmt.Errorf("test declaration contradicts its actual same-package target selection")
			}
			if strings.HasSuffix(name, "_test.go") {
				testFiles[name] = true
			}
		}
	}
	if len(testFiles) == 0 || !reflect.DeepEqual(sources, test.SourceSHA256) {
		return fmt.Errorf("test declaration has missing/extra original source inputs")
	}
	for _, name := range ordinary.GoFiles {
		if sources[name] != ordinary.SourceSHA256[name] {
			return fmt.Errorf("test variant omits an ordinary selected source")
		}
	}
	for index, decl := range test.Declarations {
		if !testFiles[decl.File] || !strings.HasPrefix(decl.Symbol, test.PackagePath+".") || decl.GoType == "" ||
			!json.Valid(decl.Layout) || index > 0 && decl.Symbol <= test.Declarations[index-1].Symbol {
			return fmt.Errorf("invalid or duplicated typed bodyless test declaration")
		}
	}
	usedImports := make(map[string]string)
	if test.ImportMap["unsafe"] != "" {
		if test.ImportMap["unsafe"] != "unsafe" {
			return fmt.Errorf("test builtin unsafe import has an invented export")
		}
		usedImports["unsafe"] = "unsafe"
	}
	for index, imported := range test.Imports {
		if imported.ImportPath == "" || imported.PackagePath == "" || !discoverySHA256Pattern.MatchString(imported.ExportSHA256) || len(imported.GoSHA256) == 0 ||
			index > 0 && imported.ImportPath <= test.Imports[index-1].ImportPath {
			return fmt.Errorf("test typecheck lacks canonical dependency export/source roles")
		}
		if test.ImportMap[imported.ImportPath] != imported.PackagePath {
			return fmt.Errorf("test dependency export differs from the actual ImportMap")
		}
		if err := validateImportedSource(input, *ordinary, imported); err != nil {
			return err
		}
		usedImports[imported.ImportPath] = imported.PackagePath
	}
	if test.ImportMap == nil || !reflect.DeepEqual(test.ImportMap, usedImports) {
		return fmt.Errorf("test typecheck omits actual dependency exports")
	}
	return nil
}
