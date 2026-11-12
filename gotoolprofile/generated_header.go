package gotoolprofile

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goasmheader"
)

const GeneratedHeaderProtocol = "actual_go_asmhdr_full_definitions_v1"
const MetadataProtocol = "actual_go_cpu_profile_metadata_v2"

// A compiler package can legitimately emit more than 4096 definitions. Bound
// its full textual input and canonical output by bytes, not declaration count.
const generatedHeaderByteLimit = goasmheader.ByteLimit

// MetadataProof is deliberately not a SelectionProof. It proves generated
// layout inputs, not successful assembly translation or LLVM object emission.
type MetadataProof struct {
	Protocol     string                   `json:"protocol"`
	ProfileID    string                   `json:"profile_id"`
	CustomTags   []string                 `json:"custom_tags,omitempty"`
	Packages     []PackageProof           `json:"packages"`
	Headers      []GeneratedHeaderProof   `json:"headers"`
	Dependencies *OrdinaryDependencyProof `json:"ordinary_dependencies"`
}

type GeneratedHeaderProof struct {
	Protocol          string            `json:"protocol"`
	PackagePath       string            `json:"package_path"`
	ProfileID         string            `json:"profile_id"`
	Target            string            `json:"target"`
	GoVersion         string            `json:"go_version"`
	LanguageVersion   string            `json:"language_version"`
	CompileToolSHA256 string            `json:"compile_tool_sha256"`
	HeaderSHA256      string            `json:"header_sha256"`
	ObjectSHA256      string            `json:"object_sha256"`
	DefinitionsSHA256 string            `json:"definitions_sha256"`
	Definitions       map[string]string `json:"definitions"`
	CompiledGoSHA256  map[string]string `json:"compiled_go_sha256"`
	ImportMap         map[string]string `json:"import_map"`
	Imports           []ImportExport    `json:"imports,omitempty"`
}

// ImportExport records the actual same-profile dependency export used by the
// compiler. ImportPath is the source spelling; PackagePath is its ImportMap
// destination. Physical archive paths are private, never portable identities.
type ImportExport struct {
	ImportPath    string            `json:"import_path"`
	PackagePath   string            `json:"package_path"`
	ModulePath    string            `json:"module_path,omitempty"`
	Version       string            `json:"version,omitempty"`
	SourceModule  string            `json:"source_module,omitempty"`
	SourceVersion string            `json:"source_version,omitempty"`
	SourceRole    string            `json:"source_role"`
	ExportSHA256  string            `json:"export_sha256"`
	GoSHA256      map[string]string `json:"compiled_go_sha256"`
}

// HeaderDefinitions accepts only the complete object-like definitions emitted
// by cmd/compile and the selected-types emitter. Unknown controls, duplicate
// names and continuations fail instead of inventing values or presence.
func HeaderDefinitions(header []byte) (map[string]string, error) {
	return goasmheader.Definitions(header)
}

func generatedHeaderDefinitionSize(name, value string) (int, error) {
	return goasmheader.DefinitionSize(name, value)
}

func generatedHeaderDefinitionsSize(definitions map[string]string) (int, error) {
	return goasmheader.DefinitionsSize(definitions)
}

func HeaderDefinitionSHA256(definitions map[string]string) string {
	return goasmheader.SHA256(definitions)
}

// ValidateMetadata is an offline replay of frozen source/tool provenance. The
// producer and consumer must separately compare actual -asmhdr definitions
// with all selected Go types; a recorded SHA is not a ZIP membership witness.
func ValidateMetadata(input *ConsumerInput, proof *MetadataProof, tags []string) error {
	if input == nil || input.Protocol != ConsumerProtocol || input.ID != ProfileID(input.Observed) {
		return fmt.Errorf("missing canonical generated-header feature input")
	}
	if err := Validate(input.Observed); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != MetadataProtocol || proof.ProfileID != input.ID || !equalDiscoveryStrings(proof.CustomTags, tags) || len(proof.Packages) == 0 {
		return fmt.Errorf("metadata query differs from its source/profile/tag scope")
	}
	selected, _, err := validatePackageSelection(input, proof.Packages, tags)
	if err != nil {
		return err
	}
	for _, file := range input.AsmFiles {
		if !selected[file] {
			return fmt.Errorf("metadata query did not load its source-required assembly package")
		}
	}
	if len(proof.Headers) != len(proof.Packages) {
		return fmt.Errorf("metadata query lacks complete per-package generated headers")
	}
	seen := make(map[string]bool)
	for _, header := range proof.Headers {
		var pkg *PackageProof
		for index := range proof.Packages {
			if proof.Packages[index].PackagePath == header.PackagePath {
				pkg = &proof.Packages[index]
			}
		}
		if pkg == nil || seen[header.PackagePath] {
			return fmt.Errorf("duplicate or unselected generated-header package")
		}
		seen[header.PackagePath] = true
		if err := ValidateGeneratedHeader(input, header, *pkg); err != nil {
			return err
		}
	}
	return ValidateOrdinaryDependencies(input, proof, tags)
}

func ValidateGeneratedHeader(input *ConsumerInput, proof GeneratedHeaderProof, pkg PackageProof) error {
	if input == nil || input.Observed == nil {
		return fmt.Errorf("missing generated-header source context")
	}
	return validateGeneratedHeaderContext(input, proof, pkg, generatedHeaderValidationContext{
		protocol: GeneratedHeaderProtocol, id: input.ID, observed: input.Observed,
		validateMacros: func() error { return ValidateOrdinaryAssemblerMacros(pkg.Macros, input.Observed, pkg.PackagePath) },
	})
}

// Different source/profile protocols share layout and import validation, not
// their identity. The public ordinary entry point always supplies its own
// original protocol, observation and ordinary assembler registration.
type generatedHeaderValidationContext struct {
	protocol       string
	id             string
	observed       *Observation
	validateMacros func() error
}

func validateGeneratedHeaderContext(input *ConsumerInput, proof GeneratedHeaderProof, pkg PackageProof, context generatedHeaderValidationContext) error {
	if input == nil || context.observed == nil || context.validateMacros == nil || proof.Protocol != context.protocol ||
		proof.PackagePath != pkg.PackagePath || proof.ProfileID != context.id ||
		proof.Target != context.observed.Target || proof.GoVersion != context.observed.GoVersion ||
		proof.CompileToolSHA256 != context.observed.ToolBinarySHA256["compile"] ||
		!discoverySHA256Pattern.MatchString(proof.HeaderSHA256) || !discoverySHA256Pattern.MatchString(proof.ObjectSHA256) ||
		proof.Definitions == nil {
		return fmt.Errorf("generated header differs from its actual compiler/package/profile scope")
	}
	if _, err := generatedHeaderDefinitionsSize(proof.Definitions); err != nil {
		return err
	}
	if proof.DefinitionsSHA256 != HeaderDefinitionSHA256(proof.Definitions) {
		return fmt.Errorf("generated header differs from its complete definition digest")
	}
	if err := ValidatePackageModule(input, pkg); err != nil {
		return err
	}
	if err := context.validateMacros(); err != nil {
		return err
	}
	languageMinor, languageErr := goMinor(proof.LanguageVersion)
	if proof.LanguageVersion == "go1" {
		languageMinor, languageErr = 0, nil
	}
	toolMinor, toolErr := goMinor(context.observed.GoVersion)
	if languageErr != nil || toolErr != nil || languageMinor > toolMinor || strings.Count(proof.LanguageVersion, ".") > 1 {
		return fmt.Errorf("generated header lacks its actual supported module language version")
	}
	if len(pkg.CompiledGoFiles) == 0 || len(proof.CompiledGoSHA256) != len(pkg.CompiledGoFiles) {
		return fmt.Errorf("generated header omits selected compiler Go inputs")
	}
	for _, file := range pkg.CompiledGoFiles {
		if proof.CompiledGoSHA256[file] != pkg.SourceSHA256[file] || proof.CompiledGoSHA256[file] != input.Sources[file] {
			return fmt.Errorf("generated header has different selected Go bytes")
		}
	}
	if len(proof.Imports) > 4096 || !sort.SliceIsSorted(proof.Imports, func(i, j int) bool { return proof.Imports[i].ImportPath < proof.Imports[j].ImportPath }) {
		return fmt.Errorf("generated header exceeds canonical import bounds")
	}
	if proof.ImportMap == nil || len(proof.ImportMap) > 4096 {
		return fmt.Errorf("generated header lacks its complete same-load ImportMap")
	}
	usedImports := map[string]string{}
	if proof.ImportMap["unsafe"] != "" {
		if proof.ImportMap["unsafe"] != "unsafe" {
			return fmt.Errorf("builtin unsafe import cannot use an invented export")
		}
		usedImports["unsafe"] = "unsafe"
	}
	for index, imported := range proof.Imports {
		if imported.ImportPath == "" || imported.PackagePath == "" || imported.ImportPath == "unsafe" ||
			strings.ContainsAny(imported.ImportPath+imported.PackagePath, "\r\n=\\") ||
			index > 0 && imported.ImportPath == proof.Imports[index-1].ImportPath ||
			!discoverySHA256Pattern.MatchString(imported.ExportSHA256) || len(imported.GoSHA256) == 0 {
			return fmt.Errorf("generated header lacks a canonical actual dependency export")
		}
		if proof.ImportMap[imported.ImportPath] != imported.PackagePath {
			return fmt.Errorf("generated-header export differs from the actual ImportMap")
		}
		usedImports[imported.ImportPath] = imported.PackagePath
		if err := validateImportedSource(input, pkg, imported); err != nil {
			return err
		}
	}
	if len(usedImports) != len(proof.ImportMap) {
		return fmt.Errorf("generated header omits actual dependency exports")
	}
	return nil
}

// Generated headers and supplemental test declarations authenticate the same
// concrete compiler dependency exports and source/module roles.
func validateImportedSource(input *ConsumerInput, pkg PackageProof, imported ImportExport) error {
	packageDir := strings.TrimPrefix(imported.PackagePath, imported.ModulePath)
	packageDir = strings.TrimPrefix(packageDir, "/")
	if packageDir == "" {
		packageDir = "."
	}
	if imported.SourceRole == "stdlib" {
		if imported.ModulePath != "" || imported.Version != "" || imported.SourceModule != "" || imported.SourceVersion != "" || strings.Contains(strings.Split(imported.PackagePath, "/")[0], ".") {
			return fmt.Errorf("stdlib dependency was relabeled as an external module")
		}
	} else {
		if imported.ModulePath == "" || imported.SourceModule == "" ||
			imported.PackagePath != imported.ModulePath && !strings.HasPrefix(imported.PackagePath, imported.ModulePath+"/") ||
			(imported.SourceRole != "module" && imported.SourceRole != "main" && imported.SourceRole != "owned_local_replace" && imported.SourceRole != "version_replace") {
			return fmt.Errorf("dependency export lacks its actual module/source role")
		}
	}
	for file, digest := range imported.GoSHA256 {
		if path.Clean(file) != file || file == "." || path.IsAbs(file) || strings.HasPrefix(file, "../") || strings.Contains(file, "\\") || path.Dir(file) != packageDir || !discoverySHA256Pattern.MatchString(digest) {
			return fmt.Errorf("dependency export has an unsafe or missing source digest")
		}
		if imported.ModulePath == input.Module && (imported.Version != input.Version || imported.SourceModule != pkg.SourceModule || imported.SourceVersion != pkg.SourceVersion || imported.SourceRole != pkg.SourceRole || digest != input.Sources[file]) {
			return fmt.Errorf("same-module dependency export differs from exact pre-load source inputs")
		}
	}
	return nil
}
