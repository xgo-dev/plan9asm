package gotoolprofile

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

const InstrumentationMetadataProtocol = "actual_go_instrumentation_metadata_v1"
const InstrumentationGeneratedHeaderProtocol = "actual_go_instrumentation_asmhdr_v1"

// InstrumentationMetadataProof is a query-only result. It binds the actual
// same-mode original selection, dependency exports and complete native header.
// It never certifies CPP, LLVM, C/SDK, sanitizers, final linking or execution.
type InstrumentationMetadataProof struct {
	Protocol               string                                `json:"protocol"`
	ModeProfileID          string                                `json:"mode_profile_id"`
	InputSHA256            string                                `json:"input_sha256"`
	Selection              *InstrumentationPackageSelectionProof `json:"selection"`
	Headers                []InstrumentationGeneratedHeader      `json:"headers"`
	Dependencies           []InstrumentationDependencyExport     `json:"dependencies"`
	Declarations           []InstrumentationDeclarationProof     `json:"actual_go_declarations"`
	OriginalExportSHA256   string                                `json:"original_export_sha256"`
	InvocationConfigSHA256 map[string]string                     `json:"invocation_config_sha256"`
	LoadBuildFlags         []string                              `json:"load_build_flags"`
	VetArgs                []string                              `json:"vet_args"`
	Status                 string                                `json:"status"`
}

type InstrumentationGeneratedHeader struct {
	Header        GeneratedHeaderProof `json:"header"`
	CompilerFlags []string             `json:"compiler_flags"`
}

// Dependency source and export digests are observations of the actual bounded
// source/type/export load, not independent ZIP membership proofs. External
// foreign modules remain unsupported here until their authentication is bound.
type InstrumentationDependencyExport struct {
	Source    ImportExport      `json:"source"`
	ImportMap map[string]string `json:"import_map"`
}

func InstrumentationHeaderCompilerFlags(input *InstrumentationConsumerInput) ([]string, error) {
	if input == nil || input.Plan == nil {
		return nil, fmt.Errorf("missing original mode header scope")
	}
	if err := ValidateInstrumentationConsumerInput(input, input.Plan.PackageDirectory, input.Plan.CustomTags); err != nil {
		return nil, err
	}
	flags := append([]string(nil), input.Plan.BuildFlags...)
	return append(flags, input.Observation.BuildPlan.CodegenFlags...), nil
}

func ValidateInstrumentationGeneratedHeader(input *InstrumentationConsumerInput, proof InstrumentationGeneratedHeader, pkg PackageProof) error {
	flags, err := InstrumentationHeaderCompilerFlags(input)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(proof.CompilerFlags, flags) {
		return fmt.Errorf("header compiler flags differ from the actual complete mode routing")
	}
	return validateGeneratedHeaderContext(input.Original, proof.Header, pkg, generatedHeaderValidationContext{
		protocol: InstrumentationGeneratedHeaderProtocol, id: input.ID, observed: input.Observation.Early.BaselineFeatures,
		validateMacros: func() error { return ValidateInstrumentationAssemblerMacros(pkg.Macros, input, pkg.PackagePath) },
	})
}

func DecodeInstrumentationMetadata(reader io.Reader, input *InstrumentationConsumerInput, directory string, tags []string) (*InstrumentationMetadataProof, error) {
	var proof InstrumentationMetadataProof
	if err := decodeInstrumentationOriginalJSON(reader, 16<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationMetadata(input, directory, tags, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func ValidateInstrumentationMetadata(input *InstrumentationConsumerInput, directory string, tags []string, proof *InstrumentationMetadataProof) error {
	if err := ValidateInstrumentationConsumerInput(input, directory, tags); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != InstrumentationMetadataProtocol || proof.ModeProfileID != input.ID ||
		proof.InputSHA256 != InstrumentationConsumerInputSHA256(input) || proof.Status != "consumer_pending" || len(proof.Headers) != 1 {
		return fmt.Errorf("mode metadata lost its independent source/profile/query identity")
	}
	if !discoverySHA256Pattern.MatchString(proof.OriginalExportSHA256) ||
		len(proof.InvocationConfigSHA256) < 1 || len(proof.InvocationConfigSHA256) > 2 ||
		!discoverySHA256Pattern.MatchString(proof.InvocationConfigSHA256["go.mod"]) {
		return fmt.Errorf("mode metadata lacks its actual original export/invocation configuration")
	}
	for name, digest := range proof.InvocationConfigSHA256 {
		if name != "go.mod" && name != "go.sum" || !discoverySHA256Pattern.MatchString(digest) {
			return fmt.Errorf("mode invocation has unknown/missing configuration")
		}
	}
	flags, err := InstrumentationPackageLoadFlags(input)
	if err != nil || !reflect.DeepEqual(flags, proof.LoadBuildFlags) || !reflect.DeepEqual(proof.VetArgs, InstrumentationPackageVetArgs(input)) {
		return fmt.Errorf("mode export/asmdecl flags lost their exact original scope")
	}
	if err := ValidateInstrumentationPackageSelection(input, directory, tags, proof.Selection); err != nil {
		return err
	}
	pkg := proof.Selection.Packages[0]
	if err := validateInstrumentationPackageDeclarations(input, pkg, proof.Declarations); err != nil {
		return err
	}
	if err := ValidateInstrumentationGeneratedHeader(input, proof.Headers[0], pkg); err != nil {
		return err
	}
	if err := validateInstrumentationTypeSourceAgreement(input, proof.Headers[0].Header, proof.Dependencies); err != nil {
		return err
	}
	return validateInstrumentationMetadataDependencies(input, pkg, proof.Headers[0].Header, proof.Dependencies)
}

func InstrumentationPackageLoadFlags(input *InstrumentationConsumerInput) ([]string, error) {
	if input == nil || input.Plan == nil {
		return nil, fmt.Errorf("missing actual mode package scope")
	}
	if err := ValidateInstrumentationConsumerInput(input, input.Plan.PackageDirectory, input.Plan.CustomTags); err != nil {
		return nil, err
	}
	flags := append([]string{"-mod=readonly", "-p=1"}, input.Plan.BuildFlags...)
	if len(input.Plan.CustomTags) != 0 {
		flags = append(flags, "-tags="+strings.Join(input.Plan.CustomTags, ","))
	}
	return flags, nil
}

// The exact actual package path is used from an independent invocation module;
// a downloaded external package must not become an invented versionless main.
func InstrumentationPackageVetArgs(input *InstrumentationConsumerInput) []string {
	if input == nil || input.Plan == nil {
		return nil
	}
	if _, err := InstrumentationPackageLoadFlags(input); err != nil {
		return nil
	}
	return instrumentationOrdinaryAsmdeclArgs()
}

func validateInstrumentationMetadataDependencies(input *InstrumentationConsumerInput, pkg PackageProof, header GeneratedHeaderProof, dependencies []InstrumentationDependencyExport) error {
	if dependencies == nil || len(dependencies) > 4096 || !sort.SliceIsSorted(dependencies, func(i, j int) bool { return dependencies[i].Source.PackagePath < dependencies[j].Source.PackagePath }) {
		return fmt.Errorf("mode dependency export closure is not bounded/canonical")
	}
	byPath := make(map[string]InstrumentationDependencyExport)
	for _, dep := range dependencies {
		source := dep.Source
		if source.PackagePath == "" || source.PackagePath == pkg.PackagePath || source.PackagePath == "unsafe" || source.ImportPath != source.PackagePath ||
			byPath[source.PackagePath].Source.PackagePath != "" || !discoverySHA256Pattern.MatchString(source.ExportSHA256) ||
			len(source.GoSHA256) == 0 || len(source.GoSHA256) > 32768 || dep.ImportMap == nil || len(dep.ImportMap) > 4096 {
			return fmt.Errorf("mode dependency lacks a unique actual export/source/import closure")
		}
		if source.ModulePath != "" && source.ModulePath != input.Original.Module && !instrumentationForeignDependencyBound(input, source) {
			return fmt.Errorf("mode foreign dependency needs its independent authenticated original source closure")
		}
		if err := validateImportedSource(input.Original, pkg, source); err != nil {
			return err
		}
		byPath[source.PackagePath] = dep
	}
	for _, imported := range header.Imports {
		actual := byPath[imported.PackagePath].Source
		actual.ImportPath = imported.ImportPath
		if !reflect.DeepEqual(actual, imported) {
			return fmt.Errorf("mode header import differs from the same-load dependency export/source")
		}
	}
	visited := make(map[string]bool)
	queue := []map[string]string{header.ImportMap}
	for len(queue) != 0 {
		imports := queue[0]
		queue = queue[1:]
		for spelling, target := range imports {
			if spelling == "" || target == "" || strings.ContainsAny(spelling+target, "\r\n=\\") || spelling == "unsafe" && target != "unsafe" {
				return fmt.Errorf("mode dependency has an invalid actual ImportMap")
			}
			if target == "unsafe" {
				continue
			}
			dep, exists := byPath[target]
			if !exists {
				return fmt.Errorf("mode dependency export closure omitted a reachable package: %s", target)
			}
			if !visited[target] {
				visited[target] = true
				queue = append(queue, dep.ImportMap)
			}
		}
	}
	if len(visited) != len(dependencies) {
		return fmt.Errorf("mode dependency export closure contains an unselected package")
	}
	return nil
}
