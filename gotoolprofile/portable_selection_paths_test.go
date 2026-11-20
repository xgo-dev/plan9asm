package gotoolprofile

import (
	"encoding/json"
	"go/build"
	"path"
	"strings"
	"testing"
)

func TestPortableSelectionDoesNotInheritHostJoinPath(t *testing.T) {
	input, proof, _ := ordinarySourceClosureFixture(t)
	// These maps contain portable module-relative names, not host filenames.
	// Exercise the Windows failure on every host without changing source keys.
	original := build.Default
	build.Default.JoinPath = func(elements ...string) string {
		return strings.ReplaceAll(path.Join(elements...), "/", "\\")
	}
	t.Cleanup(func() { build.Default = original })

	t.Run("ordinary dependency and embed closure", func(t *testing.T) {
		if err := ValidateOrdinaryDependencies(input, proof, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ordinary package selection", func(t *testing.T) {
		ctx, err := ordinaryPackageSelectionContext(input, nil)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := ctx.MatchFile("dep", "dep.go")
		if err != nil || !selected {
			t.Fatalf("portable nested source selection = %v, %v", selected, err)
		}
	})
	t.Run("instrumentation package selection", func(t *testing.T) {
		early := &InstrumentationEarlyObservation{
			SourceRules: &InstrumentationSourceProof{GoVersion: "go1.27.2"},
			Environment: input.Observed.Environment, BaselineFeatures: input.Observed,
		}
		sources := &InstrumentationOriginalSourceInventory{Contents: input.Headers}
		ctx, err := instrumentationOriginalBuildContext(sources, early, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := ctx.MatchFile("dep", "dep.go")
		if err != nil || !selected {
			t.Fatalf("portable instrumentation selection = %v, %v", selected, err)
		}
	})
	t.Run("supplemental test declaration", func(t *testing.T) {
		input := &ConsumerInput{
			Module: "example.invalid/portable", Observed: input.Observed,
			Headers: map[string]string{
				"nested/base.go":       "package nested\n",
				"nested/value_test.go": "package nested\nfunc Value()\n",
			},
			Directories: map[string][]string{"nested": {"base.go", "value_test.go", "value.s"}},
			Sources:     map[string]string{"nested/base.go": "base", "nested/value_test.go": "test", "nested/value.s": "asm"},
		}
		pkg := PackageProof{PackagePath: input.Module + "/nested", GoFiles: []string{"nested/base.go"},
			SFiles: []string{"nested/value.s"}, SourceSHA256: map[string]string{"nested/base.go": "base"}}
		proof := TestDeclarationProof{
			Protocol: TestDeclarationProtocol, PackagePath: pkg.PackagePath, VariantID: pkg.PackagePath + " [" + pkg.PackagePath + ".test]",
			Target: input.Observed.Target, GoVersion: input.Observed.GoVersion, ExportSHA256: strings.Repeat("a", 64),
			GoFiles: []string{"nested/base.go", "nested/value_test.go"}, CompiledGoFiles: []string{"nested/base.go", "nested/value_test.go"},
			SFiles: pkg.SFiles, SourceSHA256: input.Sources, ImportMap: map[string]string{},
			Declarations: []TestDeclaration{{Symbol: pkg.PackagePath + ".Value", File: "nested/value_test.go", GoType: "func()", Layout: json.RawMessage(`{}`)}},
		}
		if err := validateTestDeclaration(input, []PackageProof{pkg}, proof, nil); err != nil {
			t.Fatal(err)
		}
	})
}
