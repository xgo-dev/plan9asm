package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestSignatureSourceQueryAdequateOrdinaryTypesIgnorePoisonTests(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	input, dir := testDeclarationRoleFixture(t, "linux/amd64")
	input.TestDependencySourceProtocol = gotoolprofile.TestDependencyProtocol
	files := map[string]string{
		"layout.go": `package header
func U8ToF32s(x uint8) float32
func EchoF32(x float32) float32
func EchoF64(x float64) float64
`,
		"decl_test.go": `package header
import "missing.invalid/poison"
func UnusedBodyless() float64
var Poison = undefinedTestOnly
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name], input.Headers[name] = featureBytesSHA256([]byte(source)), source
	}
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	config, err := resolveCompileConfig(false, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	query := &gotoolprofile.SignatureQueryProof{Protocol: gotoolprofile.SignatureQueryProtocol}
	config.FeaturePath, config.Context, config.SignatureQuery = writeFeatureInput(t, input), ctx, query
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil,
		input.AsmFiles, input.Module, t.TempDir(), false, 0, false, false, true, repo, config)
	if err != nil || report.Failed != 0 || report.Success != 0 || len(query.Requests) != 0 ||
		query.Selection == nil || len(query.Selection.Outputs) != 0 || len(query.Selection.TestDeclarations) != 0 {
		t.Fatalf("adequate actual ordinary types loaded poison tests or fabricated object success: %#v, %v", report, err)
	}
	if err := gotoolprofile.ValidateSignatureQuery(input, query, nil); err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateSelection(input, query.Selection, nil, true); err == nil {
		t.Fatal("missing-reference query was accepted as final translation/object proof")
	}
}
