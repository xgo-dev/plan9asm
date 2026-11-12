package gotoolprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCPPPackageIncludeAbsenceUsesPhysicalSourceAndEnvironment(t *testing.T) {
	base := t.TempDir()
	moduleRoot, toolRoot := filepath.Join(base, "module"), filepath.Join(base, "tool")
	for name, contents := range map[string]string{
		"module/pkg/native.s": "#include \"../../src/value.h\"\n",
		"module/pkg/plain.go": "package fixture\n",
		"tool/src/value.h":    "#define VALUE 42\n",
	} {
		file := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	miss := CPPPackageSearchMiss{
		Protocol: CPPPackageSearchMissProtocol, Assembly: "pkg/native.s", Source: "module/pkg/native.s",
		Include: "../../src/value.h", PackageCandidate: "../src/value.h", ToolSource: "src/value.h",
	}
	if err := VerifyCPPPackageSearchMiss(miss, moduleRoot, toolRoot); err != nil {
		t.Fatal(err)
	}
	input := &ConsumerInput{
		Sources:                map[string]string{"pkg/native.s": strings.Repeat("a", 64), "pkg/plain.go": strings.Repeat("b", 64)},
		ToolSources:            map[string]string{"src/value.h": strings.Repeat("c", 64)},
		CPPIncludeSearchMisses: []CPPPackageSearchMiss{miss},
	}
	if err := ValidateCPPIncludeSearch(input, &SelectionProof{CPPIncludeSearchMisses: []CPPPackageSearchMiss{miss}}); err != nil {
		t.Fatal(err)
	}
	input.CPPIncludeSearchMisses[0].Source = "module/pkg/plain.go"
	if err := VerifyCPPPackageSearchMiss(input.CPPIncludeSearchMisses[0], moduleRoot, toolRoot); err == nil {
		t.Fatal("self-consistent metadata authenticated a source with no include operand")
	}
	input.CPPIncludeSearchMisses = nil
	if err := ValidateCPPIncludeSearch(input, nil); err == nil {
		t.Fatal("deleting all absence evidence fell back to arbitrary tool source acceptance")
	}
	preferred := filepath.Join(base, "src/value.h")
	if err := os.MkdirAll(filepath.Dir(preferred), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(toolRoot, "src/value.h"), preferred); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCPPPackageSearchMiss(miss, moduleRoot, toolRoot); err == nil {
		t.Fatal("outside-source shadow symlink was treated as absence")
	}
}

func TestCPPIncludeTokensMatchOriginalQuotedOperand(t *testing.T) {
	for _, source := range []string{
		"#include \"../../src/value.h\"\n",
		"#include \"../..\\x2fsrc/value.h\" // original quoted escape\n",
	} {
		if !cppLiteralInclude([]byte(source), "../../src/value.h") {
			t.Fatalf("actual quoted include operand was not retained: %q", source)
		}
	}
	for _, source := range []string{
		"// #include \"../../src/value.h\"\n",
		"/* #include \"../../src/value.h\" */\n",
		"#include \"../../src/value.h\" junk\n",
		"#include \"../../src/other.h\"\n",
	} {
		if cppLiteralInclude([]byte(source), "../../src/value.h") {
			t.Fatalf("not an exact original include operand: %q", source)
		}
	}
}
