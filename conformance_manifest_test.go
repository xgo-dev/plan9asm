package plan9asm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testConformanceManifest struct {
	SchemaVersion int `json:"schema_version"`
	Cases         []struct {
		ID         string   `json:"id"`
		Goarch     string   `json:"goarch"`
		Asm        string   `json:"asm"`
		Forms      []string `json:"forms"`
		References []string `json:"references"`
		Validation string   `json:"validation"`
		HWFeatures []string `json:"hw_features"`
		Reason     string   `json:"reason"`
	} `json:"cases"`
}

func TestConformanceManifestMatchesAssembly(t *testing.T) {
	root := filepath.Join("testdata", "conformance")
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest testConformanceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || len(manifest.Cases) == 0 {
		t.Fatalf("invalid or empty conformance manifest: %#v", manifest)
	}
	for _, tc := range manifest.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			switch tc.Validation {
			case "execute":
				if tc.Reason != "" {
					t.Error("executable case must not carry a compile-only reason")
				}
			case "compile-only":
				if strings.TrimSpace(tc.Reason) == "" {
					t.Error("compile-only case must explain why execution is unsafe")
				}
			default:
				t.Errorf("validation = %q, want execute or compile-only", tc.Validation)
			}
			arch, err := conformanceArch(tc.Goarch)
			if err != nil {
				t.Fatal(err)
			}
			src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tc.Asm)))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(arch, string(src))
			if err != nil {
				t.Fatal(err)
			}
			observed := map[string]struct{}{}
			for _, fn := range file.Funcs {
				for _, ins := range fn.Instrs {
					desc := DescribeInstruction(arch, tc.Goarch, ins)
					observed[desc.Form] = struct{}{}
				}
			}
			if len(tc.Forms) == 0 {
				t.Fatal("case claims no forms")
			}
			for _, ref := range tc.References {
				if !strings.HasPrefix(ref, "https://github.com/") {
					t.Errorf("reference %q is not a GitHub issue or pull request URL", ref)
				}
			}
			for _, form := range tc.Forms {
				if _, ok := observed[form]; !ok {
					t.Errorf("claimed form %q does not occur in %s", form, tc.Asm)
				}
			}
		})
	}
}

func conformanceArch(goarch string) (Arch, error) {
	switch goarch {
	case "386", "amd64":
		return ArchAMD64, nil
	case "arm":
		return ArchARM, nil
	case "arm64":
		return ArchARM64, nil
	default:
		return "", &unknownConformanceArchError{goarch: goarch}
	}
}

type unknownConformanceArchError struct {
	goarch string
}

func (e *unknownConformanceArchError) Error() string {
	return "unknown conformance GOARCH: " + e.goarch
}
