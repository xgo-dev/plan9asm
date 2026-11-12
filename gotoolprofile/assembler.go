package gotoolprofile

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/goasmmacros"
)

type AssemblerMacros struct {
	Protocol           string            `json:"protocol"`
	FeatureID          string            `json:"feature_id"`
	Target             string            `json:"target"`
	GoVersion          string            `json:"go_version"`
	PackagePath        string            `json:"package_path"`
	PackageRole        string            `json:"package_role"`
	Defines            []string          `json:"defines"`
	ToolSourceSHA256   map[string]string `json:"tool_source_sha256"`
	RegistrationSHA256 map[string]string `json:"registration_ast_sha256"`
}

// ValidateOrdinaryAssemblerMacros checks portable frozen producer evidence.
// It does not authenticate Go source bytes without the original source tree;
// the compiler consumer separately captures and rechecks those actual bytes.
func ValidateOrdinaryAssemblerMacros(proof *AssemblerMacros, observed *Observation, packagePath string) error {
	if err := Validate(observed); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != "go_source_assembler_macros_v1" || proof.FeatureID != ProfileID(observed) || proof.Target != observed.Target || proof.GoVersion != observed.GoVersion || proof.PackagePath != packagePath {
		return fmt.Errorf("assembler macro evidence differs from actual profile/package identity")
	}
	minor, err := goMinor(observed.GoVersion)
	if err != nil {
		return err
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(observed.Environment["GOOS"], observed.Environment["GOARCH"], observed.Environment)
	if err != nil || !reflect.DeepEqual(defines, proof.Defines) {
		return fmt.Errorf("ordinary assembler macros differ from the actual target environment")
	}
	wantedRegistration := map[string]string{"asmArgs": goasmmacros.ArgsFingerprint(minor)}
	wantedSources := []string{"VERSION", "src/cmd/go/internal/work/gc.go", "src/cmd/asm/main.go"}
	if minor < 22 {
		if proof.PackageRole != "legacy_no_experiment_macros" {
			return fmt.Errorf("unverified legacy ordinary assembler package role")
		}
		wantedRegistration["experiment_registration_absent"] = bytesSHA256(nil)
	} else {
		if proof.PackageRole != "ordinary_path" {
			return fmt.Errorf("special assembler package role is outside ordinary CPU coverage")
		}
		wantedRegistration["experiment_registration"] = "32995e3cdb0c0ab1499abc494906e85ec47b639f2ebeac6b4c049d6d676a8b0f"
		wantedRegistration["package_special_registration"] = goasmmacros.SpecialFingerprint(minor)
		wantedSources = append(wantedSources, "src/cmd/internal/objabi/pkgspecial.go")
	}
	if !reflect.DeepEqual(wantedRegistration, proof.RegistrationSHA256) || len(proof.ToolSourceSHA256) != len(wantedSources) {
		return fmt.Errorf("incomplete or unknown actual assembler source registration")
	}
	for _, file := range wantedSources {
		if !discoverySHA256Pattern.MatchString(proof.ToolSourceSHA256[file]) {
			return fmt.Errorf("actual assembler registration lacks source hash: %s", file)
		}
	}
	if proof.ToolSourceSHA256["VERSION"] != observed.ToolSourceSHA256["VERSION"] {
		return fmt.Errorf("assembler macros and actual feature driver used different Go source versions")
	}
	return nil
}

// This derives package-role macros from actual registered Go sources. It is
// not a package source-selection observation: production must separately bind
// packagePath to the actual go list package being checked under this profile.
func CaptureAssemblerMacros(root string, observed *Observation, packagePath string) (*AssemblerMacros, error) {
	if observed == nil || observed.Protocol != "go_driver_builtin_features_v2" || observed.GoVersion != observed.Environment["GOVERSION"] {
		return nil, fmt.Errorf("missing or inconsistent observed assembler environment")
	}
	rules, err := goasmmacros.Capture(root, observed.GoVersion, packagePath, os.ReadFile)
	if err != nil {
		return nil, err
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(observed.Environment["GOOS"], observed.Environment["GOARCH"], observed.Environment)
	if err != nil {
		return nil, err
	}
	proof := &AssemblerMacros{
		Protocol: "go_source_assembler_macros_v1", FeatureID: ProfileID(observed),
		Target: observed.Target, GoVersion: observed.GoVersion, PackagePath: packagePath,
		PackageRole: rules.PackageRole, Defines: defines,
		ToolSourceSHA256: rules.ToolSourceSHA256, RegistrationSHA256: rules.RegistrationSHA256,
	}
	if rules.PackageRole == "allow_asm_abi_path" {
		for _, tag := range observed.ToolTags {
			if strings.HasPrefix(tag, "goexperiment.") {
				if !observed.MarkerSelection[tag] {
					return nil, fmt.Errorf("unobserved enabled experiment %s", tag)
				}
				proof.Defines = append(proof.Defines, "GOEXPERIMENT_"+strings.TrimPrefix(tag, "goexperiment."))
			}
		}
	}
	return proof, nil
}

func discoveryAssemblerSourceFunction(file *ast.File, name string) (*ast.FuncDecl, error) {
	return goasmmacros.SourceFunction(file, name)
}

func ASTSHA(fset *token.FileSet, node ast.Node) (string, error) {
	return goasmmacros.ASTSHA(fset, node)
}
