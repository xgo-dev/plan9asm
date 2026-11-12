package gotoolprofile

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// This is a projection of complete registered Go driver declarations, not
// an evaluator of arbitrary source. The producer checks membership in each
// original SDK file before and after export; replay checks every complete AST.
// Whole-file digests authenticate the frozen producer's inputs, not a claim
// that a JSON digest alone can prove membership in an arbitrary SDK.
type InstrumentationExportEnvironment struct {
	Protocol           string            `json:"protocol"`
	GoVersion          string            `json:"go_version"`
	SourceSHA256       map[string]string `json:"source_sha256"`
	SourceDeclarations map[string]string `json:"source_declarations"`
	RegistrationSHA256 map[string]string `json:"registration_ast_sha256"`
	BootstrapText      string            `json:"bootstrap_text"`
	GoEnvPresent       bool              `json:"go_env_present"`
	GoEnvText          string            `json:"go_env_text"`
}

const instrumentationExportEnvironmentProtocol = "actual_go_marker_changed_environment_v1"
const instrumentationBootstrapSource = "src/internal/buildcfg/zbootstrap.go"

// Complete audited Go 1.27.1/1.27.2 driver files (byte-identical). Pinning these alongside the
// projected ASTs prevents accepting a rewritten, self-consistent projection
// with fabricated whole-source digests. Future SDK changes need a fresh audit.
var instrumentationExportEnvironmentSourceRegistration = map[string]string{
	"src/cmd/go/internal/work/buildid.go": "6de8324513d2a5f9f629e8ae7ede623d1e87ef7b826fd1441265fc845a256555",
	"src/cmd/go/internal/work/init.go":    "cd86d5c8fecb90d9db58ed3c98d0869ff6b5220c445025051d366818859a0963",
	"src/cmd/go/internal/cfg/cfg.go":      "8eb038ac6df168fe5af971cd768d99dd3c64224273072a4160dcc5f51eacae9d",
	"src/cmd/go/internal/work/shell.go":   "ffc69d476c2cde44a64c26693b2c9aeb42830ac2777f9f538ef268c86d57be2f",
	"src/cmd/go/internal/work/gc.go":      "13359b8707e78300e8e0ec880b9a8d1af4bafdf32140b56df5f041a52fbc1325",
}

var instrumentationExportEnvironmentRegistrations = map[string]string{
	"src/cmd/go/internal/work/buildid.go#updateBuildID":   "749e831a261f6638b3dfd4e3d6f77321276dfd530a8b906b7353343db9790858",
	"src/cmd/go/internal/cfg/cfg.go#EnvOrAndChanged":      "496696c1fba2c248d479f6a60125bdd1e349a2fc0f6936aa50c17da5ef4f416a",
	"src/cmd/go/internal/cfg/cfg.go#GOAMD64":              "802d8ea0ab395ea9620f0b9ce1d5e07cc08c5d947238d95d54286d7a04af53ab",
	"src/cmd/go/internal/cfg/cfg.go#GOARM64":              "5699ca3bb24f5c90ba510c5d95233e2e74858490766f7252d22574f48c667a03",
	"src/cmd/go/internal/cfg/cfg.go#GetArchEnv":           "554cc40b196a2240051eb791af577ac2bc392178053cf24467a9a99bcaf60812",
	"src/cmd/go/internal/cfg/cfg.go#initEnvCache":         "14d9ec4cde6592bef7e3b5f7974d11fa47d1fb5a994dce6edf4972b33ba192de",
	"src/cmd/go/internal/cfg/cfg.go#readEnvFile":          "3f62cec3d5f6853a4035a71195610afa3ddfb223f2d35d45e2d6c3ccb485bbb0",
	"src/cmd/go/internal/work/gc.go#asm":                  "1c61898cd98e26c4187d29b46b763e6822b0df8b44f2807a7dbe4013cdf67a20",
	"src/cmd/go/internal/work/gc.go#gc":                   "471dec7ded9c8b4d6adb0a4e2de4230c15b18fd85cdc3d210b46aae500c68dbb",
	"src/cmd/go/internal/work/init.go#makeCfgChangedEnv":  "fe8772618100851a770d2dcf4c66f7bdd0edf4e8800702356a6072b3322fd82e",
	"src/cmd/go/internal/work/shell.go#runOut":            "0fd749215e983f2f31d3d0499ee765d43c36392ecffad81d16cea517dfdceb00",
	"src/cmd/go/internal/work/shell.go#joinUnambiguously": "c91dbacb9686e257fda39fd6c12cdef6cc9482376dda3afa2b7f9faec5d1408f",
	"src/cmd/go/internal/work/shell.go#fmtCmd":            "acfa7656780c7e4133d04f15ab17ffda57b130f7fad7890938c29268989cb117",
	"src/cmd/go/internal/work/shell.go#ShowCmd":           "a716a83e6144f79faebfb38918bb63c156c0ad99e45f908e27acf7afa47138bd",
}

func captureInstrumentationExportEnvironment(root, version string) (*InstrumentationExportEnvironment, error) {
	minor, err := goMinor(version)
	if err != nil || minor != 27 {
		return nil, fmt.Errorf("unregistered actual marker changed-environment version")
	}
	proof := &InstrumentationExportEnvironment{
		Protocol: instrumentationExportEnvironmentProtocol, GoVersion: version,
		SourceSHA256: make(map[string]string), SourceDeclarations: make(map[string]string),
		RegistrationSHA256: make(map[string]string),
	}
	files := make(map[string][]byte)
	for key := range instrumentationExportEnvironmentRegistrations {
		name, declaration, _ := strings.Cut(key, "#")
		data, present := files[name]
		if !present {
			data, err = readInstrumentationRegistration(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				return nil, fmt.Errorf("capture actual marker environment source %s: %w", name, err)
			}
			files[name] = data
			proof.SourceSHA256[name] = bytesSHA256(data)
		}
		text, digest, err := instrumentationExportDeclaration(name, data, declaration)
		if err != nil {
			return nil, err
		}
		proof.SourceDeclarations[key], proof.RegistrationSHA256[key] = text, digest
	}
	data, err := readInstrumentationRegistration(filepath.Join(root, filepath.FromSlash(instrumentationBootstrapSource)))
	if err != nil {
		return nil, fmt.Errorf("capture actual marker architecture defaults: %w", err)
	}
	proof.BootstrapText = string(data)
	proof.SourceSHA256[instrumentationBootstrapSource] = bytesSHA256(data)
	data, err = readInstrumentationRegistration(filepath.Join(root, "go.env"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("capture actual SDK go.env: %w", err)
	}
	if err == nil {
		proof.GoEnvPresent, proof.GoEnvText = true, string(data)
		proof.SourceSHA256["go.env"] = bytesSHA256(data)
	}
	if err := validateInstrumentationExportEnvironment(proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func instrumentationExportDeclaration(name string, data []byte, target string) (string, string, error) {
	result, err := instrumentationExportDeclarations.replay(name, data, target)
	return result.text, result.digest, err
}

type instrumentationExportDeclarationResult struct {
	text, digest string
	declarations int
}

func parseInstrumentationExportDeclaration(name string, data []byte, target string) (instrumentationExportDeclarationResult, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, name, data, 0)
	if err != nil {
		return instrumentationExportDeclarationResult{}, fmt.Errorf("parse marker environment source %s: %w", name, err)
	}
	var found ast.Node
	for _, declaration := range file.Decls {
		var candidate ast.Node
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == target {
			candidate = fn
		}
		if group, ok := declaration.(*ast.GenDecl); ok {
			for _, spec := range group.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok && len(value.Names) > 0 && value.Names[0].Name == target {
					candidate = value
				}
			}
		}
		if candidate != nil {
			if found != nil {
				return instrumentationExportDeclarationResult{}, fmt.Errorf("duplicate registered marker environment declaration: %s#%s", name, target)
			}
			found = candidate
		}
	}
	if found == nil {
		return instrumentationExportDeclarationResult{}, fmt.Errorf("missing registered marker environment declaration: %s#%s", name, target)
	}
	digest, err := ASTSHA(set, found)
	if err != nil {
		return instrumentationExportDeclarationResult{}, err
	}
	var out bytes.Buffer
	if _, ok := found.(*ast.ValueSpec); ok {
		out.WriteString("var ")
	}
	if err := format.Node(&out, set, found); err != nil {
		return instrumentationExportDeclarationResult{}, err
	}
	return instrumentationExportDeclarationResult{out.String(), digest, len(file.Decls)}, nil
}

func recheckInstrumentationExportEnvironmentSources(root, version string, before *InstrumentationExportEnvironment) error {
	if err := validateInstrumentationExportEnvironment(before); err != nil {
		return err
	}
	after, err := captureInstrumentationExportEnvironment(root, version)
	if err != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("actual marker changed-environment SDK sources/defaults changed during export: %v", err)
	}
	return nil
}

func validateInstrumentationExportEnvironment(proof *InstrumentationExportEnvironment) error {
	if proof == nil || proof.Protocol != instrumentationExportEnvironmentProtocol {
		return fmt.Errorf("missing actual marker changed-environment source protocol")
	}
	minor, err := goMinor(proof.GoVersion)
	if err != nil || minor != 27 || !gotoolchain.AuditedGo127(proof.GoVersion) ||
		len(proof.SourceDeclarations) != len(instrumentationExportEnvironmentRegistrations) ||
		!reflect.DeepEqual(proof.RegistrationSHA256, instrumentationExportEnvironmentRegistrations) {
		return fmt.Errorf("incomplete or unregistered marker changed-environment source projections")
	}
	for name, registered := range instrumentationExportEnvironmentSourceRegistration {
		if proof.SourceSHA256[name] != registered {
			return fmt.Errorf("changed complete registered marker environment source: %s", name)
		}
	}
	files := map[string]bool{instrumentationBootstrapSource: true}
	for key, registered := range instrumentationExportEnvironmentRegistrations {
		name, target, _ := strings.Cut(key, "#")
		files[name] = true
		text, present := proof.SourceDeclarations[key]
		if !present || len(text) == 0 || len(text) > instrumentationRegistrationByteLimit {
			return fmt.Errorf("missing or over-bound marker environment declaration: %s", key)
		}
		result, err := instrumentationExportDeclarations.replay(name, []byte("package replay\n"+text+"\n"), target)
		if err != nil || result.declarations != 1 {
			return fmt.Errorf("marker environment projection must contain exactly one complete declaration: %s", key)
		}
		if result.digest != registered {
			return fmt.Errorf("changed complete marker environment declaration: %s", key)
		}
	}
	if proof.GoEnvPresent {
		files["go.env"] = true
		if len(proof.GoEnvText) > instrumentationRegistrationByteLimit ||
			proof.SourceSHA256["go.env"] != bytesSHA256([]byte(proof.GoEnvText)) {
			return fmt.Errorf("changed or over-bound actual SDK go.env")
		}
	} else if proof.GoEnvText != "" {
		return fmt.Errorf("absent SDK go.env carries invented content")
	}
	if len(proof.SourceSHA256) != len(files) {
		return fmt.Errorf("incomplete or additional marker environment source digests")
	}
	for name := range files {
		if !discoverySHA256Pattern.MatchString(proof.SourceSHA256[name]) {
			return fmt.Errorf("missing marker environment source digest: %s", name)
		}
	}
	if len(proof.BootstrapText) == 0 || len(proof.BootstrapText) > instrumentationRegistrationByteLimit ||
		proof.SourceSHA256[instrumentationBootstrapSource] != bytesSHA256([]byte(proof.BootstrapText)) {
		return fmt.Errorf("changed or over-bound actual architecture defaults")
	}
	set := token.NewFileSet()
	bootstrap, err := parser.ParseFile(set, instrumentationBootstrapSource, proof.BootstrapText, 0)
	if err != nil || bootstrap.Name.Name != "buildcfg" {
		return fmt.Errorf("malformed actual architecture default source")
	}
	wanted := map[string]string{"DefaultGOAMD64": "v1", "DefaultGOARM64": "v8.0", "version": proof.GoVersion}
	seen := make(map[string]bool)
	for _, declaration := range bootstrap.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 {
				continue
			}
			name := value.Names[0].Name
			expected, required := wanted[name]
			if !required {
				continue
			}
			if seen[name] || len(value.Values) != 1 {
				return fmt.Errorf("duplicate or incomplete actual architecture default: %s", name)
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return fmt.Errorf("nonliteral actual architecture default: %s", name)
			}
			decoded, err := strconv.Unquote(literal.Value)
			if err != nil || decoded != expected {
				return fmt.Errorf("unregistered actual architecture default: %s", name)
			}
			seen[name] = true
		}
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("missing actual architecture defaults/version")
	}
	return nil
}

// The marker observer explicitly passes its captured GOOS/GOARCH, so the
// registered makeCfgChangedEnv cannot emit either mismatch. Eligible Go 1.27
// instrumentation targets use AMD64 or ARM64; rejected targets never export.
func instrumentationExportCommandEnvironment(proof *InstrumentationExportEnvironment, actual map[string]string, plan *InstrumentationBuildPlan) ([]string, error) {
	if plan == nil {
		return nil, fmt.Errorf("missing actual marker build plan")
	}
	if err := validateInstrumentationExportEnvironment(proof); err != nil {
		return nil, err
	}
	osName, arch, valid := strings.Cut(plan.Target, "/")
	if !valid || actual["GOOS"] != osName || actual["GOARCH"] != arch || proof.GoVersion != plan.GoVersion {
		return nil, fmt.Errorf("marker command environment differs from the actual target/version")
	}
	key, defaultValue := "", ""
	switch arch {
	case "amd64":
		key, defaultValue = "GOAMD64", "v1"
	case "arm64":
		key, defaultValue = "GOARM64", "v8.0"
	default:
		return nil, fmt.Errorf("marker export architecture lacks an eligible registered environment route")
	}
	value, present := actual[key]
	if !present || value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return nil, fmt.Errorf("marker export lacks its actual architecture environment")
	}
	// Replay readEnvFile exactly: no trimming, first '=' split, uppercase first
	// byte, last duplicate wins. An empty SDK value is present, not absent.
	for _, line := range strings.Split(proof.GoEnvText, "\n") {
		at := strings.IndexByte(line, '=')
		if at < 0 || line[0] < 'A' || line[0] > 'Z' {
			continue
		}
		if line[:at] == key {
			defaultValue = line[at+1:]
		}
	}
	if value == defaultValue {
		return nil, nil
	}
	return []string{key + "=" + value}, nil
}

func instrumentationExportCommandPrefix(environment []string) string {
	var out strings.Builder
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		if strings.ContainsRune(value, '\'') {
			out.WriteString(key + "=" + strconv.Quote(value) + " ")
		} else {
			out.WriteString(key + "='" + value + "' ")
		}
	}
	return out.String()
}
