package gotoolprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The target-driver foundation is integrated with profile scopes separately;
// it must not silently turn feature-only inputs into baseline exclusions.
type discoveryTargetFeatures = Observation

const discoveryFeatureMarkerModule = "example.invalid/plan9asm-feature-markers"

var discoveryFeatureEnvKeys = []string{
	"CGO_ENABLED", "GOCACHE", "GO386", "GOAMD64", "GOARCH", "GOARM", "GOARM64", "GOEXPERIMENT", "GOOS", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOWASM",
}

func captureDiscoveryTargetFeatures(ctx context.Context, goBinary, markerDir string, baseEnv []string, target string, overrides map[string]string, run Runner) (*discoveryTargetFeatures, error) {
	env, err := FeatureCommandEnvironment(baseEnv, target, overrides)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(target, "/")
	cpuKeys := map[string]string{"386": "GO386", "amd64": "GOAMD64", "arm": "GOARM", "arm64": "GOARM64", "wasm": "GOWASM"}
	cpuKey := cpuKeys[parts[1]]
	if !filepath.IsAbs(goBinary) || !filepath.IsAbs(markerDir) {
		return nil, fmt.Errorf("feature driver and owned marker directory must be absolute")
	}
	resolvedDir, err := sourcepath.Resolve(markerDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		return nil, fmt.Errorf("read owned feature marker directory: %w", err)
	}
	if len(entries) != 0 {
		return nil, fmt.Errorf("feature marker directory must exist and be empty")
	}
	driverHash, err := discoveryFeatureFileSHA256(goBinary)
	if err != nil {
		return nil, fmt.Errorf("feature driver: %w", err)
	}
	args := append([]string{"env", "-json"}, discoveryFeatureEnvKeys...)
	output, envStderr, err := run(ctx, resolvedDir, env, goBinary, args...)
	if err != nil {
		return nil, fmt.Errorf("feature target environment: %w", err)
	}
	var actualEnv map[string]string
	if err := json.Unmarshal(output, &actualEnv); err != nil {
		return nil, fmt.Errorf("decode actual feature environment: %w", err)
	}
	if len(actualEnv) != len(discoveryFeatureEnvKeys) {
		return nil, fmt.Errorf("incomplete actual feature environment")
	}
	for _, key := range discoveryFeatureEnvKeys {
		if _, ok := actualEnv[key]; !ok {
			return nil, fmt.Errorf("missing actual feature environment %s", key)
		}
	}
	if actualEnv["GOOS"] != parts[0] || actualEnv["GOARCH"] != parts[1] || actualEnv["CGO_ENABLED"] != "0" {
		return nil, fmt.Errorf("Go driver returned a different feature target")
	}
	for key, wanted := range overrides {
		if actualEnv[key] != wanted {
			return nil, fmt.Errorf("actual Go driver did not preserve required %s=%q (reported %q)", key, wanted, actualEnv[key])
		}
	}
	minor, err := goMinor(actualEnv["GOVERSION"])
	if err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("feature registration is not audited for Go version %q", actualEnv["GOVERSION"])
	}
	if err := validateDiscoveryCPUEnvironment(parts[1], actualEnv[cpuKey], minor); err != nil {
		return nil, err
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, goBinary, env, actualEnv, run)
	if err != nil {
		return nil, err
	}
	tags, sourceHashes, err := discoveryBuiltinFeatureCandidates(actualEnv["GOROOT"], actualEnv["GOVERSION"])
	if err != nil {
		return nil, err
	}
	markerFiles := discoveryFeatureMarkerFiles(tags)
	for name, data := range markerFiles {
		file, err := os.OpenFile(filepath.Join(resolvedDir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("create owned feature marker: %w", err)
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, fmt.Errorf("write owned feature marker: %v (close: %v)", writeErr, closeErr)
		}
	}
	output, listStderr, err := run(ctx, resolvedDir, env, goBinary, "list", "-find", "-json", "-mod=readonly", ".")
	if err != nil {
		return nil, fmt.Errorf("feature marker selection: %w", err)
	}
	selection, err := decodeDiscoveryFeatureMarkers(output, resolvedDir, tags)
	if err != nil {
		return nil, err
	}
	output, recheckStderr, err := run(ctx, resolvedDir, env, goBinary, args...)
	if err != nil {
		return nil, fmt.Errorf("recheck actual feature environment: %w", err)
	}
	var afterEnv map[string]string
	if err := json.Unmarshal(output, &afterEnv); err != nil || len(afterEnv) != len(actualEnv) {
		return nil, fmt.Errorf("actual feature environment changed during marker selection")
	}
	for key, value := range actualEnv {
		if after, exists := afterEnv[key]; !exists || after != value {
			return nil, fmt.Errorf("actual feature environment changed during marker selection: %s", key)
		}
	}
	// The observer binds the bytes consumed by both driver commands. Caller
	// owns markerDir's lifetime; never remove cache-owned or user files here.
	afterDriver, err := discoveryFeatureFileSHA256(goBinary)
	if err != nil || afterDriver != driverHash {
		return nil, fmt.Errorf("feature driver changed during capture")
	}
	afterTools, err := captureDiscoveryFeatureSubtools(ctx, goBinary, env, afterEnv, run)
	if err != nil {
		return nil, fmt.Errorf("recheck actual Go subtools: %w", err)
	}
	if !equalDiscoveryFeatureToolStates(tools, afterTools) {
		return nil, fmt.Errorf("actual Go subtool bytes/routing/cache changed during capture")
	}
	for name, before := range sourceHashes {
		after, err := discoveryFeatureFileSHA256(filepath.Join(actualEnv["GOROOT"], filepath.FromSlash(name)))
		if err != nil || after != before {
			return nil, fmt.Errorf("feature tool source changed during capture: %s", name)
		}
	}
	afterEntries, err := os.ReadDir(resolvedDir)
	if err != nil || len(afterEntries) != len(markerFiles) {
		return nil, fmt.Errorf("feature marker files changed during capture")
	}
	for name, before := range markerFiles {
		after, err := os.ReadFile(filepath.Join(resolvedDir, name))
		if err != nil || !bytes.Equal(before, after) {
			return nil, fmt.Errorf("feature marker bytes changed during capture: %s", name)
		}
	}
	var selected []string
	for _, tag := range tags {
		if selection[tag] {
			selected = append(selected, tag)
		}
	}
	selectionJSON, err := json.Marshal(selection)
	if err != nil {
		return nil, err
	}
	// Do not leak machine-private source roots into portable profile evidence.
	delete(actualEnv, "GOROOT")
	delete(actualEnv, "GOTOOLDIR")
	delete(actualEnv, "GOCACHE")
	return &discoveryTargetFeatures{
		Protocol: "go_driver_builtin_features_v2", Target: target, Environment: actualEnv,
		GoVersion: actualEnv["GOVERSION"], DriverSHA256: driverHash, ToolSourceSHA256: sourceHashes,
		ToolDirectory: tools.directory, ToolBinarySHA256: tools.digests,
		ToolBinaryOrigins: tools.origins, ToolRoutingSHA256: tools.routing,
		ToolDispatcherSHA256: tools.dispatcher,
		ToolTags:             selected, MarkerSelection: selection, MarkerSourceSHA256: discoveryFeatureMarkerSHA256(markerFiles),
		DriverSelectionSHA256: discoveryFeatureBytesSHA256(selectionJSON), EnvStderrSHA256: discoveryFeatureBytesSHA256(envStderr),
		EnvRecheckStderrSHA256: discoveryFeatureBytesSHA256(recheckStderr),
		ListStderrSHA256:       discoveryFeatureBytesSHA256(listStderr),
	}, nil
}

func validateDiscoveryCPUEnvironment(arch, value string, minor int) error {
	valid := false
	switch arch {
	case "386":
		valid = value == "sse2" || value == "softfloat"
	case "amd64":
		valid = value == "v1" || value == "v2" || value == "v3" || value == "v4"
	case "arm":
		for _, version := range []string{"5", "6", "7"} {
			valid = valid || value == version || value == version+",softfloat" || value == version+",hardfloat"
		}
	case "arm64":
		if minor < 23 {
			valid = value == ""
			break
		}
		level := strings.Split(value, ",")[0]
		for _, candidate := range discoveryCPUFeatureCandidates() {
			valid = valid || candidate == "arm64."+level
		}
		for _, extension := range strings.Split(value, ",")[1:] {
			if extension != "lse" && extension != "crypto" {
				valid = false
			}
		}
	case "wasm":
		valid = true
		for _, feature := range strings.Split(value, ",") {
			if feature != "" && feature != "satconv" && feature != "signext" {
				valid = false
			}
		}
	}
	if !valid {
		return fmt.Errorf("unrecognized actual CPU feature environment for %s: %q", arch, value)
	}
	return nil
}

func discoveryCPUFeatureCandidates() []string {
	tags := []string{"386.sse2", "386.softfloat", "wasm.satconv", "wasm.signext"}
	for level := 1; level <= 4; level++ {
		tags = append(tags, fmt.Sprintf("amd64.v%d", level))
	}
	for level := 5; level <= 7; level++ {
		tags = append(tags, fmt.Sprintf("arm.%d", level))
	}
	for minor := 0; minor <= 9; minor++ {
		tags = append(tags, fmt.Sprintf("arm64.v8.%d", minor))
	}
	for minor := 0; minor <= 5; minor++ {
		tags = append(tags, fmt.Sprintf("arm64.v9.%d", minor))
	}
	return tags
}

func discoveryBuiltinFeatureCandidates(root string, versions ...string) ([]string, map[string]string, error) {
	if !filepath.IsAbs(root) {
		return nil, nil, fmt.Errorf("actual Go driver returned non-absolute GOROOT")
	}
	const cfg = "src/internal/buildcfg/cfg.go"
	const flags = "src/internal/goexperiment/flags.go"
	versionData, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil || len(versions) != 1 || strings.TrimSpace(strings.Split(string(versionData), "\n")[0]) != versions[0] {
		return nil, nil, fmt.Errorf("actual Go source VERSION does not match driver GOVERSION")
	}
	minor, err := goMinor(versions[0])
	if err != nil || minor < 20 || minor > 27 {
		return nil, nil, fmt.Errorf("unsupported actual feature source version")
	}
	cfgData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(cfg)))
	if err != nil {
		return nil, nil, err
	}
	if err := validateDiscoveryFeatureRegistration(cfgData, minor); err != nil {
		return nil, nil, err
	}
	flagsData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(flags)))
	if err != nil {
		return nil, nil, err
	}
	experiments, err := discoveryExperimentFeatureCandidates(flagsData)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(experiments)
	if err != nil || discoveryFeatureBytesSHA256(encoded) != discoveryVersionedExperimentFingerprints[minor] {
		return nil, nil, fmt.Errorf("actual experiment Flags namespace differs from audited Go 1.%d source", minor)
	}
	tags := append(discoveryCPUFeatureCandidates(), experiments...)
	sort.Strings(tags)
	return tags, map[string]string{"VERSION": discoveryFeatureBytesSHA256(versionData), cfg: discoveryFeatureBytesSHA256(cfgData), flags: discoveryFeatureBytesSHA256(flagsData)}, nil
}

// Sorted actual Flags names from the same eight source versions audited below.
// Binding their inventory to GOVERSION prevents a valid old Flags AST from
// hiding experiments registered in the current driver.
var discoveryVersionedExperimentFingerprints = map[int]string{
	20: "48b85ced0e6d664288c06553e34762cd631e2b0399bdad5688d7798c6785e08f",
	21: "40a8da1e5be03c7cd358c2692b1acb73c597a5efe7c02cf193be22c32c2d70c7",
	22: "878f99519db76a94823059333c94e0610cfeef96ea911547b68d3cf3f769d6b7",
	23: "9726432e4577241c2cd37c474d29245742f932fd88f62a706e89f099fe05c880",
	24: "7f6653c3871242ec1e4f7dc3be2e00c66a64d224176b45acfe8dc8fdad5ada9c",
	25: "438bf2033e42b67f81f59d72126b0c341d110b9c3ffdea46c47f35442f2121b1",
	26: "91203a6562b47777218dbb24bba84f16083d8abbf9d169a8770207d6fdb8c325",
	27: "aee888ef48c2fb3276d64ef9c9229667bd4a7187e2e0fd886444d2d9a7daab7d",
}

// These are normalized AST-token fingerprints of the complete registration
// functions actually audited in Go 1.20.14, 1.21.13, 1.22.12, 1.23.12,
// 1.24.13, 1.25.14, 1.26.8 and 1.27.1 sources. This is a finite source grammar
// guard, not a coverage baseline. Unknown registration code must be reviewed;
// it cannot silently invent an unobserved builtin or an arbitrary custom tag.
var discoveryFeatureRegistrationFingerprints = map[string][]string{
	"toolTags":       {"b4b6381704ea6e60d0d2522595df66db182ff1b58c29d2f753bea782496323a3"},
	"experimentTags": {"f391da8e69ecb7f0383a9e342a8639489dcb7fd94c6596e7a9e483ced36476d2"},
	"gogoarchTags": {
		"b2dd21d5ca443f36db4fa966ed8fc3467216f88db85edb44b243a8c9ce332755", // Go 1.20–1.21
		"ed7c2a3ec46db74c8888369284c192d2effd85b32f3c99082ceeb983a806a14c", // Go 1.22
		"43924858e77d06c222e4dab4f21f24c8bd32207287edb370f258254a8cbf9b2f", // Go 1.23–1.24
		"f9f731718824fba2d59ac1cb1de5743562acc6d3875f7d0677dc0dbd9806429c", // Go 1.25
		"e51726aa195348f1455632487fd66752581ff49e055cfb8cdefe34b1908cc036", // Go 1.26–1.27
	},
}

func validateDiscoveryFeatureRegistration(data []byte, minors ...int) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "cfg.go", data, 0)
	if err != nil || f.Name.Name != "buildcfg" {
		return fmt.Errorf("invalid actual feature registration source: %v", err)
	}
	seen := make(map[string]bool)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		allowed, registered := discoveryFeatureRegistrationFingerprints[fn.Name.Name]
		if !registered {
			continue
		}
		if len(minors) != 0 && fn.Name.Name == "gogoarchTags" {
			index, known := map[int]int{20: 0, 21: 0, 22: 1, 23: 2, 24: 2, 25: 3, 26: 4, 27: 4}[minors[0]]
			if len(minors) != 1 || !known {
				return fmt.Errorf("unrecognized actual feature registration Go version")
			}
			allowed = allowed[index : index+1]
		}
		if seen[fn.Name.Name] || fn.Recv != nil || fn.Body == nil {
			return fmt.Errorf("invalid feature registration function %s", fn.Name.Name)
		}
		seen[fn.Name.Name] = true
		var formatted bytes.Buffer
		if err := format.Node(&formatted, fset, fn); err != nil {
			return err
		}
		var scan scanner.Scanner
		scan.Init(token.NewFileSet().AddFile("registration", -1, formatted.Len()), formatted.Bytes(), nil, 0)
		var canonical bytes.Buffer
		for {
			_, tok, literal := scan.Scan()
			if tok == token.EOF {
				break
			}
			fmt.Fprintf(&canonical, "%s\x00%s\x00", tok, literal)
		}
		digest := discoveryFeatureBytesSHA256(canonical.Bytes())
		accepted := false
		for _, known := range allowed {
			accepted = accepted || digest == known
		}
		if !accepted {
			return fmt.Errorf("unrecognized actual feature registration function %s (%s)", fn.Name.Name, digest)
		}
	}
	if len(seen) != len(discoveryFeatureRegistrationFingerprints) {
		return fmt.Errorf("incomplete actual feature registration functions")
	}
	return nil
}

func discoveryExperimentFeatureCandidates(data []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "flags.go", data, 0)
	if err != nil || f.Name.Name != "goexperiment" {
		return nil, fmt.Errorf("invalid actual experiment flags source: %v", err)
	}
	var tags []string
	seen := make(map[string]bool)
	flagTypes := 0
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typ := spec.(*ast.TypeSpec)
			if typ.Name.Name != "Flags" {
				continue
			}
			flagTypes++
			fields, ok := typ.Type.(*ast.StructType)
			if !ok || typ.Assign.IsValid() {
				return nil, fmt.Errorf("unrecognized actual experiment Flags type")
			}
			for _, field := range fields.Fields.List {
				kind, ok := field.Type.(*ast.Ident)
				if !ok || kind.Name != "bool" || len(field.Names) != 1 || field.Tag != nil {
					return nil, fmt.Errorf("unrecognized actual experiment Flags field")
				}
				tag := "goexperiment." + strings.ToLower(field.Names[0].Name)
				if seen[tag] {
					return nil, fmt.Errorf("duplicate actual experiment flag %s", tag)
				}
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	if flagTypes != 1 || len(tags) == 0 {
		return nil, fmt.Errorf("incomplete actual experiment Flags type")
	}
	sort.Strings(tags)
	return tags, nil
}

func discoveryFeatureMarkerFiles(tags []string) map[string][]byte {
	files := map[string][]byte{
		"go.mod":  []byte("module " + discoveryFeatureMarkerModule + "\n\ngo 1.20\n"),
		"base.go": []byte("package markers\n"),
	}
	for index, tag := range tags {
		files[fmt.Sprintf("marker%03d.go", index)] = []byte("//go:build " + tag + "\n\npackage markers\n")
	}
	return files
}

func decodeDiscoveryFeatureMarkers(data []byte, dir string, tags []string) (map[string]bool, error) {
	var pkg struct {
		Dir            string
		ImportPath     string
		GoFiles        []string
		IgnoredGoFiles []string
		SFiles         []string
		Error          *struct{ Err string }
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("decode actual feature marker selection: %w", err)
	}
	actualDir, err := sourcepath.Resolve(pkg.Dir)
	if err != nil || actualDir != dir || pkg.ImportPath != discoveryFeatureMarkerModule || pkg.Error != nil || len(pkg.SFiles) != 0 {
		return nil, fmt.Errorf("Go driver returned a different or invalid marker package")
	}
	byFile := map[string]string{"base.go": ""}
	for index, tag := range tags {
		byFile[fmt.Sprintf("marker%03d.go", index)] = tag
	}
	seen := make(map[string]bool)
	selection := make(map[string]bool, len(tags))
	for _, group := range []struct {
		files []string
		match bool
	}{{pkg.GoFiles, true}, {pkg.IgnoredGoFiles, false}} {
		for _, file := range group.files {
			tag, exists := byFile[file]
			if !exists || seen[file] || (file == "base.go" && !group.match) {
				return nil, fmt.Errorf("invalid actual feature marker file %s", file)
			}
			seen[file] = true
			if tag != "" {
				selection[tag] = group.match
			}
		}
	}
	if len(seen) != len(byFile) {
		return nil, fmt.Errorf("actual feature selection omitted marker files")
	}
	return selection, nil
}

func discoveryFeatureTagNamespace(tag string) bool {
	if tag == "boringcrypto" || tag == "race" || tag == "msan" || tag == "asan" || strings.HasPrefix(tag, "goexperiment.") || strings.HasPrefix(tag, "go1.") {
		return true
	}
	for _, arch := range []string{
		"386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be", "loong64", "mips", "mipsle", "mips64", "mips64le",
		"mips64p32", "mips64p32le", "ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm",
	} {
		if strings.HasPrefix(tag, arch+".") {
			return true
		}
	}
	return false
}

func discoveryFeatureBytesSHA256(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func discoveryFeatureProfileID(observed *discoveryTargetFeatures) string {
	// encoding/json orders map keys; observers also require sorted ToolTags.
	// Bind every portable observation byte, including command/namespace proof,
	// rather than permitting the same ID to carry a different evidence body.
	data, _ := json.Marshal(observed)
	return discoveryFeatureBytesSHA256(data)
}

func containsTargetFeature(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func discoveryFeatureMarkerSHA256(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", name, len(files[name]))
		h.Write(files[name])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
