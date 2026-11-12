package gotoolprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type InstrumentationMode string

const (
	InstrumentationRace InstrumentationMode = "race"
	InstrumentationMSan InstrumentationMode = "msan"
	InstrumentationASan InstrumentationMode = "asan"
)

// InstrumentationBuildFlags returns one driver mode, never a synthetic build
// tag. These flags alone do not prove that compilation, CGO, a cross SDK, or
// the sanitizer runtime is available for a target.
func InstrumentationBuildFlags(mode InstrumentationMode) ([]string, error) {
	switch mode {
	case "race", "msan", "asan":
		return []string{"-" + string(mode)}, nil
	default:
		return nil, fmt.Errorf("invalid or nonexclusive Go instrumentation mode %q", mode)
	}
}

// InstrumentationSourceRules is an in-process registration capture. It is not
// a portable source exclusion or a compiler consumer proof. Target rules are
// derived from the actual platform source, not a caller-provided support table.
// The full instrumentInit registration gates CGO, mutual exclusion, and PIE
// semantics; any change to that registration fails closed.
type InstrumentationSourceRules struct {
	root, version string
	sources       map[string]string
	registration  map[string]string
	targets       map[InstrumentationMode]map[string]bool
}

var instrumentationRuleSources = []string{
	"VERSION", "src/internal/platform/supported.go", "src/cmd/go/internal/work/init.go",
}

// This is the normalized token fingerprint of the complete instrumentInit
// function, not a selected condition or a reported Supported field. The Go
// 1.20 and 1.27 actual-source oracles verify the same audited registration.
const instrumentationInitRegistration = "d1a0e667707a7a0016ce864f7ace726eed14227d666385fcb7aa6bc7beb3c708"

const instrumentationRegistrationByteLimit = 2 << 20

func CaptureInstrumentationSourceRules(root, version string) (*InstrumentationSourceRules, error) {
	minor, err := goMinor(version)
	if err != nil || minor < 20 || minor > 27 || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("instrumentation registration requires an absolute Go 1.20–1.27 source root")
	}
	contents := make(map[string][]byte)
	for _, name := range instrumentationRuleSources {
		data, err := readInstrumentationRegistration(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("instrumentation source %s: %w", name, err)
		}
		contents[name] = data
	}
	return replayInstrumentationRuleSources(root, version, contents)
}

// A portable replay has no physical root and cannot satisfy Recheck. Both
// paths parse exactly the same complete registrations from original bytes.
func replayInstrumentationRuleSources(root, version string, contents map[string][]byte) (*InstrumentationSourceRules, error) {
	return instrumentationRulesMemo.replay(root, version, contents)
}

func parseInstrumentationRuleSources(root, version string, contents map[string][]byte) (*InstrumentationSourceRules, error) {
	rules := &InstrumentationSourceRules{
		root: root, version: version, sources: make(map[string]string),
		registration: make(map[string]string), targets: make(map[InstrumentationMode]map[string]bool),
	}
	for _, name := range instrumentationRuleSources {
		rules.sources[name] = bytesSHA256(contents[name])
	}
	if strings.Split(strings.TrimSpace(string(contents["VERSION"])), "\n")[0] != version {
		return nil, fmt.Errorf("instrumentation source VERSION differs from actual driver")
	}
	set := token.NewFileSet()
	init, err := parser.ParseFile(set, "init.go", contents["src/cmd/go/internal/work/init.go"], 0)
	if err != nil || init.Name.Name != "work" {
		return nil, fmt.Errorf("invalid actual Go instrumentation driver registration")
	}
	function, err := discoveryAssemblerSourceFunction(init, "instrumentInit")
	if err != nil {
		return nil, err
	}
	fingerprint, err := ASTSHA(set, function)
	if err != nil || fingerprint != instrumentationInitRegistration {
		return nil, fmt.Errorf("unrecognized complete Go instrumentInit registration")
	}
	rules.registration["instrumentInit"] = fingerprint
	for mode, name := range map[InstrumentationMode]string{"race": "RaceDetectorSupported", "msan": "MSanSupported", "asan": "ASanSupported"} {
		data := contents["src/internal/platform/supported.go"]
		targets, err := parseInstrumentationTargetRule(data, name)
		if err != nil {
			return nil, err
		}
		rules.targets[mode] = targets
		set := token.NewFileSet()
		platform, err := parser.ParseFile(set, "supported.go", data, 0)
		if err != nil {
			return nil, err
		}
		function, err := discoveryAssemblerSourceFunction(platform, name)
		if err != nil {
			return nil, err
		}
		rules.registration[name], err = ASTSHA(set, function)
		if err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func readInstrumentationRegistration(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, instrumentationRegistrationByteLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > instrumentationRegistrationByteLimit {
		return nil, fmt.Errorf("instrumentation registration exceeds its byte bound")
	}
	return data, nil
}

func (rules *InstrumentationSourceRules) SourceHashes() map[string]string {
	return copyInstrumentationHashes(rules.sources)
}

func (rules *InstrumentationSourceRules) RegistrationHashes() map[string]string {
	return copyInstrumentationHashes(rules.registration)
}

func copyInstrumentationHashes(original map[string]string) map[string]string {
	copy := make(map[string]string, len(original))
	for key, value := range original {
		copy[key] = value
	}
	return copy
}

func (rules *InstrumentationSourceRules) Recheck() error {
	if rules == nil {
		return fmt.Errorf("missing actual instrumentation source registration")
	}
	after, err := CaptureInstrumentationSourceRules(rules.root, rules.version)
	if err != nil || !reflect.DeepEqual(rules, after) {
		return fmt.Errorf("instrumentation source registration changed during consumption: %v", err)
	}
	return nil
}

func (rules *InstrumentationSourceRules) TargetSupported(target string, mode InstrumentationMode) (bool, error) {
	if _, err := InstrumentationBuildFlags(mode); err != nil {
		return false, err
	}
	if err := validateInstrumentationRuleTarget(target); err != nil {
		return false, err
	}
	if rules == nil || rules.targets[mode] == nil || rules.registration["instrumentInit"] != instrumentationInitRegistration {
		return false, fmt.Errorf("missing actual instrumentation target registration")
	}
	return rules.targets[mode][target], nil
}

func (rules *InstrumentationSourceRules) RequiresCGO(target string, mode InstrumentationMode) (bool, error) {
	supported, err := rules.TargetSupported(target, mode)
	if err != nil {
		return false, err
	}
	if !supported {
		return false, fmt.Errorf("no effective CGO requirement for a rejected instrumentation target")
	}
	return !strings.HasPrefix(target, "darwin/") || mode != "race", nil
}

func (rules *InstrumentationSourceRules) EffectiveBuildMode(target string, mode InstrumentationMode) (string, error) {
	supported, err := rules.TargetSupported(target, mode)
	if err != nil {
		return "", err
	}
	if !supported {
		return "", fmt.Errorf("no effective buildmode for a rejected instrumentation target")
	}
	if mode == "msan" && target != "linux/amd64" {
		return "pie", nil
	}
	return "default", nil
}

type InstrumentationEarlyStatus string

const (
	// This is only an early target/flag gate. It is not export or object proof.
	InstrumentationEarlyRuleAccepted         InstrumentationEarlyStatus = "early_target_rule_accepted"
	InstrumentationOfficialTargetUnsupported InstrumentationEarlyStatus = "official_target_rule_unsupported"
)

// ClassifyInstrumentationEarlyResult accepts only an actual bounded driver
// result paired with captured registration. It never classifies CGO, compiler,
// SDK, timeout, malformed output, or additional errors as source inapplicability.
// Production callers must separately bind the exact command, driver/version,
// environment and original file/profile scope; this foundation is not such a
// portable report, and accepted -find output is never a compilation claim.
func ClassifyInstrumentationEarlyResult(rules *InstrumentationSourceRules, target string, mode InstrumentationMode, stdout, stderr []byte, commandErr error) (InstrumentationEarlyStatus, error) {
	supported, err := rules.TargetSupported(target, mode)
	if err != nil {
		return "", err
	}
	if supported {
		if commandErr != nil {
			return "", fmt.Errorf("eligible instrumentation target driver failed: %w", commandErr)
		}
		// The zero-dependency early marker protocol has no registered
		// informational stderr. Do not let successful JSON hide a warning,
		// mixed error, or tool failure; a future allowance needs its own
		// actual-driver observation and exact diagnostic registration.
		if len(stderr) != 0 {
			return "", fmt.Errorf("eligible instrumentation target emitted unregistered stderr")
		}
		var pkg struct {
			Dir, ImportPath string
			GoFiles         []string
			Error           *struct{ Err string }
		}
		if err := json.Unmarshal(stdout, &pkg); err != nil || pkg.Dir == "" || pkg.ImportPath == "" || len(pkg.GoFiles) == 0 || pkg.Error != nil {
			return "", fmt.Errorf("eligible instrumentation target omitted actual package selection")
		}
		return InstrumentationEarlyRuleAccepted, nil
	}
	wanted := "-" + string(mode) + " is not supported on " + target + "\n"
	if len(stdout) != 0 || string(stderr) != wanted || !instrumentationActualExitTwo(commandErr) {
		return "", fmt.Errorf("actual driver did not give the unique registered instrumentation target rejection")
	}
	return InstrumentationOfficialTargetUnsupported, nil
}

func instrumentationActualExitTwo(err error) bool {
	for err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode() == 2
		}
		// A joined error can carry a timeout, overflow, or resource failure.
		// Do not extract a convenient ExitError from that mixed result.
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}

func validateInstrumentationRuleTarget(target string) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || !instrumentationTargetToken(parts[0]) || !instrumentationTargetToken(parts[1]) {
		return fmt.Errorf("invalid instrumentation target %q", target)
	}
	return validateTarget(target)
}

func instrumentationTargetToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func parseInstrumentationTargetRule(data []byte, name string) (map[string]bool, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "supported.go", data, 0)
	if err != nil || file.Name.Name != "platform" {
		return nil, fmt.Errorf("invalid instrumentation platform registration")
	}
	function, err := discoveryAssemblerSourceFunction(file, name)
	if err != nil {
		return nil, err
	}
	if function.Type.TypeParams != nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 ||
		len(function.Type.Params.List[0].Names) != 2 || function.Type.Params.List[0].Names[0].Name != "goos" || function.Type.Params.List[0].Names[1].Name != "goarch" ||
		!instrumentationIdent(function.Type.Params.List[0].Type, "string") || function.Type.Results == nil || len(function.Type.Results.List) != 1 ||
		len(function.Type.Results.List[0].Names) != 0 || !instrumentationIdent(function.Type.Results.List[0].Type, "bool") || len(function.Body.List) != 1 {
		return nil, fmt.Errorf("unrecognized complete instrumentation platform function %s", name)
	}
	switchRule, ok := function.Body.List[0].(*ast.SwitchStmt)
	if !ok || switchRule.Init != nil || !instrumentationIdent(switchRule.Tag, "goos") {
		return nil, fmt.Errorf("unrecognized instrumentation platform switch %s", name)
	}
	targets, seenOS := make(map[string]bool), make(map[string]bool)
	defaultSeen := false
	for _, statement := range switchRule.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok || len(clause.Body) != 1 {
			return nil, fmt.Errorf("unrecognized instrumentation platform case %s", name)
		}
		result, ok := clause.Body[0].(*ast.ReturnStmt)
		if !ok || len(result.Results) != 1 {
			return nil, fmt.Errorf("incomplete instrumentation platform return %s", name)
		}
		if len(clause.List) == 0 {
			if defaultSeen || !instrumentationIdent(result.Results[0], "false") {
				return nil, fmt.Errorf("unknown instrumentation platform default %s", name)
			}
			defaultSeen = true
			continue
		}
		arches, err := instrumentationArchAlternatives(result.Results[0])
		if err != nil {
			return nil, err
		}
		for _, item := range clause.List {
			goos, err := instrumentationString(item)
			if err != nil || seenOS[goos] {
				return nil, fmt.Errorf("unknown or duplicate instrumentation platform OS")
			}
			seenOS[goos] = true
			for _, arch := range arches {
				targets[goos+"/"+arch] = true
			}
		}
	}
	if !defaultSeen || len(targets) == 0 {
		return nil, fmt.Errorf("incomplete instrumentation platform target rule %s", name)
	}
	return targets, nil
}

func instrumentationArchAlternatives(expression ast.Expr) ([]string, error) {
	if paren, ok := expression.(*ast.ParenExpr); ok {
		return instrumentationArchAlternatives(paren.X)
	}
	binary, ok := expression.(*ast.BinaryExpr)
	if !ok {
		return nil, fmt.Errorf("unknown instrumentation architecture predicate")
	}
	if binary.Op == token.LOR {
		left, err := instrumentationArchAlternatives(binary.X)
		if err != nil {
			return nil, err
		}
		right, err := instrumentationArchAlternatives(binary.Y)
		if err != nil {
			return nil, err
		}
		for _, a := range left {
			for _, b := range right {
				if a == b {
					return nil, fmt.Errorf("duplicate instrumentation architecture predicate")
				}
			}
		}
		return append(left, right...), nil
	}
	if binary.Op != token.EQL {
		return nil, fmt.Errorf("unknown instrumentation architecture comparison")
	}
	value := binary.Y
	if !instrumentationIdent(binary.X, "goarch") {
		if !instrumentationIdent(binary.Y, "goarch") {
			return nil, fmt.Errorf("unknown instrumentation architecture input")
		}
		value = binary.X
	}
	arch, err := instrumentationString(value)
	if err != nil {
		return nil, err
	}
	return []string{arch}, nil
}

func instrumentationIdent(expression ast.Expr, name string) bool {
	ident, ok := expression.(*ast.Ident)
	return ok && ident.Name == name
}

func instrumentationString(expression ast.Expr) (string, error) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", fmt.Errorf("unknown instrumentation target literal")
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil || !instrumentationTargetToken(value) {
		return "", fmt.Errorf("invalid instrumentation target literal")
	}
	return value, nil
}
