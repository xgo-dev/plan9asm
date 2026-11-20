package gostaticstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const Protocol = "actual_go_static_numeric_storage_prototype_v1"

// Request supplies actual input locations and references, not permissions.
// The prototype accepts an ordinary pure-Go flat main module and its actual
// same-module imports only. It does not download modules or load test variants.
type Request struct {
	GoBinary, Directory, PackagePath, Target string
	Environment                              []string
	Variables                                []Reference
}

type Reference struct{ PackagePath, Name string }
type Span struct{ Offset, Length int64 }

// Variable records initialized numerical storage, never a constant value after
// initialization. uintptr bits here grant no pointer/address permission.
type Variable struct {
	Reference
	NativeName, GoType string
	Size, Alignment    int64 // zero object Alignment means unspecified, not inferred
	Kind               uint8
	Numerical          []Span
	DefinitionMember   string
	DefinitionIndex    uint32
}

type Package struct {
	Dir, ImportPath, Name, Export, ForTest                      string
	Root                                                        string
	GoFiles, CompiledGoFiles, SFiles, HFiles, CgoFiles, Imports []string
	EmbedFiles, EmbedPatterns, CFiles, CXXFiles, MFiles, FFiles []string
	SwigFiles, SwigCXXFiles, SysoFiles                          []string
	Standard                                                    bool
	Goroot                                                      bool
	ImportMap                                                   map[string]string
	Module                                                      *struct {
		Path, Version, Dir, GoMod string
		Main                      bool
		Replace                   json.RawMessage
	}
	Error      json.RawMessage
	DepsErrors []json.RawMessage
}

// Report retains complete bounded original bytes so a reader can recompute
// hashes and binary records. Its JSON is an observation, not a sealed authority.
// Physical paths are private invocation artifacts; this is not ledger format.
type Report struct {
	Protocol, Target, PackagePath string
	Environment                   map[string]string
	RawEnvironment, RawSelection  []byte
	Source                        map[string][]byte
	SourceSHA256                  map[string]string
	Archives                      map[string][]byte
	ArchiveSHA256                 map[string]string
	Tools                         map[string]string
	Variables                     []Variable
	CommandDirectory              string
	CommandArguments              []string
	CommandBinary                 string
	CommandEnvironment            map[string]string
	TextProtocol                  string
	TextBuiltinSource             []byte
	TextArchives                  map[string][]TextMember
}

// Observation can be created only by Capture's actual command/source boundary.
// It is not wired to translation or declaration-only result initialization.
type Observation struct {
	mu      sync.Mutex
	ready   bool
	request Request
	report  Report
	inputs  map[string]string
	dirs    map[string]os.FileInfo
	seal    [32]byte
}

var formatSources = map[string]string{
	"src/cmd/internal/goobj/objfile.go":    "caf835a17e23aa02cae9bda6e8723d8be359846fc4453bd53f3a3947744b938a",
	"src/cmd/internal/archive/archive.go":  "7e7a3af16eef5c6140145f245ae21147b42a462def4d6e043a74b54710a083a1",
	"src/cmd/internal/objabi/symkind.go":   "de287864b7ff9a3614becc538cbabdccdecc030a848aad5d5bbef6ec7ec5c225",
	"src/cmd/internal/objfile/goobj.go":    "5411305140a7f5cd3f61f826d1b6fbbab155db6c94fd263a7ecf1a570e80dc04",
	"src/cmd/internal/sys/arch.go":         "07ac549fe63e0df269822d5b10b704ca710489b2aa25e176df5d98f2a2c6b8f2",
	"src/cmd/internal/objabi/reloctype.go": "49bebd30a27d05a24de77398ab524dfbeb0630c8b88c06646c1e4734e4f1fc9d",
	"src/cmd/internal/obj/pcln.go":         "c165134b74c7e6f908d852551280b45ca58b580226ec27aa345bb869b554448f",
	builtinSourceRole:                      "8f38ef757cdebb27963ee9befe24dd8041b86d217937db30f13e4d3d91207311",
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func readRegular(name string, limit int64) ([]byte, error) {
	resolved, resolveErr := sourcepath.Resolve(name)
	info, err := sourcepath.Lstat(name)
	if resolveErr != nil || resolved != name || err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, contextError("missing, redirected or oversized regular input: " + name)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, contextError("input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, contextError("input changed or exceeded read bound")
	}
	return data, nil
}

func within(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func snapshot(root, protocol string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	budget := sourceBudget(protocol)
	total := int64(0)
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name != root && strings.HasPrefix(entry.Name(), ".") {
				return contextError("hidden/nested source directory outside prototype")
			}
			return nil
		}
		if err := budget.checkCount(len(files) + 1); err != nil {
			return err
		}
		data, err := readRegular(name, 16<<20)
		if err != nil {
			return err
		}
		if err := budget.checkBytes(total, len(data)); err != nil {
			return err
		}
		total += int64(len(data))
		rel, _ := filepath.Rel(root, name)
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}

func Capture(ctx context.Context, request Request) (*Observation, error) {
	return capture(ctx, request, false)
}

func capture(ctx context.Context, request Request, sdkCPU bool) (*Observation, error) {
	protocol := Protocol
	if sdkCPU {
		protocol = SDKCPUProtocol
	}
	return captureRole(ctx, request, protocol)
}

func captureRole(ctx context.Context, request Request, protocol string) (*Observation, error) {
	sdkCPU, sdkGlobals := protocol == SDKCPUProtocol, protocol == SDKGlobalsProtocol
	sdk := sdkCPU || sdkGlobals
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		request.PackagePath == "" || len(request.Variables) == 0 || len(request.Variables) > 32 {
		return nil, contextError("missing actual source context or bounded variable request")
	}
	goos, arch, valid := strings.Cut(request.Target, "/")
	if !valid || (arch != "386" && arch != "amd64" && arch != "arm" && arch != "arm64" && arch != "wasm") ||
		goos != "linux" && goos != "darwin" && goos != "windows" && !(goos == "js" && arch == "wasm") {
		return nil, contextError("unknown target")
	}
	root, err := sourcepath.Resolve(request.Directory)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve original source root: %w", ErrContext, err)
	}
	if root != request.Directory {
		return nil, contextError("source root must be canonical")
	}
	if sdkCPU && (request.PackagePath != "internal/cpu" || !sdkCPUTarget(request.Target) ||
		root != filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "cpu")) {
		return nil, contextError("SDK producer requires exact original CPU owner")
	}
	if sdkGlobals && (!sdkCPUTarget(request.Target) || !sdkGlobalDirectory(request.GoBinary, root, request.PackagePath)) {
		return nil, contextError("SDK global producer requires this invoked installation's exact original package")
	}
	provided := make(map[string]string)
	for _, pair := range request.Environment {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, contextError("invalid environment")
		}
		if _, duplicate := provided[key]; duplicate {
			return nil, contextError("duplicate environment key")
		}
		provided[key] = value
	}
	if provided["GOFLAGS"] != "" || provided["GOEXPERIMENT"] != "" || provided["GOPACKAGESDRIVER"] != "" && provided["GOPACKAGESDRIVER"] != "off" {
		return nil, contextError("unbound flags, experiments or package driver")
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(provided[key]) {
			return nil, contextError("explicit command cache/temp directory required")
		}
	}
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": arch, "GOAMD64": "v1", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "CGO_ENABLED": "0", "GOPROXY": "off"} {
		if key == "CGO_ENABLED" && sdk && (provided[key] == "0" || provided[key] == "1") {
			continue // Preserve the explicitly observed SDK profile; sources stay pure Go.
		}
		provided[key] = value
	}
	if sdk {
		for key, value := range sdkCPUProfile(request.Target) {
			provided[key] = value
		}
	}
	request.Environment = nil
	for key, value := range provided {
		request.Environment = append(request.Environment, key+"="+value)
	}
	sort.Strings(request.Environment)
	request.Variables = append([]Reference(nil), request.Variables...)
	sort.Slice(request.Variables, func(i, j int) bool { return referenceKey(request.Variables[i]) < referenceKey(request.Variables[j]) })
	for i, ref := range request.Variables {
		if !token.IsIdentifier(ref.Name) || ref.Name == "_" || ref.PackagePath == "" || i > 0 && ref == request.Variables[i-1] {
			return nil, contextError("invalid or duplicate variable reference")
		}
	}
	source, err := snapshot(root, protocol)
	if err != nil {
		return nil, fmt.Errorf("%w: snapshot complete original sources: %w", ErrContext, err)
	}
	if !sdk && source["go.mod"] == nil {
		return nil, contextError("complete original module sources lack go.mod")
	}
	if sdkCPU {
		if err := sdkCPUSource(source); err != nil {
			return nil, fmt.Errorf("%w: complete original SDK CPU sources: %w", ErrContext, err)
		}
	}
	o := &Observation{request: request, inputs: make(map[string]string), report: Report{
		Protocol: Protocol, Target: request.Target, PackagePath: request.PackagePath,
		Source: source, SourceSHA256: make(map[string]string), Archives: make(map[string][]byte),
		ArchiveSHA256: make(map[string]string), Tools: make(map[string]string),
	}}
	o.report.Protocol = protocol
	o.dirs = make(map[string]os.FileInfo)
	directories := []string{request.Directory, provided["GOCACHE"], provided["GOMODCACHE"], provided["GOPATH"], provided["TMPDIR"], provided["GOTMPDIR"]}
	if sdk {
		directories = append(directories, filepath.Dir(filepath.Dir(request.GoBinary)))
	}
	for _, name := range directories {
		resolved, err := sourcepath.Resolve(name)
		info, statErr := sourcepath.Lstat(name)
		if err != nil || resolved != name || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, contextError("actual command input/cache/temp root is redirected or missing")
		}
		o.dirs[name] = info
	}
	for name, data := range source {
		o.report.SourceSHA256[name] = digest(data)
	}
	driver, err := readRegular(request.GoBinary, 64<<20)
	if err != nil {
		return nil, err
	}
	o.inputs[request.GoBinary] = digest(driver)
	o.report.CommandDirectory = request.Directory
	o.report.CommandArguments = o.selectionArguments()
	o.report.CommandBinary = request.GoBinary
	o.report.CommandEnvironment = make(map[string]string)
	for _, key := range []string{"GOROOT", "GOCACHE", "GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR", "GOOS", "GOARCH", "GOAMD64", "GOTOOLCHAIN", "GOENV", "GOWORK", "CGO_ENABLED", "GOPROXY", "GOFLAGS", "GOEXPERIMENT"} {
		o.report.CommandEnvironment[key] = provided[key]
	}
	if sdk {
		for key, value := range sdkCPUProfile(request.Target) {
			o.report.CommandEnvironment[key] = value
		}
	}
	if err := o.observe(ctx); err != nil {
		return nil, err
	}
	if sdkGlobals {
		if err := o.captureSDKGlobalDependencies(ctx); err != nil {
			return nil, err
		}
	}
	raw, err := o.run(ctx, o.selectionArguments()...)
	if err != nil {
		return nil, err
	}
	o.report.RawSelection = raw
	packages, err := reportPackages(o.report, root)
	if err != nil {
		return nil, err
	}
	total := 0
	for path, pkg := range packages {
		data, err := readRegular(pkg.Export, archiveLimit)
		if err != nil || !within(o.report.Environment["GOCACHE"], pkg.Export) {
			return nil, contextError("archive differs from actual cache/source role")
		}
		total += len(data)
		if total > 64<<20 {
			return nil, contextError("actual export byte bound exceeded")
		}
		o.report.Archives[path], o.report.ArchiveSHA256[path] = data, digest(data)
		o.inputs[pkg.Export] = digest(data)
	}
	o.report.Variables, err = bindVariables(o.report, packages, request.Variables)
	if err != nil {
		return nil, err
	}
	o.report.TextProtocol = TextProtocol
	o.report.TextArchives, err = textArchives(o.report, packages)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(o.report)
	o.seal, o.ready = sha256.Sum256(encoded), true
	if err := o.Verify(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *Observation) run(ctx context.Context, args ...string) ([]byte, error) {
	stage, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return goasmcmd.Run(stage, o.request.Directory, o.request.Environment, o.request.GoBinary, args...)
}

func (o *Observation) observe(ctx context.Context) error {
	arguments := []string{"env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOCACHE", "GOMODCACHE", "GOOS", "GOARCH", "GOAMD64", "GOFLAGS", "GOEXPERIMENT", "CGO_ENABLED", "GOWORK"}
	if sdkStorageProtocol(o.report.Protocol) {
		arguments = append(arguments, "GO386", "GOARM", "GOARM64", "GOWASM")
	}
	raw, err := o.run(ctx, arguments...)
	if err != nil {
		return err
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil || !gotoolchain.AuditedGo127(env["GOVERSION"]) ||
		env["GOOS"]+"/"+env["GOARCH"] != o.request.Target || env["GOFLAGS"] != "" || env["GOEXPERIMENT"] != "" ||
		env["CGO_ENABLED"] != o.report.CommandEnvironment["CGO_ENABLED"] ||
		!sdkStorageProtocol(o.report.Protocol) && env["CGO_ENABLED"] != "0" ||
		env["GOWORK"] != "off" || filepath.Join(env["GOROOT"], "bin", gotoolchain.HostExecutable("go")) != o.request.GoBinary {
		return contextError("actual Go driver/profile/target differs")
	}
	if env["GOMODCACHE"] != o.report.CommandEnvironment["GOMODCACHE"] {
		return contextError("actual Go module cache differs from the explicit command role")
	}
	if !sdkStorageProtocol(o.report.Protocol) {
		if err := ValidateOwnedSourceDirectory(o.request.Directory, env["GOROOT"], env["GOMODCACHE"]); err != nil {
			return err
		}
	}
	if sdkStorageProtocol(o.report.Protocol) {
		for key, expected := range sdkCPUProfile(o.request.Target) {
			if env[key] != expected {
				return contextError("actual SDK target tuning differs")
			}
		}
	}
	o.report.Environment, o.report.RawEnvironment = env, raw
	paths := map[string]string{"go": o.request.GoBinary, "VERSION": filepath.Join(env["GOROOT"], "VERSION")}
	route, err := o.run(ctx, "tool", "-n", "compile")
	if err != nil || strings.TrimSpace(string(route)) != filepath.Join(env["GOTOOLDIR"], gotoolchain.HostExecutable("compile")) {
		return contextError("unknown actual compile route")
	}
	paths["compile"] = strings.TrimSpace(string(route))
	if sdkStorageProtocol(o.report.Protocol) {
		route, err := o.run(ctx, "tool", "-n", "asm")
		if err != nil || strings.TrimSpace(string(route)) != filepath.Join(env["GOTOOLDIR"], gotoolchain.HostExecutable("asm")) {
			return contextError("unknown actual SDK assembly route")
		}
		paths["asm"] = strings.TrimSpace(string(route))
		for role := range sdkCPUFormatSources {
			paths[role] = filepath.Join(env["GOROOT"], filepath.FromSlash(role))
		}
	}
	for name := range formatSources {
		paths[name] = filepath.Join(env["GOROOT"], filepath.FromSlash(name))
	}
	for role, name := range paths {
		data, err := readRegular(name, 64<<20)
		if err != nil || formatSources[role] != "" && digest(data) != formatSources[role] ||
			sdkCPUFormatSources[role] != "" && digest(data) != sdkCPUFormatSources[role] ||
			role == "VERSION" && strings.Split(string(data), "\n")[0] != env["GOVERSION"] {
			return contextError("actual SDK/tool/object-format source differs")
		}
		if previous := o.inputs[name]; previous != "" && previous != digest(data) {
			return contextError("actual driver changed during observation")
		}
		o.report.Tools[role], o.inputs[name] = digest(data), digest(data)
		if role == builtinSourceRole {
			o.report.TextBuiltinSource = append([]byte(nil), data...)
		}
	}
	return nil
}

func (o *Observation) Verify(ctx context.Context) error {
	if o == nil {
		return contextError("nil observation")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.ready || ctx == nil || ctx.Err() != nil {
		return contextError("observation is revoked or lacks live context")
	}
	fail := func(err error) error { o.ready = false; return err }
	if err := o.verifyDirectories(); err != nil {
		return fail(err)
	}
	encoded, _ := json.Marshal(o.report)
	if sha256.Sum256(encoded) != o.seal {
		return fail(contextError("sealed producer report changed"))
	}
	source, err := o.snapshotSource()
	if err != nil {
		return fail(fmt.Errorf("%w: snapshot complete original source inventory: %w", ErrContext, err))
	}
	if !reflect.DeepEqual(source, o.report.Source) {
		return fail(contextError("complete original source inventory changed"))
	}
	for name, expected := range o.inputs {
		actual, err := gooriginalsrc.HashRegularFile(name, 64<<20)
		if err != nil || hex.EncodeToString(actual[:]) != expected {
			return fail(contextError("actual source/tool/export bytes changed"))
		}
	}
	raw, err := o.run(ctx, o.verificationArguments()...)
	if err != nil || !sameSelection(raw, o.report.RawSelection) {
		return fail(contextError("actual selected package/import/export changed"))
	}
	// The final command is not an exemption from the source/export guards.
	final, err := o.snapshotSource()
	if err != nil {
		return fail(fmt.Errorf("%w: snapshot original sources after actual final selection: %w", ErrContext, err))
	}
	if !reflect.DeepEqual(final, o.report.Source) {
		return fail(contextError("source changed during actual final selection"))
	}
	for name, expected := range o.inputs {
		actual, err := gooriginalsrc.HashRegularFile(name, 64<<20)
		if err != nil || hex.EncodeToString(actual[:]) != expected {
			return fail(contextError("tool/export changed during actual final selection"))
		}
	}
	if err := o.verifyDirectories(); err != nil {
		return fail(err)
	}
	return nil
}

func (o *Observation) verifyDirectories() error {
	for name, original := range o.dirs {
		resolved, resolveErr := sourcepath.Resolve(name)
		info, err := sourcepath.Lstat(name)
		if err != nil || resolveErr != nil || resolved != name || !info.IsDir() || !os.SameFile(info, original) {
			return contextError("actual command/source/cache/temp root identity changed")
		}
	}
	return nil
}

func selectionArguments() []string {
	// -a recompiles this bounded same-module graph: an already cached export
	// alone is not an observation of the actual selected compiler's data record.
	return []string{"list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "-mod=readonly", "."}
}

func (o *Observation) selectionArguments() []string {
	if o.report.Protocol == SDKCPUProtocol {
		return sdkCPUArguments()
	}
	if o.report.Protocol == SDKGlobalsProtocol {
		return sdkGlobalsArguments(o.report.PackagePath)
	}
	return selectionArguments()
}

// Capture retains its forced compiler prior. Live verification still queries
// the same complete selection/export graph and guards every current byte on
// both sides of that command; it need not force recompilation of that graph.
func (o *Observation) verificationArguments() []string {
	arguments := o.selectionArguments()
	result := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument != "-a" {
			result = append(result, argument)
		}
	}
	return result
}

func referenceKey(ref Reference) string { return ref.PackagePath + "\x00" + ref.Name }

// CheckReport checks an independently decoded snapshot against the live sealed
// producer and reconstructs the retained bytes. JSON alone cannot satisfy it.
func (o *Observation) CheckReport(ctx context.Context, report Report) error {
	if o == nil {
		return contextError("nil observation")
	}
	o.mu.Lock()
	data, _ := json.Marshal(report)
	matched := o.ready && sha256.Sum256(data) == o.seal
	o.mu.Unlock()
	if !matched {
		return contextError("readback report differs from sealed original command outputs")
	}
	if err := o.Verify(ctx); err != nil {
		return err
	}
	return ValidateReport(report)
}

func (o *Observation) Readback(ctx context.Context) (Report, error) {
	if err := o.Verify(ctx); err != nil {
		return Report{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	data, _ := json.Marshal(o.report)
	var result Report
	if err := json.Unmarshal(data, &result); err != nil {
		return Report{}, err
	}
	if err := ValidateReport(result); err != nil {
		return Report{}, err
	}
	return result, nil
}

func (o *Observation) Close() {
	if o != nil {
		o.mu.Lock()
		o.ready = false
		o.mu.Unlock()
	}
}
