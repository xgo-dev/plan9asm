package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// GoX86SDKLiteralAlignment observes original linked literal layout only.
// It supplies neither a numerical address nor execution, ABI or read authority.
// Its original source and independent initializer owner remain borrowed/live.
type GoX86SDKLiteralAlignment struct {
	mu, operation            sync.Mutex
	identity                 *GoX86SDKLiteralAlignment
	ready                    bool
	generation               uint64
	active                   int
	closePending             bool
	owner, originalOwner     *GoX86SDKReadonlyLiteralDataOwner
	ownerGeneration          uint64
	ownerSeal                [32]byte
	guard, originalGuard     *GoAMD64FrameSource
	directories              map[string]os.FileInfo
	context, originalContext context.Context
	deadline                 time.Time
	report                   []byte
	seal, stateSeal          [32]byte
	observation              sdkLiteralAlignmentReport
}

type sdkLiteralMinimumAlignment struct {
	SourceOrdinal, MemberOrdinal int
	Namespace                    gostaticstorage.TextSymbolNamespace
	Index                        uint32
	Name                         string
	Size, MinimumAlignment       uint32
}

type sdkLiteralAlignmentReport struct {
	Protocol, PackagePath, Target, CGOEnabled, BuildMode string
	InitializerSHA256                                    [32]byte
	Graph                                                []byte
	Inputs                                               map[string][32]byte
	Commands                                             []numericalSBCommand
	Minima                                               []sdkLiteralMinimumAlignment
}

const sdkLiteralAlignmentProtocol = "actual_go_sdk_linked_literal_minimum_alignment_v1"

// CaptureGoX86SDKLiteralAlignment links untouched original SDK archives through
// an ordinary generated empty main. It never imports an internal package, uses
// linkname/-E, changes SDK source, or invents a callable ABI. Internal candidates
// must already be natural dependencies of runtime; otherwise they stay Context.
// Dead-stripped or ambiguously named objects receive no minimum-alignment row.
func CaptureGoX86SDKLiteralAlignment(ctx context.Context, owner *GoX86SDKReadonlyLiteralDataOwner) (_ *GoX86SDKLiteralAlignment, result error) {
	if ctx == nil || owner == nil || owner.identity != owner {
		return nil, sdkASMDataContext("minimum alignment requires its original live literal owner")
	}
	if err := owner.Verify(ctx); err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !reflect.TypeOf(ctx).Comparable() {
		return nil, sdkASMDataContext("minimum alignment requires one bounded original context")
	}
	owner.mu.Lock()
	source, generation, seal := owner.source, owner.generation, owner.seal
	owner.mu.Unlock()
	if source == nil || source.identity != source {
		return nil, sdkASMDataContext("minimum alignment requires its original SDK source")
	}
	// The selected linker/layout inputs are byte-identical in these patches.
	// Actual input, compiler, linker and image checks below remain mandatory.
	version := source.guard.env["GOVERSION"]
	if version != "go1.27.2" && version != "go1.27.3" {
		return nil, sdkASMDataContext("minimum alignment requires the registered original Go 1.27.2 or Go 1.27.3 SDK")
	}
	request := source.request
	guard := newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, Target: request.Target, Environment: append([]string(nil), request.Environment...)})
	guard.env = make(map[string]string, len(source.guard.env))
	for key, value := range source.guard.env {
		guard.env[key] = value
	}
	guard.selection = source.guard.selection
	observed := &GoX86SDKLiteralAlignment{owner: owner, originalOwner: owner, ownerGeneration: generation,
		ownerSeal: seal, guard: guard, originalGuard: guard, context: ctx, originalContext: ctx, deadline: deadline,
		directories: make(map[string]os.FileInfo)}
	observed.identity = observed
	defer func() {
		if result != nil {
			result = errors.Join(result, observed.Close())
		}
	}()
	provided, err := sdkASMDataEnvironment(request)
	if err != nil {
		return nil, err
	}
	guard.owned, err = os.MkdirTemp(provided["TMPDIR"], "plan9asm-sdk-literal-alignment-")
	if err != nil {
		return nil, err
	}
	guard.owned, err = sourcepath.Resolve(guard.owned)
	if err != nil {
		return nil, err
	}
	guard.ownedInfo, err = sourcepath.Lstat(guard.owned)
	if err != nil {
		return nil, err
	}
	if err := captureSDKPackageDirectoryInputs(guard, observed.retainDirectory); err != nil {
		return nil, err
	}
	for _, dir := range []string{request.Directory, guard.env["GOROOT"], guard.env["GOTOOLDIR"], guard.env["GOCACHE"], guard.owned} {
		if err := observed.retainDirectory(dir); err != nil {
			return nil, err
		}
	}
	observed.observation = sdkLiteralAlignmentReport{Protocol: sdkLiteralAlignmentProtocol,
		PackagePath: request.PackagePath, Target: request.Target, CGOEnabled: provided["CGO_ENABLED"],
		BuildMode: "exe", InitializerSHA256: seal}
	if guard.env["GOOS"] == "darwin" || guard.env["GOOS"] == "windows" {
		observed.observation.BuildMode = "pie"
	}
	if err := observed.capture(ctx); err != nil {
		return nil, err
	}
	observed.observation.Inputs = cloneSDKASMDataInputs(guard.inputs)
	observed.report, err = json.Marshal(observed.observation)
	if err != nil {
		return nil, err
	}
	observed.seal = sha256.Sum256(observed.report)
	observed.stateSeal, err = observed.digest()
	if err != nil {
		return nil, err
	}
	observed.ready, observed.generation = true, 1
	if err := observed.Verify(ctx); err != nil {
		return nil, err
	}
	return observed, nil
}

func (observed *GoX86SDKLiteralAlignment) capture(ctx context.Context) error {
	guard, root := observed.guard, observed.guard.env["GOROOT"]
	for _, tool := range []string{"link", "compile"} {
		route, err := observed.run(ctx, "tool", "-n", tool)
		if err != nil {
			return err
		}
		name := strings.TrimSpace(string(route))
		if name != filepath.Join(guard.env["GOTOOLDIR"], gotoolchain.HostExecutable(tool)) {
			return sdkASMDataContext("minimum alignment lost actual %s tool route", tool)
		}
		if _, err := guard.read(name); err != nil {
			return err
		}
		version, err := observed.run(ctx, "tool", tool, "-V")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(version)) != tool+" version "+guard.env["GOVERSION"] {
			return sdkASMDataContext("minimum alignment actual %s binary version differs from its SDK", tool)
		}
	}
	directory := guard.env["GOARCH"]
	if directory == "386" {
		directory = "x86"
	}
	var rule [][]byte
	for _, name := range []string{"src/cmd/link/internal/ld/data.go", "src/cmd/link/internal/loader/loader.go",
		"src/cmd/link/internal/" + directory + "/l.go", "src/cmd/link/internal/" + directory + "/obj.go",
		"src/cmd/link/internal/ld/lib.go", "src/cmd/link/internal/ld/deadcode.go", "src/cmd/link/internal/ld/elf.go",
		"src/cmd/link/internal/ld/macho.go", "src/cmd/link/internal/ld/pe.go", "src/cmd/link/internal/ld/main.go",
		"src/internal/platform/supported.go", "src/cmd/go/internal/work/build.go", "src/cmd/go/internal/work/gc.go"} {
		data, err := guard.read(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		rule = append(rule, data)
	}
	if err := verifyGoAssemblyDataAlignmentRule(rule[0], rule[1], rule[2], rule[3]); err != nil {
		return err
	}
	if err := verifyGoLiteralDefaultPIE(rule[10]); err != nil {
		return err
	}
	graph, err := observed.run(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", "runtime", observed.observation.PackagePath)
	if err != nil {
		return err
	}
	imports, err := observed.bindLinkGraph(graph)
	if err != nil {
		return err
	}
	guard.imports, observed.observation.Graph = imports, graph
	for _, selected := range append([]goAMD64FrameSelection{guard.selection}, frameImportGraphValues(imports)...) {
		if !selected.Standard || selected.Module != nil {
			return sdkASMDataContext("minimum alignment graph is not the invoked SDK")
		}
		if err := observed.retainDirectory(selected.Dir); err != nil {
			return err
		}
	}
	archives := make(map[string]gostaticstorage.SDKReferencedArchive)
	var config strings.Builder
	selected := make(map[string]goAMD64FrameSelection, len(imports)+1)
	for path, dependency := range imports {
		selected[path] = dependency
	}
	selected[guard.selection.ImportPath] = guard.selection
	paths := make([]string, 0, len(selected))
	for path := range selected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		dependency := selected[path]
		if path == "unsafe" {
			continue
		}
		if strings.ContainsAny(path, "\x00\r\n=\\ \t") || strings.ContainsAny(dependency.Export, "\x00\r\n") || strings.TrimSpace(dependency.Export) != dependency.Export {
			return sdkASMDataContext("minimum alignment importcfg is not exact")
		}
		archive, err := guard.read(dependency.Export)
		if err != nil {
			return err
		}
		archives[path] = gostaticstorage.SDKReferencedArchive{PackagePath: path, Sources: dependency.SFiles, Archive: archive}
		fmt.Fprintf(&config, "packagefile %s=%s\n", path, dependency.Export)
	}
	inventory, err := gostaticstorage.SDKArchiveDefinitionInventory(archives, observed.observation.Target)
	if err != nil {
		return err
	}
	program := "package main\nfunc main() {}\n"
	pkg := observed.observation.PackagePath
	if !strings.HasPrefix(pkg, "internal/") && !strings.Contains(pkg, "/internal/") {
		program = "package main\nimport _ " + strconv.Quote(pkg) + "\nfunc main() {}\n"
	}
	// No internal import bypass: a direct compile has no such import at all.
	// Only the ordinary runtime link can naturally retain internal candidates.
	main, err := observed.artifact("main.go", []byte(program))
	if err != nil {
		return err
	}
	configPath, err := observed.artifact("importcfg", []byte(config.String()))
	if err != nil {
		return err
	}
	object, image := filepath.Join(guard.owned, "main.a"), filepath.Join(guard.owned, "original-linked")
	args := []string{"tool", "compile", "-p", "main", "-lang=go1.27", "-goversion", guard.env["GOVERSION"], "-importcfg", configPath, "-o", object}
	if guard.env["GOOS"] == "darwin" {
		args = append(args, "-shared")
	}
	args = append(args, main)
	if _, err := observed.run(ctx, args...); err != nil {
		return err
	}
	if _, err := guard.read(object); err != nil {
		return err
	}
	args = []string{"tool", "link", "-buildmode=" + observed.observation.BuildMode, "-importcfg", configPath, "-o", image, object}
	if _, err := observed.run(ctx, args...); err != nil {
		return err
	}
	linked, err := guard.read(image)
	if err != nil {
		return err
	}
	observed.owner.mu.Lock()
	initializerBytes := append([]byte(nil), observed.owner.report...)
	observed.owner.mu.Unlock()
	var initializer sdkReadonlyLiteralDataReport
	if json.Unmarshal(initializerBytes, &initializer) != nil {
		return sdkASMDataContext("minimum alignment lost exact initializers")
	}
	minima, err := sdkLiteralLinkedMinima(linked, observed.observation.Target, pkg, initializer.Initializers, inventory)
	if err != nil {
		return err
	}
	if len(minima) == 0 {
		return sdkASMDataContext("no uniquely retained original literal has observed minimum alignment")
	}
	observed.observation.Minima = minima
	return nil
}

func (observed *GoX86SDKLiteralAlignment) artifact(name string, data []byte) (string, error) {
	path := filepath.Join(observed.guard.owned, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	_, err := observed.guard.read(path)
	return path, err
}

func (observed *GoX86SDKLiteralAlignment) retainDirectory(name string) error {
	resolved, err := sourcepath.Resolve(name)
	info, statErr := sourcepath.Lstat(name)
	if err != nil || statErr != nil || resolved != name || !filepath.IsAbs(name) || !info.IsDir() {
		return sdkASMDataContext("minimum alignment directory is redirected or unavailable")
	}
	observed.directories[name] = info
	return nil
}

func (observed *GoX86SDKLiteralAlignment) verifyDirectories() error {
	for name, before := range observed.directories {
		resolved, err := sourcepath.Resolve(name)
		after, statErr := sourcepath.Lstat(name)
		if err != nil || statErr != nil || resolved != name || !after.IsDir() || !os.SameFile(before, after) {
			return sdkASMDataContext("minimum alignment input directory identity changed")
		}
	}
	return nil
}

func (observed *GoX86SDKLiteralAlignment) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := errors.Join(observed.guard.verifyInputs(), observed.verifyDirectories(), ctx.Err()); err != nil {
		return nil, err
	}
	commandContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	output, err := goasmcmd.Run(commandContext, observed.guard.request.Directory, observed.guard.request.Environment, observed.guard.request.GoBinary, args...)
	err = errors.Join(err, commandContext.Err(), observed.guard.verifyInputs(), observed.verifyDirectories())
	if err == nil {
		observed.observation.Commands = append(observed.observation.Commands, numericalSBCommand{
			Directory: observed.guard.request.Directory, Binary: observed.guard.request.GoBinary,
			Arguments: append([]string(nil), args...), Stdout: append([]byte(nil), output...)})
	}
	return output, err
}

func (observed *GoX86SDKLiteralAlignment) liveContext(ctx context.Context) error {
	if ctx == nil || observed.context == nil || observed.originalContext == nil ||
		reflect.TypeOf(observed.context) != reflect.TypeOf(observed.originalContext) || !reflect.TypeOf(observed.context).Comparable() || observed.context != observed.originalContext {
		return sdkASMDataContext("minimum alignment original context identity changed")
	}
	_, err := sampleGoSourceContext(ctx, observed.context,
		goSourceContextLifetime{deadline: observed.deadline, bounded: true}, false,
		sdkASMDataContext("minimum alignment original deadline changed or canceled without a cause"))
	return err
}

func (observed *GoX86SDKLiteralAlignment) verifyOwner() error {
	owner := observed.owner
	if owner == nil || owner != observed.originalOwner || owner.identity != owner {
		return sdkASMDataContext("minimum alignment borrowed another initializer")
	}
	owner.mu.Lock()
	valid := owner.ready && owner.generation == observed.ownerGeneration && owner.seal == observed.ownerSeal && sha256.Sum256(owner.report) == observed.ownerSeal
	owner.mu.Unlock()
	if !valid {
		return sdkASMDataContext("minimum alignment initializer is closed, stale or changed")
	}
	return owner.verifySourceGeneration()
}

func (observed *GoX86SDKLiteralAlignment) digest() ([32]byte, error) {
	raw, err := json.Marshal(struct {
		Observation sdkLiteralAlignmentReport
		Request     GoAMD64FrameCaptureRequest
		Inputs      map[string][32]byte
		Environment map[string]string
		Selection   goAMD64FrameSelection
		Imports     map[string]goAMD64FrameSelection
		Deadline    time.Time
	}{observed.observation, observed.guard.request, observed.guard.inputs, observed.guard.env, observed.guard.selection, observed.guard.imports, observed.deadline})
	return sha256.Sum256(raw), err
}

// Verify invokes caller contexts/borrowed owners outside locks. A lease protects
// only the factory's own artifacts during callback reentry and Close.
func (observed *GoX86SDKLiteralAlignment) Verify(ctx context.Context) (result error) {
	if observed == nil || observed.identity != observed {
		return sdkASMDataContext("copied or missing minimum alignment observation")
	}
	observed.mu.Lock()
	ready, generation := observed.ready, observed.generation
	if ready {
		observed.active++
	}
	observed.mu.Unlock()
	if !ready {
		return sdkASMDataContext("minimum alignment observation is closed or revoked")
	}
	defer func() {
		result = errors.Join(result, observed.liveContext(ctx), observed.verifyOwner())
		observed.mu.Lock()
		if observed.generation != generation || !observed.ready {
			result = errors.Join(result, sdkASMDataContext("minimum alignment closed during verification"))
		}
		if result != nil {
			observed.ready = false
			observed.generation++
		}
		observed.active--
		cleanup := observed.closePending && observed.active == 0
		observed.mu.Unlock()
		if cleanup {
			observed.operation.Lock()
			result = errors.Join(result, observed.guard.Close())
			observed.operation.Unlock()
		}
	}()
	if err := observed.liveContext(ctx); err != nil {
		return err
	}
	if err := observed.verifyOwner(); err != nil {
		return err
	}
	if err := observed.owner.Verify(ctx); err != nil {
		return err
	}
	private, stop, err := sdkASMDataPrivateContext(ctx, observed.context, observed.deadline)
	if err != nil {
		return err
	}
	defer stop()
	observed.operation.Lock()
	result = observed.verifyState(private)
	observed.operation.Unlock()
	if result != nil {
		return result
	}
	return observed.owner.Verify(ctx)
}

func (observed *GoX86SDKLiteralAlignment) verifyState(ctx context.Context) error {
	guard := observed.guard
	if guard == nil || guard != observed.originalGuard || guard.identity != guard || guard.ready || guard.request.NumericalReads != nil || guard.numericalOrigin != nil || guard.downloadedOrigin != nil {
		return sdkASMDataContext("minimum alignment guard acquired a foreign authority")
	}
	before, err := observed.digest()
	if err != nil || before != observed.stateSeal || sha256.Sum256(observed.report) != observed.seal {
		return sdkASMDataContext("minimum alignment sealed source/linker/profile/object state changed")
	}
	commands := observed.observation.Commands
	defer func() { observed.observation.Commands = commands }()
	graph, err := observed.run(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", "runtime", observed.observation.PackagePath)
	if err != nil {
		return err
	}
	imports, err := observed.bindLinkGraph(graph)
	if err != nil || !reflect.DeepEqual(imports, guard.imports) || !numericalSameRawSDKGraph(graph, observed.observation.Graph) {
		return sdkASMDataContext("minimum alignment complete original SDK graph changed: %v", err)
	}
	observed.observation.Commands = commands
	after, err := observed.digest()
	if err != nil || after != observed.stateSeal {
		return sdkASMDataContext("minimum alignment source/linker inputs changed during verification")
	}
	return errors.Join(guard.verifyInputs(), observed.verifyDirectories(), ctx.Err())
}

func (observed *GoX86SDKLiteralAlignment) Readback(ctx context.Context) ([]byte, error) {
	if err := observed.Verify(ctx); err != nil {
		return nil, err
	}
	observed.mu.Lock()
	defer observed.mu.Unlock()
	if !observed.ready {
		return nil, sdkASMDataContext("minimum alignment closed after verification")
	}
	return append([]byte(nil), observed.report...), nil
}

func (observed *GoX86SDKLiteralAlignment) CheckReadback(ctx context.Context, raw []byte) error {
	actual, err := observed.Readback(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, raw) {
		observed.mu.Lock()
		observed.ready = false
		observed.generation++
		observed.mu.Unlock()
		return sdkASMDataContext("minimum alignment public report bytes differ")
	}
	return nil
}

func (observed *GoX86SDKLiteralAlignment) Close() error {
	if observed == nil {
		return nil
	}
	if observed.identity != observed || observed.guard == nil || observed.guard != observed.originalGuard || observed.guard.identity != observed.guard {
		return sdkASMDataContext("copied minimum alignment cannot dispose original artifacts")
	}
	observed.mu.Lock()
	observed.ready = false
	observed.generation++
	observed.closePending = true
	active := observed.active
	observed.mu.Unlock()
	if active != 0 {
		return nil
	}
	observed.operation.Lock()
	defer observed.operation.Unlock()
	return observed.guard.Close()
}
