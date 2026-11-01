package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type GoX86NumericalReadCaptureRequest struct {
	GoBinary, Directory, PackagePath, AssemblyFile, Target string
	Environment                                            []string
	Owners                                                 []*GoNumericalStorageOwner

	// ReadonlyLiterals explicitly selects the same live SDK assembly source's
	// independent private literal initializer role. Nil retains the TEXT-only
	// boundary. Ordinary owned-main capture cannot consume this SDK role.
	// This is not a numerical variable, pointer, caller or native-entry owner.
	// The borrowed owner and its original SDK source must remain live through
	// binding and translation; closing this numerical source never closes them.
	ReadonlyLiterals *GoX86SDKReadonlyLiteralDataOwner

	// AssemblySource observes complete original/expanded/compiler source nodes
	// independently of DATA initialization. It grants no numerical storage or
	// entry state. Nil preserves the existing ordinary TEXT-only route.
	AssemblySource *GoX86SDKASMDataSource
}

// GoX86NumericalReadSource is a sealed source/native-instruction/numerical-owner
// join. Capture alone supplies no Options, LLVM load, caller or entry authority.
// Ordinary owned-main and explicit independently observed SDK sources retain
// separate roles. External sources and generated headers without an explicit
// independent SDK source observation remain Context.
type GoX86NumericalReadSource struct {
	mu                           sync.Mutex
	revoked                      atomic.Bool
	identity                     *GoX86NumericalReadSource
	ready                        bool
	request                      GoX86NumericalReadCaptureRequest
	guard                        *GoAMD64FrameSource // private reuse of file/command guards, NOT its factory or frame role
	dirs                         map[string]os.FileInfo
	misses                       map[string]bool
	file                         *File
	cpp                          AssemblyCPPObservation
	reads                        []numericalSBRead
	native                       numericalSBNativeProof
	report                       []byte
	seal                         [32]byte
	stateSeal                    [32]byte
	rawSelection, rawEnvironment []byte
	originalOwners               []*GoNumericalStorageOwner
	commands                     []numericalSBCommand
	role                         numericalSBSourceRole
	sdk                          *numericalSBSDKObservation
	literals                     *numericalSDKLiteralJoin
	assembly                     *numericalSDKAssemblyJoin
}

type numericalSBCommand struct {
	Directory, Binary string
	Arguments         []string
	Stdout            []byte
}

func CaptureGoX86NumericalReadSource(ctx context.Context, request GoX86NumericalReadCaptureRequest) (*GoX86NumericalReadSource, error) {
	return captureGoX86NumericalReadSource(ctx, request, numericalSBOwnedSource, false)
}

func captureGoX86NumericalReadSource(ctx context.Context, request GoX86NumericalReadCaptureRequest,
	role numericalSBSourceRole, inputsOnly bool,
) (_ *GoX86NumericalReadSource, result error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("capture numerical read source: %w", ctx.Err())
	}
	if role != numericalSBOwnedSource && role != numericalSBSDKSource || inputsOnly && role != numericalSBSDKSource ||
		ctx == nil || !gostaticstorage.X86SDKTarget(request.Target) ||
		role == numericalSBOwnedSource && request.Target != "linux/386" && request.Target != "linux/amd64" ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) || request.PackagePath == "" ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || !strings.HasSuffix(request.AssemblyFile, ".s") ||
		len(request.Owners) == 0 || len(request.Owners) > 8 {
		return nil, numericalSBContext("needs bounded actual x86 source/tool/owner inputs")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, numericalSBContext("requires bounded live context")
	}
	request.Environment = append([]string(nil), request.Environment...)
	request.Owners = append([]*GoNumericalStorageOwner(nil), request.Owners...)
	literals, err := captureNumericalSDKLiteralJoin(ctx, request, role)
	if err != nil {
		return nil, err
	}
	assembly, err := captureNumericalSDKAssemblyJoin(ctx, request, role)
	if err != nil {
		return nil, err
	}
	provided := make(map[string]string)
	for _, pair := range request.Environment {
		key, value, valid := strings.Cut(pair, "=")
		if !valid || key == "" {
			return nil, numericalSBContext("malformed actual command environment")
		}
		if _, duplicate := provided[key]; duplicate {
			return nil, numericalSBContext("duplicate actual command environment")
		}
		provided[key] = value
	}
	goos, arch, _ := strings.Cut(request.Target, "/")
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2",
		"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOPROXY": "off"} {
		if key == "CGO_ENABLED" && role == numericalSBSDKSource && (provided[key] == "0" || provided[key] == "1") {
			continue // Complete selected SDK graph still rejects every cgo/generated source.
		}
		if provided[key] != value {
			return nil, numericalSBContext("unbound actual command profile: %s", key)
		}
	}
	if provided["GOPACKAGESDRIVER"] != "" && provided["GOPACKAGESDRIVER"] != "off" {
		return nil, numericalSBContext("external package driver needs independent mapping")
	}
	source := &GoX86NumericalReadSource{request: request, role: role, literals: literals, assembly: assembly, dirs: make(map[string]os.FileInfo), misses: make(map[string]bool),
		originalOwners: append([]*GoNumericalStorageOwner(nil), request.Owners...)}
	source.identity = source
	source.guard = newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary, Directory: request.Directory,
		AssemblyFile: request.AssemblyFile, Target: request.Target, Environment: request.Environment})
	for _, directory := range append([]string{request.Directory}, provided["GOCACHE"], provided["GOMODCACHE"], provided["GOPATH"], provided["TMPDIR"], provided["GOTMPDIR"]) {
		if err := source.retainDirectory(directory); err != nil {
			return nil, err
		}
	}
	snapshot := source.guard.snapshotDirectory
	if role == numericalSBSDKSource {
		snapshot = func() error {
			return captureSDKPackageDirectoryInputs(source.guard, source.retainDirectory)
		}
	}
	if err := snapshot(); err != nil {
		return nil, err
	}
	owned, err := os.MkdirTemp(provided["TMPDIR"], "plan9asm-numerical-read-")
	if err != nil {
		return nil, err
	}
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		return nil, err
	}
	source.guard.owned = owned
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	// Canonicalize only the freshly factory-created directory, never caller inputs.
	canonicalOwned, err := sourcepath.Resolve(owned)
	info, statErr := os.Lstat(canonicalOwned)
	if err != nil || statErr != nil || !info.IsDir() || !os.SameFile(source.guard.ownedInfo, info) || !goAssemblyPathWithinRoot(provided["TMPDIR"], canonicalOwned) {
		return nil, numericalSBContext("new factory artifact role changed during canonicalization")
	}
	source.guard.owned = canonicalOwned
	if err := source.observe(ctx, provided); err != nil {
		return nil, err
	}
	selected, rawSelection, err := source.guard.loadWithRawPackage(ctx, source.packageQuery())
	if err != nil {
		return nil, err
	}
	source.guard.selection = selected
	source.rawSelection = append([]byte(nil), rawSelection...)
	source.recordCommand(rawSelection, "list", "-json", "-compiled", "-export", "-mod=readonly", source.packageQuery())
	if selected.ImportPath != request.PackagePath || selected.Dir != request.Directory || selected.ForTest != "" || selected.nonordinaryRole() ||
		len(selected.GoFiles) == 0 || len(selected.SFiles) == 0 || len(selected.SFiles) > 32 {
		return nil, numericalSBContext("consumer needs complete original source selection")
	}
	if err := source.captureSourceRole(ctx); err != nil {
		return nil, err
	}
	var reports []gostaticstorage.Report
	variables := make(map[string]numericalSBRead)
	mainRootBound := role == numericalSBOwnedSource && selected.Module.Dir == request.Directory
	for ordinal, owner := range request.Owners {
		if err := owner.Verify(ctx); err != nil {
			return nil, err
		}
		report, err := owner.observation.Readback(ctx)
		if err != nil {
			return nil, numericalStorageFailure(ctx, "capture numerical read owner readback", err)
		}
		if report.Target != request.Target || report.Tools["go"] != source.toolHash(request.GoBinary) ||
			report.Tools["compile"] != source.toolHash(filepath.Join(source.guard.env["GOTOOLDIR"], gotoolchain.HostExecutable("compile"))) {
			return nil, numericalSBContext("owner source/tool/profile differs")
		}
		if report.Protocol == gostaticstorage.SDKGlobalsProtocol {
			if role != numericalSBSDKSource || report.PackagePath != request.PackagePath || report.CommandDirectory != request.Directory ||
				report.CommandBinary != request.GoBinary || report.Environment["CGO_ENABLED"] != provided["CGO_ENABLED"] {
				return nil, numericalSBContext("SDK Go global owner differs from this complete original selected package/profile")
			}
		} else if report.Protocol != gostaticstorage.SDKCPUProtocol {
			if role != numericalSBOwnedSource || report.CommandDirectory != selected.Module.Dir || report.PackagePath != selected.Module.Path {
				return nil, numericalSBContext("numerical owner is not the actual same main module")
			}
			mainRootBound = true
		} else if report.CommandDirectory != filepath.Join(source.guard.env["GOROOT"], "src", "internal", "cpu") {
			return nil, numericalSBContext("SDK numerical owner is not this selected original installation")
		}
		for _, variable := range report.Variables {
			if _, duplicate := variables[variable.NativeName]; duplicate {
				return nil, numericalSBContext("duplicate numerical owner identity")
			}
			variables[variable.NativeName] = numericalSBRead{variable: variable, owner: owner, ownerOrdinal: ordinal}
		}
		reports = append(reports, report)
	}
	if role == numericalSBOwnedSource && !mainRootBound {
		return nil, numericalSBContext("nested consumer lacks complete original module inventory owner")
	}
	// Imports cannot borrow a CPU assembly reference as a Go graph certificate.
	// Same-main dependencies must be present in an actual owner selection/export.
	if role == numericalSBOwnedSource {
		if err := source.bindImports(reports); err != nil {
			return nil, err
		}
	} else if err := source.verifySDKObservation(ctx); err != nil {
		return nil, err
	}
	// This private observation stop has no public request flag and no ready
	// numerical source, binding, instruction certificate or LLVM permission.
	if inputsOnly {
		return source, nil
	}
	if err := source.bindNative(ctx, variables, provided); err != nil {
		return nil, err
	}
	source.report, err = json.Marshal(struct {
		Request                      GoX86NumericalReadCaptureRequest
		CPP                          AssemblyCPPObservation
		File                         *File
		Selection                    goAMD64FrameSelection
		Inputs                       map[string][32]byte
		Owners                       []gostaticstorage.Report
		Native                       numericalSBNativeProof
		RawSelection, RawEnvironment []byte
		Commands                     []numericalSBCommand
		Reads                        []numericalSBReadFact
		Role                         numericalSBSourceRole
		SDK                          *numericalSBSDKObservation
		Literals                     *numericalSDKLiteralJoin
		Assembly                     *numericalSDKAssemblyJoin
	}{request, source.cpp, source.file, selected, source.guard.inputs, reports, source.native, source.rawSelection, source.rawEnvironment, source.commands, source.readFacts(), role, source.sdk, source.literals, source.assembly})
	if err != nil {
		return nil, err
	}
	source.seal, source.ready = sha256.Sum256(source.report), true
	source.stateSeal, err = source.stateDigest()
	if err != nil {
		return nil, err
	}
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *GoX86NumericalReadSource) retainDirectory(directory string) error {
	resolved, err := sourcepath.Resolve(directory)
	info, statErr := sourcepath.Lstat(directory)
	if !filepath.IsAbs(directory) || err != nil || resolved != directory || statErr != nil || !info.IsDir() {
		return numericalSBContext("redirected or missing command/source root")
	}
	source.dirs[directory] = info
	return nil
}

func (source *GoX86NumericalReadSource) recordCommand(stdout []byte, arguments ...string) {
	source.commands = append(source.commands, numericalSBCommand{source.request.Directory, source.request.GoBinary,
		append([]string(nil), arguments...), append([]byte(nil), stdout...)})
}

func (source *GoX86NumericalReadSource) run(ctx context.Context, arguments ...string) ([]byte, error) {
	stdout, err := source.guard.run(ctx, arguments...)
	if err == nil {
		source.recordCommand(stdout, arguments...)
	}
	return stdout, err
}

func (source *GoX86NumericalReadSource) toolHash(file string) string {
	digest := source.guard.inputs[file]
	return hex.EncodeToString(digest[:])
}

func (source *GoX86NumericalReadSource) observe(ctx context.Context, provided map[string]string) error {
	if _, err := source.guard.read(source.request.GoBinary); err != nil {
		return err
	}
	raw, err := source.run(ctx, "env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOOS", "GOARCH", "GOAMD64", "GO386", "GOFLAGS", "GOEXPERIMENT", "GOCACHE", "GOMODCACHE", "CGO_ENABLED")
	if err != nil {
		return err
	}
	var env map[string]string
	if json.Unmarshal(raw, &env) != nil || !gotoolchain.AuditedGo127(env["GOVERSION"]) || env["GOOS"]+"/"+env["GOARCH"] != source.request.Target ||
		filepath.Join(env["GOROOT"], "bin", gotoolchain.HostExecutable("go")) != source.request.GoBinary || env["GOAMD64"] != "v1" ||
		env["GOARCH"] == "386" && env["GO386"] != "sse2" || env["GOFLAGS"] != "" || env["GOEXPERIMENT"] != "" ||
		env["GOCACHE"] != provided["GOCACHE"] || env["GOMODCACHE"] != provided["GOMODCACHE"] {
		return numericalSBContext("actual SDK/tool/profile differs")
	}
	if env["CGO_ENABLED"] != provided["CGO_ENABLED"] {
		return numericalSBContext("actual selected SDK cgo profile differs from the original command")
	}
	if source.role == numericalSBOwnedSource {
		if err := gostaticstorage.ValidateOwnedSourceDirectory(source.request.Directory, env["GOROOT"], env["GOMODCACHE"]); err != nil {
			return numericalStorageFailure(ctx, "numerical original owned source role", err)
		}
	} else if err := source.verifySDKDirectory(env["GOROOT"]); err != nil {
		return err
	}
	source.guard.env = env
	source.rawEnvironment = append([]byte(nil), raw...)
	for _, directory := range []string{env["GOROOT"], env["GOTOOLDIR"], filepath.Join(env["GOROOT"], "pkg", "include")} {
		resolved, err := sourcepath.Resolve(directory)
		info, statErr := sourcepath.Lstat(directory)
		if err != nil || resolved != directory || statErr != nil || !info.IsDir() {
			return numericalSBContext("SDK directory role is missing or redirected")
		}
		source.dirs[directory] = info
	}
	for _, tool := range []string{"asm", "compile"} {
		route, err := source.run(ctx, "tool", "-n", tool)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(route)) != filepath.Join(env["GOTOOLDIR"], gotoolchain.HostExecutable(tool)) {
			return numericalSBContext("unknown actual %s route", tool)
		}
		if _, err := source.guard.read(strings.TrimSpace(string(route))); err != nil {
			return err
		}
	}
	for _, role := range []string{"VERSION", "src/cmd/internal/goobj/builtinlist.go", "src/cmd/internal/obj/x86/asm6.go", "src/cmd/internal/obj/x86/obj6.go",
		"src/cmd/go/internal/work/gc.go", "src/cmd/go/internal/load/pkg.go", "src/cmd/asm/main.go", "src/cmd/asm/internal/lex/input.go", "src/cmd/asm/internal/lex/stack.go", "src/cmd/asm/internal/lex/tokenizer.go"} {
		if _, err := source.guard.read(filepath.Join(env["GOROOT"], filepath.FromSlash(role))); err != nil {
			return err
		}
	}
	return nil
}

func (source *GoX86NumericalReadSource) bindImports(reports []gostaticstorage.Report) error {
	selected := source.guard.selection
	for _, path := range selected.Imports {
		if path == "unsafe" {
			continue
		}
		mapped := path
		if selected.ImportMap[path] != "" {
			mapped = selected.ImportMap[path]
		}
		found := false
		for _, report := range reports {
			if report.Protocol == gostaticstorage.SDKCPUProtocol {
				continue
			}
			decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
			for decoder.More() {
				var pkg gostaticstorage.Package
				if decoder.Decode(&pkg) != nil {
					return numericalSBContext("invalid live owner selection")
				}
				found = found || pkg.ImportPath == mapped && pkg.Module != nil && pkg.Module.Main && pkg.Module.Dir == selected.Module.Dir
			}
		}
		if !found || mapped != path {
			return numericalSBContext("unbound consumer import/namespace role")
		}
	}
	return nil
}

func (source *GoX86NumericalReadSource) preprocess() error {
	if source.sdkAssemblyJoin() != nil {
		return source.preprocessSDKAssembly()
	}
	guard := source.guard
	original, err := guard.read(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil {
		return err
	}
	source.cpp, err = ObserveAssemblyCPP(string(original), AssemblyPreprocessOptions{FileName: filepath.Join(source.request.Directory, source.request.AssemblyFile),
		Defines: GoAssemblerDefinesWithEnv(guard.env["GOOS"], guard.env["GOARCH"], guard.env),
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if filepath.Base(name) != name || name == "go_asm.h" {
				return "", nil, numericalSBContext("generated/relative header needs separate actual compiler agreement")
			}
			candidate := filepath.Join(source.request.Directory, name)
			_, statErr := os.Lstat(candidate)
			if os.IsNotExist(statErr) {
				source.misses[candidate] = true
				candidate = filepath.Join(guard.env["GOROOT"], "pkg", "include", name)
			} else if statErr != nil {
				return "", nil, statErr
			}
			data, err := guard.read(candidate)
			return candidate, data, err
		}})
	if err != nil {
		return err
	}
	source.file, err = Parse(ArchAMD64, source.cpp.Output)
	if err != nil || len(source.file.Funcs) == 0 || len(source.file.Data) != 0 || len(source.file.Globl) != 0 || len(source.file.UnlinkedPrelude) != 0 {
		return numericalSBContext("source is not a bounded TEXT-only program: %v", err)
	}
	return nil
}

func (source *GoX86NumericalReadSource) Verify(ctx context.Context) error {
	if source != nil && source.revoked.Load() {
		return numericalSBContext("read source publication is permanently revoked")
	}
	var result error
	if source != nil && source.literals != nil {
		result = source.verifySDKLiteralNumericalSource(ctx)
	} else if source != nil && source.assembly != nil {
		result = source.verifySDKAssemblyNumericalSource(ctx)
	} else {
		result = source.verifyNumericalSource(ctx)
	}
	// SDK verification also samples the original caller context in its final
	// defer. Revoke is lock-free and changes no ready/owner generation, so
	// authenticate its publication token after every such callback has returned.
	if source != nil && source.revoked.Load() {
		result = errors.Join(result, numericalSBContext("read source publication revoked during verification"))
	}
	return result
}

func (source *GoX86NumericalReadSource) verifyNumericalSource(ctx context.Context) error {
	if source == nil {
		return numericalSBContext("missing live read source")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready || source.identity != source || source.revoked.Load() {
		source.ready = false
		return numericalSBContext("read source is closed/revoked")
	}
	fail := func(err error) error { source.ready = false; return err }
	// Any failed live Verify permanently revokes this source, including an
	// invalid caller context. A fresh context cannot revive a failed lease.
	if ctx != nil && ctx.Err() != nil {
		return fail(fmt.Errorf("verify numerical read source: %w", ctx.Err()))
	}
	if ctx == nil {
		return fail(numericalSBContext("live verification requires an unexpired context"))
	}
	if len(source.request.Owners) != len(source.originalOwners) {
		return fail(numericalSBContext("sealed owner identity/order changed"))
	}
	for ordinal, owner := range source.request.Owners {
		if owner != source.originalOwners[ordinal] {
			return fail(numericalSBContext("sealed owner identity/order changed"))
		}
	}
	if sha256.Sum256(source.report) != source.seal {
		return fail(numericalSBContext("sealed read report changed"))
	}
	state, err := source.stateDigest()
	if err != nil || state != source.stateSeal {
		return fail(numericalSBContext("sealed source/native/read join changed"))
	}
	for directory, before := range source.dirs {
		resolved, err := sourcepath.Resolve(directory)
		now, statErr := os.Lstat(directory)
		if err != nil || resolved != directory || statErr != nil || !now.IsDir() || !os.SameFile(before, now) {
			return fail(numericalSBContext("source/cache/temp directory role changed"))
		}
	}
	for name := range source.misses {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			return fail(numericalSBContext("CPP preferred-search miss changed"))
		}
	}
	if err := source.guard.verifyInputs(); err != nil {
		return fail(err)
	}
	if source.sdkAssemblyJoin() == nil {
		for _, owner := range source.request.Owners {
			if err := owner.Verify(ctx); err != nil {
				return fail(err)
			}
		}
	}
	for _, read := range source.reads {
		if read.ownerOrdinal < 0 || read.ownerOrdinal >= len(source.originalOwners) || read.owner != source.originalOwners[read.ownerOrdinal] {
			return fail(numericalSBContext("joined read owner identity changed"))
		}
	}
	if source.role == numericalSBSDKSource {
		if err := source.verifySDKObservation(ctx); err != nil {
			return fail(err)
		}
	} else {
		selected, raw, err := source.guard.loadWithRawPackage(ctx, source.packageQuery())
		if err != nil {
			return fail(err)
		}
		if !reflect.DeepEqual(selected, source.guard.selection) || !numericalSameRawSelection(source.rawSelection, raw) {
			return fail(numericalSBContext("actual consumer selection/export changed"))
		}
	}
	if err := source.guard.verifyInputs(); err != nil {
		return fail(err)
	}
	return nil
}

func (source *GoX86NumericalReadSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.ready = false
	if source.guard == nil {
		return nil
	}
	if source.identity != source {
		return numericalSBContext("copied numerical source cannot close the original artifact owner")
	}
	if source.sdk != nil {
		source.sdk.closed = true
	}
	return source.guard.Close()
}

// Readback returns retained portable whole bytes for inspection only. Neither
// this JSON nor any edited/copy report can reconstruct a source or Options.
func (source *GoX86NumericalReadSource) Readback(ctx context.Context) ([]byte, error) {
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready || source.revoked.Load() {
		return nil, numericalSBContext("read source closed after verification")
	}
	return append([]byte(nil), source.report...), nil
}

// CheckReadback compares complete retained bytes with the live factory seal.
// This is not a constructor or a permission derived from self-consistent JSON.
func (source *GoX86NumericalReadSource) CheckReadback(ctx context.Context, raw []byte) error {
	if err := source.Verify(ctx); err != nil {
		return err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready || source.revoked.Load() || sha256.Sum256(raw) != source.seal {
		return numericalSBContext("readback differs from actual sealed source/object/owner outputs")
	}
	return nil
}

type numericalSBReadFact struct {
	Function             string
	Instruction, Operand int
	Owner                int // portable ordinal; private exact identity/order is checked separately
	Original             Instr
	PC, Offset, Width    int64
	Code                 []byte
	Relocation           gostaticstorage.TextRelocation
	Variable             gostaticstorage.Variable
}

func (source *GoX86NumericalReadSource) readFacts() []numericalSBReadFact {
	facts := make([]numericalSBReadFact, 0, len(source.reads))
	for _, read := range source.reads {
		facts = append(facts, numericalSBReadFact{read.function, read.instruction, read.operand, read.ownerOrdinal, read.original, read.pc, read.offset, read.width, read.code, read.relocation, read.variable})
	}
	return facts
}

func (source *GoX86NumericalReadSource) stateDigest() ([32]byte, error) {
	raw, err := json.Marshal(struct {
		Request                      GoX86NumericalReadCaptureRequest
		CPP                          AssemblyCPPObservation
		File                         *File
		Native                       numericalSBNativeProof
		Selection                    goAMD64FrameSelection
		Inputs                       map[string][32]byte
		Reads                        []numericalSBReadFact
		RawSelection, RawEnvironment []byte
		Commands                     []numericalSBCommand
		Role                         numericalSBSourceRole
		SDK                          *numericalSBSDKObservation
		Literals                     *numericalSDKLiteralJoin
		Assembly                     *numericalSDKAssemblyJoin
	}{source.request, source.cpp, source.file, source.native, source.guard.selection, source.guard.inputs, source.readFacts(), source.rawSelection, source.rawEnvironment, source.commands, source.role, source.sdk, source.literals, source.assembly})
	return sha256.Sum256(raw), err
}

// As in the numerical owner's selection reader, SDK load/pkg.go reports
// Stale/StaleReason before list -export builds the archive. The sealed factory
// retains that SDK source and both whole stdout roles; only these official
// bool/string display fields may differ on a repeated actual command.
func numericalSameRawSelection(first, second []byte) bool {
	decode := func(raw []byte) (map[string]json.RawMessage, bool) {
		var value map[string]json.RawMessage
		if len(raw) > 4<<20 || json.Unmarshal(raw, &value) != nil || value == nil {
			return nil, false
		}
		for key, data := range value {
			if key == "Stale" {
				var display bool
				if string(data) == "null" || json.Unmarshal(data, &display) != nil {
					return nil, false
				}
				delete(value, key)
			} else if key == "StaleReason" {
				var display string
				if string(data) == "null" || json.Unmarshal(data, &display) != nil {
					return nil, false
				}
				delete(value, key)
			} else {
				var compact bytes.Buffer
				if json.Compact(&compact, data) != nil {
					return nil, false
				}
				value[key] = compact.Bytes()
			}
		}
		return value, true
	}
	a, validA := decode(first)
	b, validB := decode(second)
	return validA && validB && reflect.DeepEqual(a, b)
}
