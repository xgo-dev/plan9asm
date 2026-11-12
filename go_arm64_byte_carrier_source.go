package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type GoARM64ByteCarrierCaptureRequest struct {
	GoBinary, Directory, PackagePath, AssemblyFile, Target string
	Environment                                            []string
}

// GoARM64ByteCarrierSource observes a complete private numeric source, original
// compiler entries and same-file ABI0 caller/callee objects. Capture and its
// portable readback do not provide Options, writable padding or entry authority.
type GoARM64ByteCarrierSource struct {
	mu           sync.Mutex
	identity     *GoARM64ByteCarrierSource
	ready        bool
	lease        context.Context // the original bounded capture lease, never supplied by a report or later Options
	request      GoARM64ByteCarrierCaptureRequest
	guard        *GoAMD64FrameSource // physical inputs/commands/cleanup only; no frame factory
	dirs         map[string]os.FileInfo
	files        map[string]os.FileInfo
	file         *File
	declarations map[string]FuncSig
	report       arm64ByteCarrierReport
	raw          []byte
	seal         [32]byte
	stateSeal    [32]byte
}

type arm64ByteCarrierReport struct {
	Protocol                     string
	NativePackagePath            string
	Request                      GoARM64ByteCarrierCaptureRequest
	RawSelection, RawEnvironment []byte
	Sources                      map[string][]byte
	Inputs                       map[string][32]byte
	OriginalArchive              []byte
	OriginalObject               []byte
	OriginalListing              []byte
	Archive                      []gostaticstorage.TextMember
	Standalone                   []gostaticstorage.TextRecord
	Declarations                 map[string]string
	Calls                        []arm64ByteCarrierCall
	Commands                     []numericalSBCommand
}

// A call observation binds exact original bytes and its physical continuation.
// It is deliberately not a writable extent, native-state lease or FrameLayout.
type arm64ByteCarrierCall struct {
	Caller, Callee          string
	SourceInstruction       int
	CallPC, ContinuationPC  int64
	CallerCode, CalleeCode  [32]byte
	OriginalCall            gostaticstorage.TextRelocation
	Position                gostaticstorage.TextPosition
	CalleeSPReads, SPWrites []arm64ByteCarrierMemory
}

type arm64ByteCarrierMemory struct {
	PC, Offset, Bytes int64
	Instruction       uint32
}

func arm64ByteCarrierContext(format string, arguments ...any) error {
	return fmt.Errorf("%w: actual ARM64 byte-carrier source: %s", ErrProbeNeedsContext, fmt.Sprintf(format, arguments...))
}

func arm64ByteCarrierLive(ctx context.Context) error {
	if ctx == nil {
		return arm64ByteCarrierContext("requires a bounded live context")
	}
	if ctx.Err() != nil {
		return errors.Join(arm64ByteCarrierContext("context expired"), ctx.Err(), context.Cause(ctx))
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return arm64ByteCarrierContext("requires a bounded live context")
	}
	return nil
}

func CaptureGoARM64ByteCarrierSource(ctx context.Context, request GoARM64ByteCarrierCaptureRequest) (_ *GoARM64ByteCarrierSource, captureErr error) {
	if err := arm64ByteCarrierLive(ctx); err != nil {
		return nil, err
	}
	goos, arch, valid := strings.Cut(request.Target, "/")
	if !valid || arch != "arm64" || !arm64ByteCarrierOS(goos) || request.PackagePath == "" ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || !strings.HasSuffix(request.AssemblyFile, ".s") {
		return nil, arm64ByteCarrierContext("requires actual ARM64 source/tool/profile inputs")
	}
	request.Environment = append([]string(nil), request.Environment...)
	provided := make(map[string]string)
	for _, pair := range request.Environment {
		key, value, valid := strings.Cut(pair, "=")
		if !valid || key == "" {
			return nil, arm64ByteCarrierContext("malformed command environment")
		}
		if _, duplicate := provided[key]; duplicate {
			return nil, arm64ByteCarrierContext("duplicate command environment")
		}
		provided[key] = value
	}
	for key, value := range map[string]string{
		"GOOS": goos, "GOARCH": "arm64", "GOARM64": "v8.0", "GOAMD64": "v1",
		"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOPROXY": "off",
	} {
		if provided[key] != value {
			return nil, arm64ByteCarrierContext("unbound command profile: %s", key)
		}
	}
	if provided["GOPACKAGESDRIVER"] != "" && provided["GOPACKAGESDRIVER"] != "off" {
		return nil, arm64ByteCarrierContext("external package driver has no original-source mapping")
	}
	source := &GoARM64ByteCarrierSource{
		request: request, lease: ctx, dirs: make(map[string]os.FileInfo), files: make(map[string]os.FileInfo),
		declarations: make(map[string]FuncSig),
	}
	source.identity = source
	source.guard = newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: request.AssemblyFile,
		Target: request.Target, Environment: request.Environment,
	})
	for _, name := range []string{request.Directory, provided["GOCACHE"], provided["GOMODCACHE"], provided["GOPATH"], provided["TMPDIR"], provided["GOTMPDIR"]} {
		physical, err := sourcepath.Resolve(name)
		info, statErr := sourcepath.Lstat(name)
		if !filepath.IsAbs(name) || err != nil || physical != name || statErr != nil || !info.IsDir() {
			return nil, arm64ByteCarrierContext("missing or redirected source/command root")
		}
		source.dirs[name] = info
	}
	if err := source.guard.snapshotDirectory(); err != nil {
		return nil, err
	}
	owned, err := os.MkdirTemp(provided["TMPDIR"], "plan9asm-arm64-byte-carrier-")
	if err != nil {
		return nil, err
	}
	source.guard.owned, source.guard.ownedInfo = owned, nil
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		return nil, err
	}
	defer func() {
		if captureErr != nil {
			captureErr = errors.Join(captureErr, source.Close())
			if ctx.Err() != nil {
				captureErr = errors.Join(captureErr, ctx.Err(), context.Cause(ctx))
			}
		}
	}()
	if err := source.observe(ctx); err != nil {
		return nil, err
	}
	if err := gostaticstorage.ValidateOwnedSourceDirectory(request.Directory, source.guard.env["GOROOT"], provided["GOMODCACHE"]); err != nil {
		return nil, arm64ByteCarrierContext("original source owner role: %v", err)
	}
	// TMPDIR itself is not an external-source role: private first-party fixtures
	// may live there. Only the actual build cache and this factory's artifact
	// directory are forbidden here; no public Main metadata can override them.
	for _, root := range []string{provided["GOCACHE"], owned} {
		inside, err := gostaticstorage.SourceDirectoryWithinRoot(request.Directory, root)
		if err != nil || inside {
			return nil, arm64ByteCarrierContext("source occupies a cache/artifact role: %v", err)
		}
	}
	selected, raw, err := source.guard.loadWithRaw(ctx)
	if err != nil {
		return nil, arm64ByteCarrierContext("actual complete source export: %v", err)
	}
	source.guard.selection = selected
	if selected.ImportPath != request.PackagePath || selected.Dir != request.Directory || selected.Standard || selected.ForTest != "" ||
		selected.Module == nil || !selected.Module.Main || selected.Module.Dir != request.Directory || selected.Module.Path != request.PackagePath ||
		selected.Module.Version != "" || len(selected.Module.Replace) != 0 && string(selected.Module.Replace) != "null" ||
		selected.Module.GoMod != filepath.Join(request.Directory, "go.mod") || selected.nonordinaryRole() || len(selected.Imports) != 0 ||
		len(selected.GoFiles) == 0 || len(selected.SFiles) != 1 || selected.SFiles[0] != request.AssemblyFile {
		return nil, arm64ByteCarrierContext("requires a complete flat private numeric owned-main selection")
	}
	source.report = arm64ByteCarrierReport{
		Protocol: "actual_go_arm64_byte_carrier_observation_v1", Request: request,
		RawSelection: append([]byte(nil), raw...), RawEnvironment: source.report.RawEnvironment,
		Sources: make(map[string][]byte), Declarations: make(map[string]string), Commands: source.report.Commands,
	}
	source.record(raw, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
	if err := source.bindDeclarations(); err != nil {
		return nil, err
	}
	if err := source.bindNative(ctx, provided); err != nil {
		return nil, err
	}
	source.report.Inputs = source.guard.inputs
	for name := range source.guard.inputs {
		info, err := sourcepath.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return nil, arm64ByteCarrierContext("original input identity changed before sealing")
		}
		source.files[name] = info
	}
	source.raw, err = json.Marshal(source.report)
	if err != nil || len(source.raw) > 64<<20 {
		return nil, arm64ByteCarrierContext("bounded complete observation: %v", err)
	}
	source.seal, source.ready = sha256.Sum256(source.raw), true
	state, err := source.stateBytes()
	if err != nil {
		return nil, err
	}
	source.stateSeal = sha256.Sum256(state)
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func arm64ByteCarrierOS(goos string) bool {
	switch goos {
	case "darwin", "linux", "windows", "freebsd", "openbsd":
		return true
	}
	return false
}

func (source *GoARM64ByteCarrierSource) record(stdout []byte, arguments ...string) {
	source.report.Commands = append(source.report.Commands, numericalSBCommand{
		Directory: source.request.Directory, Binary: source.request.GoBinary,
		Arguments: append([]string(nil), arguments...), Stdout: append([]byte(nil), stdout...),
	})
}

func (source *GoARM64ByteCarrierSource) observe(ctx context.Context) error {
	if err := source.guard.observe(ctx); err != nil {
		return err
	}
	if !gotoolchain.AuditedGo127(source.guard.env["GOVERSION"]) {
		return arm64ByteCarrierContext("unobserved original SDK version")
	}
	for _, name := range []string{source.guard.env["GOROOT"], source.guard.env["GOTOOLDIR"], filepath.Join(source.guard.env["GOROOT"], "pkg/include")} {
		physical, err := sourcepath.Resolve(name)
		info, statErr := sourcepath.Lstat(name)
		if err != nil || physical != name || statErr != nil || !info.IsDir() {
			return arm64ByteCarrierContext("actual SDK root is redirected or unavailable")
		}
		if before, exists := source.dirs[name]; exists {
			if !os.SameFile(before, info) {
				return arm64ByteCarrierContext("actual SDK root identity changed")
			}
		} else {
			source.dirs[name] = info
		}
	}
	for _, name := range []string{
		"src/cmd/internal/obj/arm64/asm7.go", "src/cmd/internal/obj/arm64/obj7.go",
		"src/cmd/internal/goobj/builtinlist.go", "src/cmd/internal/objabi/reloctype.go",
		"src/cmd/compile/internal/abi/abiutils.go", "src/cmd/compile/internal/ssa/config.go",
		"src/cmd/go/internal/load/pkg.go",
		"src/cmd/go/internal/list/list.go",
		"src/cmd/go/internal/work/init.go",
		"src/cmd/go/internal/work/gc.go",
		"src/internal/platform/supported.go",
	} {
		if _, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(name))); err != nil {
			return err
		}
	}
	raw, err := source.guard.run(ctx, "env", "-json", "GOROOT", "GOVERSION", "GOOS", "GOARCH", "GOARM64", "CGO_ENABLED", "GOTOOLCHAIN", "GOFLAGS", "GOEXPERIMENT", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "GOPATH")
	if err != nil {
		return err
	}
	var actual map[string]string
	if json.Unmarshal(raw, &actual) != nil || actual["GOARM64"] != "v8.0" || actual["CGO_ENABLED"] != "0" || actual["GOTOOLCHAIN"] != "local" {
		return arm64ByteCarrierContext("actual original ARM64 profile differs")
	}
	for key, value := range source.guard.env {
		if observed, exists := actual[key]; exists && observed != value {
			return arm64ByteCarrierContext("actual original environment differs: %s", key)
		}
	}
	if source.report.RawEnvironment == nil {
		source.report.RawEnvironment = append([]byte(nil), raw...)
		source.record(raw, "env", "-json", "GOROOT", "GOVERSION", "GOOS", "GOARCH", "GOARM64", "CGO_ENABLED", "GOTOOLCHAIN", "GOFLAGS", "GOEXPERIMENT", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "GOPATH")
	} else if !bytes.Equal(source.report.RawEnvironment, raw) {
		return arm64ByteCarrierContext("complete original environment changed")
	}
	return nil
}

func (source *GoARM64ByteCarrierSource) bindDeclarations() error {
	fset := token.NewFileSet()
	var syntax []*ast.File
	var compiled []string
	bodyless := make(map[string]bool)
	for _, name := range source.guard.selection.GoFiles {
		data, err := source.guard.read(filepath.Join(source.request.Directory, name))
		if err != nil {
			return err
		}
		source.report.Sources[name] = data
		file, err := parser.ParseFile(fset, name, data, parser.ParseComments)
		if err != nil {
			return arm64ByteCarrierContext("original Go syntax: %v", err)
		}
		for _, comment := range file.Comments {
			for _, line := range comment.List {
				if strings.Contains(line.Text, "go:") {
					return arm64ByteCarrierContext("linkname/directive source needs separate entry ownership")
				}
			}
		}
		for _, declaration := range file.Decls {
			fn, valid := declaration.(*ast.FuncDecl)
			if !valid || fn.Recv != nil || ast.IsExported(fn.Name.Name) || fn.Type.TypeParams != nil {
				return arm64ByteCarrierContext("source is not a closed private numeric function set")
			}
			if fn.Body == nil {
				bodyless[fn.Name.Name] = true
			}
		}
		syntax = append(syntax, file)
		compiled = append(compiled, filepath.Join(source.request.Directory, name))
	}
	sort.Strings(compiled)
	actual := append([]string(nil), source.guard.selection.CompiledGoFiles...)
	for index, name := range actual {
		if !filepath.IsAbs(name) {
			actual[index] = filepath.Join(source.request.Directory, name)
		}
	}
	sort.Strings(actual)
	if !reflect.DeepEqual(compiled, actual) || len(bodyless) == 0 {
		return arm64ByteCarrierContext("effective source mapping omits the original declarations")
	}
	info := &types.Info{Uses: make(map[*ast.Ident]types.Object)}
	sizes := types.SizesFor("gc", "arm64")
	typed, err := (&types.Config{Sizes: sizes}).Check(source.request.PackagePath, fset, syntax, info)
	if err != nil || typed.Name() != source.guard.selection.Name {
		return arm64ByteCarrierContext("complete original numeric typecheck: %v", err)
	}
	for _, name := range typed.Scope().Names() {
		fn, valid := typed.Scope().Lookup(name).(*types.Func)
		if !valid {
			return arm64ByteCarrierContext("nonfunction global role")
		}
		signature := fn.Type().(*types.Signature)
		if signature.Variadic() || signature.TypeParams().Len() != 0 || signature.Recv() != nil {
			return arm64ByteCarrierContext("custom/generic numeric entry transport")
		}
		for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
			if tuple.Len() > 32 {
				return arm64ByteCarrierContext("numeric transport tuple exceeds its bound")
			}
			for index := 0; index < tuple.Len(); index++ {
				basic, valid := tuple.At(index).Type().(*types.Basic)
				if !valid || basic.Info()&types.IsInteger == 0 {
					return arm64ByteCarrierContext("pointer/aggregate/noninteger transport needs a separate producer")
				}
			}
		}
		source.report.Declarations[name] = types.TypeString(signature, nil)
		if bodyless[name] {
			derived, err := DeriveGoFuncABI0Signature(source.request.PackagePath+"."+name, fn, "arm64", sizes)
			if err != nil {
				return arm64ByteCarrierContext("actual original typed ABI0 declaration: %v", err)
			}
			source.declarations[name] = derived
		}
	}
	// Every reference to a function is an original direct call. Copying a
	// function into a variable, returning it or taking its code address must not
	// silently open the otherwise private entry boundary.
	called := make(map[*ast.Ident]bool)
	for _, file := range syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			if call, valid := node.(*ast.CallExpr); valid {
				if name, direct := call.Fun.(*ast.Ident); direct {
					called[name] = true
				}
			}
			return true
		})
	}
	for name, object := range info.Uses {
		if _, function := object.(*types.Func); function && !called[name] {
			return arm64ByteCarrierContext("original Go function address escapes the closed direct-call set")
		}
	}
	data, err := source.guard.read(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil {
		return err
	}
	source.report.Sources[source.request.AssemblyFile] = data
	// This first producer accepts literal complete source only. CPP/raw data,
	// private-address entries and external SB references need separate joins.
	if strings.Contains(string(data), "#") {
		return arm64ByteCarrierContext("CPP source requires actual origin binding")
	}
	source.file, err = Parse(ArchARM64, string(data))
	if err != nil || len(source.file.Data) != 0 || len(source.file.Globl) != 0 || len(source.file.UnlinkedPrelude) != 0 || len(source.file.Funcs) != len(bodyless) {
		return arm64ByteCarrierContext("complete literal assembly source differs: %v", err)
	}
	seen := make(map[string]bool)
	for _, fn := range source.file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		if !bodyless[name] || seen[name] || fn.Sym != "·"+name || fn.FrameSize < 0 || fn.FrameSize > 4096 || fn.ArgSize < 0 || fn.ArgSize > 4096 {
			return arm64ByteCarrierContext("assembly declaration/entry identity differs")
		}
		seen[name] = true
		declared := source.declarations[name]
		var end int64
		for _, fields := range [][]FrameSlot{declared.Frame.Params, declared.Frame.Results} {
			for _, field := range fields {
				if next := field.Offset + frameTypeSize(field.Type, 8); next > end {
					end = next
				}
			}
		}
		if fn.ArgSize != end {
			return arm64ByteCarrierContext("original TEXT args differs from the complete declared fields")
		}
		for _, instruction := range fn.Instrs {
			for _, operand := range instruction.Args {
				if operand.Kind != OpFP {
					continue
				}
				found := false
				for _, fields := range [][]FrameSlot{declared.Frame.Params, declared.Frame.Results} {
					for _, field := range fields {
						found = found || operand.FPOffset == field.Offset
					}
				}
				if !found {
					return arm64ByteCarrierContext("FP source lacks an exact original declared field start")
				}
			}
		}
	}
	return nil
}

func (source *GoARM64ByteCarrierSource) Readback(ctx context.Context) ([]byte, error) {
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready || source.identity != source {
		return nil, arm64ByteCarrierContext("source closed after verification")
	}
	if err := arm64ByteCarrierLive(source.lease); err != nil {
		source.ready = false
		return nil, err
	}
	return append([]byte(nil), source.raw...), nil
}

func (source *GoARM64ByteCarrierSource) Verify(ctx context.Context) (verifyErr error) {
	if source == nil {
		return arm64ByteCarrierContext("missing live source observation")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.identity != source {
		return arm64ByteCarrierContext("copied or uninitialized source identity")
	}
	defer func() {
		if verifyErr != nil {
			source.ready = false
			if source.lease != nil && source.lease.Err() != nil {
				verifyErr = errors.Join(verifyErr, source.lease.Err(), context.Cause(source.lease))
			}
			if ctx != nil && ctx.Err() != nil {
				verifyErr = errors.Join(verifyErr, ctx.Err(), context.Cause(ctx))
			}
		}
	}()
	if !source.ready {
		return arm64ByteCarrierContext("closed or revoked source")
	}
	runContext, release, err := source.executionContext(ctx)
	if err != nil {
		return err
	}
	defer release()
	state, err := source.stateBytes()
	if err != nil || sha256.Sum256(state) != source.stateSeal || sha256.Sum256(source.raw) != source.seal {
		return arm64ByteCarrierContext("sealed complete original observation changed")
	}
	for name, before := range source.dirs {
		physical, err := sourcepath.Resolve(name)
		after, statErr := os.Lstat(name)
		if err != nil || physical != name || statErr != nil || !after.IsDir() || !os.SameFile(before, after) {
			return arm64ByteCarrierContext("source/cache/temporary root identity changed")
		}
	}
	if err := source.guard.verifyInputs(); err != nil {
		return err
	}
	if err := source.verifyFileIdentities(); err != nil {
		return err
	}
	before := source.guard.env
	if err := source.observe(runContext); err != nil {
		return err
	}
	if !reflect.DeepEqual(before, source.guard.env) {
		return arm64ByteCarrierContext("actual original tool/profile changed")
	}
	selected, raw, err := source.guard.loadWithRaw(runContext)
	// Reuse the existing exact original-Go selection comparator. Only the
	// pinned SDK's typed Stale/StaleReason display fields can change after the
	// first -export builds its cache entry; every semantic field and both whole
	// stdout records stay bound. A fresh cache is not a source change.
	if err != nil || !reflect.DeepEqual(selected, source.guard.selection) || !numericalSameRawSelection(raw, source.report.RawSelection) {
		return arm64ByteCarrierContext("actual complete compiler selection/export changed: %v", err)
	}
	return errors.Join(source.guard.verifyInputs(), source.verifyFileIdentities(),
		arm64ByteCarrierLive(source.lease), arm64ByteCarrierLive(ctx))
}

// executionContext obeys both the later operation context and the actual
// original capture owner. It cannot renew the lease. The small watcher is
// joined on release; this works on Go 1.20 without context.AfterFunc.
func (source *GoARM64ByteCarrierSource) executionContext(ctx context.Context) (context.Context, func(), error) {
	if err := errors.Join(arm64ByteCarrierLive(source.lease), arm64ByteCarrierLive(ctx)); err != nil {
		return nil, nil, err
	}
	deadline, _ := source.lease.Deadline()
	base, cancelCause := context.WithCancelCause(ctx)
	bounded, cancelDeadline := context.WithDeadline(base, deadline)
	closed := make(chan struct{})
	lease := source.lease
	go func() {
		defer close(closed)
		select {
		case <-lease.Done():
			cancelCause(context.Cause(lease))
		case <-bounded.Done():
		}
	}()
	release := func() {
		cancelDeadline()
		cancelCause(context.Canceled)
		<-closed
	}
	return bounded, release, nil
}

func (source *GoARM64ByteCarrierSource) verifyFileIdentities() error {
	if len(source.files) != len(source.guard.inputs) {
		return arm64ByteCarrierContext("complete input identity inventory changed")
	}
	for name, before := range source.files {
		after, err := os.Lstat(name)
		if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
			return arm64ByteCarrierContext("original file identity changed: %s", filepath.Base(name))
		}
	}
	return nil
}

func (source *GoARM64ByteCarrierSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.identity != source {
		return arm64ByteCarrierContext("copied source cannot release another factory's artifacts")
	}
	source.ready = false
	if source.guard == nil {
		return nil
	}
	return source.guard.Close()
}

func (source *GoARM64ByteCarrierSource) stateBytes() ([]byte, error) {
	identities := make(map[string]string)
	for name, info := range source.dirs {
		identities["directory:"+name] = fmt.Sprintf("%#v", info.Sys())
	}
	for name, info := range source.files {
		identities["file:"+name] = fmt.Sprintf("%#v", info.Sys())
	}
	return json.Marshal(struct {
		Report       arm64ByteCarrierReport
		Request      GoARM64ByteCarrierCaptureRequest
		GuardRequest GoAMD64FrameCaptureRequest
		Selection    goAMD64FrameSelection
		Environment  map[string]string
		Entries      []string
		File         *File
		Declarations map[string]FuncSig
		Owned        string
		Identities   map[string]string
	}{source.report, source.request, source.guard.request, source.guard.selection, source.guard.env, source.guard.entries, source.file, source.declarations, source.guard.owned, identities})
}
