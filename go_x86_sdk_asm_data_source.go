package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// GoX86SDKASMDataCaptureRequest selects one physical package in the invoked
// stock-Go SDK. It accepts no caller AST, Types, header, object or owner token.
type GoX86SDKASMDataCaptureRequest struct {
	GoBinary, Directory, PackagePath, Target string
	Environment                              []string
}

type sdkASMDataCaptureRole uint8

const (
	sdkASMDataStrictRole sdkASMDataCaptureRole = iota
	sdkASMDataOriginalFrameRole
	sdkASMDataOriginalSourceRole
)

// GoX86SDKASMDataSource authenticates source/header/CPP/object observations
// only. It has no Bind, Options, initializer, numerical or native-body API.
type GoX86SDKASMDataSource struct {
	mu, operation    sync.Mutex
	identity         *GoX86SDKASMDataSource
	ready            bool
	active           int
	closePending     bool
	generation       uint64
	request          GoX86SDKASMDataCaptureRequest
	guard            *GoAMD64FrameSource
	originalGuard    *GoAMD64FrameSource
	context          context.Context
	originalContext  context.Context
	originalDeadline time.Time
	// Only distinct private SDK-primary observation factories select an
	// original profile. Public DATA/numerical producers remain strict.
	originalProfile   bool
	captureRole       sdkASMDataCaptureRole
	originalConfig    string
	originalConfigID  os.FileInfo
	frameListingBytes int
	directories       map[string]os.FileInfo
	misses            map[string]bool
	observation       sdkASMDataLiveObservation
	report            []byte
	seal              [32]byte
	stateSeal         [32]byte
}

type sdkASMDataLiveObservation struct {
	Protocol                     string
	Request                      GoX86SDKASMDataCaptureRequest
	RawEnvironment, RawSelection []byte
	Graph                        []byte
	Imports                      map[string]goAMD64FrameSelection
	Inputs                       map[string][32]byte
	Header                       sdkASMDataHeaderObservation
	CPP                          []AssemblyCPPObservation
	Positions                    []sdkCPPPositionObservation
	ObjectInputs                 gostaticstorage.SDKASMDataObservationRequest
	Objects                      *gostaticstorage.SDKASMDataObservation
	Frames                       []sdkAMD64FrameNativeObservation `json:",omitempty"`
	FrameListingBytes            int                              `json:",omitempty"`
	Commands                     []numericalSBCommand
}

func sdkASMDataContext(format string, args ...any) error {
	return fmt.Errorf("%w: actual SDK ASM DATA observation: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

// CaptureGoX86SDKASMDataSource is an explicit live SDK observation producer.
// Successful capture does not make DATA initialized storage or authorize any
// instruction to read it. Existing owned and numerical factories stay strict.
func CaptureGoX86SDKASMDataSource(ctx context.Context, request GoX86SDKASMDataCaptureRequest) (_ *GoX86SDKASMDataSource, result error) {
	return captureGoX86SDKASMDataSource(ctx, request, false)
}

func captureGoX86SDKASMDataSource(ctx context.Context, request GoX86SDKASMDataCaptureRequest, originalProfile bool) (_ *GoX86SDKASMDataSource, result error) {
	role := sdkASMDataStrictRole
	if originalProfile {
		role = sdkASMDataOriginalFrameRole
	}
	return captureGoX86SDKASMDataSourceRole(ctx, request, role)
}

// A distinct private source-only role observes the same original profile but
// never captures AMD64 native frames or constructs their observation owner.
func captureGoX86SDKASMDataSourceRole(ctx context.Context, request GoX86SDKASMDataCaptureRequest, role sdkASMDataCaptureRole) (_ *GoX86SDKASMDataSource, result error) {
	if role > sdkASMDataOriginalSourceRole {
		return nil, sdkASMDataContext("unknown private SDK source observation role")
	}
	originalProfile := role != sdkASMDataStrictRole
	if ctx != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("capture SDK ASM DATA: %w", ctx.Err())
	}
	if ctx == nil || !gostaticstorage.X86SDKTarget(request.Target) ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		!filepath.IsLocal(filepath.FromSlash(request.PackagePath)) ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(request.PackagePath))) != request.PackagePath {
		return nil, sdkASMDataContext("requires exact SDK source/tool/target inputs")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, sdkASMDataContext("requires a bounded original capture context")
	}
	request.Environment = append([]string(nil), request.Environment...)
	var provided map[string]string
	var err error
	if role == sdkASMDataOriginalFrameRole {
		provided, err = sdkAMD64FrameEnvironment(request)
	} else if role == sdkASMDataOriginalSourceRole {
		provided, err = sdkX86OriginalSourceEnvironment(request)
	} else {
		provided, err = sdkASMDataEnvironment(request)
	}
	if err != nil {
		return nil, err
	}
	source := &GoX86SDKASMDataSource{request: request, context: ctx, originalContext: ctx, originalProfile: originalProfile, captureRole: role,
		originalDeadline: deadline,
		directories:      make(map[string]os.FileInfo), misses: make(map[string]bool)}
	source.identity = source
	source.guard = newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, Target: request.Target, Environment: request.Environment})
	source.originalGuard = source.guard
	for _, directory := range []string{request.Directory, provided["GOCACHE"], provided["GOMODCACHE"],
		provided["GOPATH"], provided["TMPDIR"], provided["GOTMPDIR"]} {
		if err := source.retainDirectory(directory); err != nil {
			return nil, err
		}
	}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		return nil, err
	}
	owned, err := os.MkdirTemp(provided["TMPDIR"], "plan9asm-sdk-asm-data-")
	if err != nil {
		return nil, err
	}
	source.guard.owned = owned
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	canonical, err := sourcepath.Resolve(owned)
	info, statErr := os.Lstat(canonical)
	if err != nil || statErr != nil || !info.IsDir() || !os.SameFile(info, source.guard.ownedInfo) ||
		!goAssemblyPathWithinRoot(provided["TMPDIR"], canonical) {
		return nil, sdkASMDataContext("factory artifact identity changed")
	}
	source.guard.owned = canonical
	if originalProfile && provided["GOENV"] != "off" {
		if err := source.captureSDKFrameConfig(provided["GOENV"]); err != nil {
			return nil, err
		}
	}
	if err := source.capture(ctx, provided); err != nil {
		return nil, err
	}
	source.observation.Inputs = cloneSDKASMDataInputs(source.guard.inputs)
	source.report, err = json.Marshal(source.observation)
	if err != nil {
		return nil, err
	}
	source.seal = sha256.Sum256(source.report)
	source.stateSeal, err = source.digest()
	if err != nil {
		return nil, err
	}
	source.ready, source.generation = true, 1
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func sdkASMDataEnvironment(request GoX86SDKASMDataCaptureRequest) (map[string]string, error) {
	provided := make(map[string]string)
	for _, pair := range request.Environment {
		key, value, valid := strings.Cut(pair, "=")
		if _, duplicate := provided[key]; !valid || key == "" || duplicate {
			return nil, sdkASMDataContext("malformed or duplicate command environment")
		}
		provided[key] = value
	}
	goos, arch, _ := strings.Cut(request.Target, "/")
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2",
		"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOPROXY": "off"} {
		if key == "CGO_ENABLED" && (provided[key] == "0" || provided[key] == "1") {
			continue // Actual SDK graph still requires complete ordinary uncgo sources.
		}
		if actual, present := provided[key]; !present || actual != value {
			return nil, sdkASMDataContext("unbound command profile: %s", key)
		}
	}
	if provided["GOPACKAGESDRIVER"] != "" && provided["GOPACKAGESDRIVER"] != "off" {
		return nil, sdkASMDataContext("external package driver needs its own source role")
	}
	return provided, nil
}

func (source *GoX86SDKASMDataSource) retainDirectory(directory string) error {
	resolved, err := sourcepath.Resolve(directory)
	info, statErr := sourcepath.Lstat(directory)
	if !filepath.IsAbs(directory) || err != nil || resolved != directory || statErr != nil || !info.IsDir() {
		return sdkASMDataContext("missing or redirected source/command directory")
	}
	source.directories[directory] = info
	return nil
}

func (source *GoX86SDKASMDataSource) verifyDirectories() error {
	if source.originalConfig != "" {
		resolved, err := sourcepath.Resolve(source.originalConfig)
		info, statErr := sourcepath.Lstat(source.originalConfig)
		if err != nil || resolved != source.originalConfig || statErr != nil || !info.Mode().IsRegular() || info.Size() > sdkAMD64FrameConfigBytes ||
			source.originalConfigID == nil || !os.SameFile(source.originalConfigID, info) {
			return sdkASMDataContext("SDK-primary original GOENV identity changed")
		}
	}
	for directory, before := range source.directories {
		resolved, err := sourcepath.Resolve(directory)
		after, statErr := sourcepath.Lstat(directory)
		if err != nil || resolved != directory || statErr != nil || !after.IsDir() || !os.SameFile(before, after) {
			return sdkASMDataContext("source/command directory identity changed")
		}
	}
	for name := range source.misses {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			return sdkASMDataContext("CPP preferred search miss changed")
		}
	}
	return nil
}

func (source *GoX86SDKASMDataSource) liveContext(ctx context.Context) error {
	if ctx == nil || source.context == nil {
		return sdkASMDataContext("missing original or verification context")
	}
	if source.originalContext == nil || reflect.TypeOf(source.context) != reflect.TypeOf(source.originalContext) ||
		!reflect.TypeOf(source.context).Comparable() || source.context != source.originalContext {
		return sdkASMDataContext("original capture context identity changed")
	}
	_, err := sampleGoSourceContext(ctx, source.context,
		goSourceContextLifetime{deadline: source.originalDeadline, bounded: true}, false,
		sdkASMDataContext("original capture context deadline changed or canceled without a cause"))
	return err
}

func (source *GoX86SDKASMDataSource) run(ctx context.Context, arguments ...string) ([]byte, error) {
	if err := source.liveContext(ctx); err != nil {
		return nil, err
	}
	stdout, err := source.runCommand(ctx, arguments...)
	return stdout, errors.Join(err, source.liveContext(ctx))
}

// Verification supplies only a private standard context here. Never invoke a
// caller context while the operation lock protects private input maps.
func (source *GoX86SDKASMDataSource) runCommand(ctx context.Context, arguments ...string) ([]byte, error) {
	if err := source.verifyDirectories(); err != nil {
		return nil, err
	}
	if err := source.guard.verifyInputs(); err != nil {
		return nil, err
	}
	commandContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	stdout, err := goasmcmd.Run(commandContext, source.request.Directory, source.request.Environment, source.request.GoBinary, arguments...)
	err = errors.Join(err, commandContext.Err(), source.guard.verifyInputs(), source.verifyDirectories())
	if err == nil && source.originalProfile && len(arguments) > 1 && arguments[0] == "tool" && arguments[1] == "asm" {
		for _, argument := range arguments[2:] {
			if argument == "-S" {
				err = source.retainSDKFrameListingBytes(len(stdout))
				break
			}
		}
	}
	if err == nil {
		source.observation.Commands = append(source.observation.Commands, numericalSBCommand{
			Directory: source.request.Directory, Binary: source.request.GoBinary,
			Arguments: append([]string(nil), arguments...), Stdout: append([]byte(nil), stdout...),
		})
	}
	return stdout, err
}

func cloneSDKASMDataInputs(inputs map[string][32]byte) map[string][32]byte {
	result := make(map[string][32]byte, len(inputs))
	for name, digest := range inputs {
		result[name] = digest
	}
	return result
}

func (source *GoX86SDKASMDataSource) digest() ([32]byte, error) {
	return digestSDKASMDataState(struct {
		Request           GoX86SDKASMDataCaptureRequest
		Guard             GoAMD64FrameCaptureRequest
		Selection         goAMD64FrameSelection
		Env               map[string]string
		Imports           map[string]goAMD64FrameSelection
		Inputs            map[string][32]byte
		Entries           []string
		Misses            map[string]bool
		Observation       sdkASMDataLiveObservation
		OriginalDeadline  time.Time
		OriginalProfile   bool
		CaptureRole       sdkASMDataCaptureRole
		OriginalConfig    string
		FrameListingBytes int
	}{source.request, source.guard.request, source.guard.selection, source.guard.env, source.guard.imports,
		source.guard.inputs, source.guard.entries, source.misses, source.observation, source.originalDeadline,
		source.originalProfile, source.captureRole, source.originalConfig, source.frameListingBytes})
}

// Verify samples every caller context outside both locks. A lifetime lease
// protects artifacts during reentrant Verify/Readback/Close callbacks; only a
// private standard context enters the serialized command/guard operation.
// Every postcheck must still match the exact original generation.
func (source *GoX86SDKASMDataSource) Verify(ctx context.Context) (result error) {
	if source == nil || source.identity != source {
		return sdkASMDataContext("copied, missing or uninitialized source")
	}
	source.mu.Lock()
	generation, ready := source.generation, source.ready
	if ready {
		source.active++
	}
	source.mu.Unlock()
	if !ready {
		return sdkASMDataContext("source is closed or revoked")
	}
	defer func() {
		result = errors.Join(result, source.liveContext(ctx))
		source.mu.Lock()
		if source.generation != generation || !source.ready {
			result = errors.Join(result, sdkASMDataContext("source closed or revoked during verification"))
		}
		if result != nil {
			source.ready = false
			source.generation++
		}
		source.active--
		cleanup := source.closePending && source.active == 0
		source.mu.Unlock()
		if cleanup {
			source.operation.Lock()
			result = errors.Join(result, source.guard.Close())
			source.operation.Unlock()
		}
	}()
	if err := source.liveContext(ctx); err != nil {
		return err
	}
	private, stop, err := sdkASMDataPrivateContext(ctx, source.context, source.originalDeadline)
	if err != nil {
		return err
	}
	defer stop()
	source.operation.Lock()
	defer source.operation.Unlock()
	source.mu.Lock()
	current := source.ready && source.generation == generation
	source.mu.Unlock()
	if !current {
		return sdkASMDataContext("source closed or revoked during context callbacks")
	}
	return errors.Join(source.verifyState(private), private.Err())
}

func (source *GoX86SDKASMDataSource) verifyState(ctx context.Context) error {
	if source.guard != source.originalGuard || source.guard == nil || source.guard.identity != source.guard ||
		source.guard.ready || source.guard.request.NumericalReads != nil || source.guard.numericalOrigin != nil || source.guard.downloadedOrigin != nil {
		return sdkASMDataContext("source borrowed a foreign frame, origin or numerical capability")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := source.digest()
	if err != nil || before != source.stateSeal || sha256.Sum256(source.report) != source.seal {
		return sdkASMDataContext("sealed source/header/CPP/object state changed")
	}
	if err := source.verifySDKDirectory(); err != nil {
		return err
	}
	// Verification commands are not new capture observations. Retain the exact
	// original command inventory while checking current actual graph bytes.
	commands := source.observation.Commands
	defer func() { source.observation.Commands = commands }()
	raw, err := source.runCommand(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", source.request.PackagePath)
	if err != nil {
		return err
	}
	imports, err := source.guard.bindOriginalDeclarationImports(raw)
	if err != nil || !reflect.DeepEqual(imports, source.observation.Imports) ||
		!numericalSameRawSDKGraph(raw, source.observation.Graph) {
		return sdkASMDataContext("complete SDK source/export/selection graph changed: %v", err)
	}
	source.observation.Commands = commands
	if err := source.guard.verifyInputs(); err != nil {
		return err
	}
	after, err := source.digest()
	if err != nil || after != source.stateSeal {
		return sdkASMDataContext("inputs or observation changed during verification")
	}
	return nil
}

// Close cannot dispose a copied source's shared artifacts. It never deletes
// the SDK, original source, dependency exports or caller cache directories.
func (source *GoX86SDKASMDataSource) Close() error {
	if source == nil {
		return nil
	}
	if source.identity != source {
		return sdkASMDataContext("copied observation cannot close its original artifact owner")
	}
	if source.guard == nil || source.guard != source.originalGuard || source.guard.identity != source.guard {
		return sdkASMDataContext("foreign artifact guard cannot dispose its owner's directory")
	}
	source.mu.Lock()
	source.ready = false
	source.generation++
	source.closePending = true
	active := source.active
	source.mu.Unlock()
	if active != 0 {
		return nil
	}
	source.operation.Lock()
	defer source.operation.Unlock()
	return source.guard.Close()
}

func (source *GoX86SDKASMDataSource) Readback(ctx context.Context) ([]byte, error) {
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready {
		return nil, sdkASMDataContext("source closed after verification")
	}
	return append([]byte(nil), source.report...), nil
}

// CheckReadback compares actual retained whole bytes. It is not a constructor.
func (source *GoX86SDKASMDataSource) CheckReadback(ctx context.Context, raw []byte) error {
	if err := source.Verify(ctx); err != nil {
		return err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready || sha256.Sum256(raw) != source.seal {
		source.ready = false
		source.generation++
		return sdkASMDataContext("readback differs from retained original observations")
	}
	return nil
}
