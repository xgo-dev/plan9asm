package gotoolprofile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// AMD64OriginalObservationRequest observes an owned main module, not a signed
// external archive. It has no signatures, frames, pointer bounds or permission
// inputs. External/foreign and instrumentation roles require a separate sealed
// source handoff; this initial producer never silently uses their baseline.
type AMD64OriginalObservationRequest struct {
	GoBinary, Directory, PackagePath, Target string
	Environment                              []string
}

// AMD64OriginalPackageObservation is only an actual source/export observation.
// No JSON representation, public Options or FrameSource conversion exists.
// In particular, it grants no local backing, incoming frame, caller, alias,
// allocation, initialization, native-memory or ABI authority.
type AMD64OriginalPackageObservation struct {
	mu         sync.Mutex
	ready      bool
	generation uint64
	request    AMD64OriginalObservationRequest
	run        Runner
	state      *amd64OriginalObservationState
	downloaded *amd64DownloadedSources
	fixedLocal []*AMD64OriginalFixedLocalBinding
}

type amd64OriginalObservationState struct {
	profile              *Observation
	environment, context map[string]string
	packages             map[string]amd64OriginalListPackage
	declarations         map[string]string
	files                *amd64OriginalObservationFiles
}

// CaptureAMD64OriginalPackageObservation compiles exports only. It never runs
// package initialization or any third-party program. Runner is the existing
// trusted bounded actual-command seam, not a user-supplied verification token.
func CaptureAMD64OriginalPackageObservation(ctx context.Context, request AMD64OriginalObservationRequest, run Runner) (*AMD64OriginalPackageObservation, error) {
	return captureAMD64OriginalPackageObservation(ctx, request, nil, run)
}

func captureAMD64OriginalPackageObservation(ctx context.Context, request AMD64OriginalObservationRequest, downloaded *amd64DownloadedSources, run Runner) (*AMD64OriginalPackageObservation, error) {
	if err := validateAMD64OriginalObservationRequest(ctx, request, run); err != nil {
		return nil, err
	}
	request.Environment = append([]string(nil), request.Environment...)
	state, err := captureAMD64OriginalObservationState(ctx, request, downloaded, run)
	if err != nil {
		return nil, err
	}
	observed := &AMD64OriginalPackageObservation{ready: true, generation: 1, request: request, run: run, state: state, downloaded: downloaded}
	if err := observed.Verify(ctx); err != nil {
		return nil, err
	}
	return observed, nil
}

// Verify releases the lock before every external callback. Close or a failed
// verification permanently revokes this generation, including a verification
// already in flight; restoring bytes cannot restore the observation.
func (observed *AMD64OriginalPackageObservation) Verify(ctx context.Context) error {
	if observed == nil {
		return fmt.Errorf("missing original package observation")
	}
	observed.mu.Lock()
	ready, generation := observed.ready, observed.generation
	request, run, expected := observed.request, observed.run, observed.state
	downloaded := observed.downloaded
	observed.mu.Unlock()
	if !ready || expected == nil {
		return fmt.Errorf("original package observation is closed or revoked")
	}
	err := validateAMD64OriginalObservationRequest(ctx, request, run)
	if err == nil {
		err = expected.files.verify()
	}
	var actual *amd64OriginalObservationState
	if err == nil {
		actual, err = captureAMD64OriginalObservationState(ctx, request, downloaded, run)
	}
	if err == nil && !equalAMD64OriginalObservationStates(expected, actual) {
		err = fmt.Errorf("original package source/selection/export/profile changed")
	}
	observed.mu.Lock()
	if !observed.ready || generation != observed.generation {
		observed.mu.Unlock()
		return fmt.Errorf("original package observation was revoked during verification")
	}
	var revoked []*AMD64OriginalFixedLocalBinding
	if err != nil {
		observed.ready = false
		observed.generation++
		revoked, observed.fixedLocal = observed.fixedLocal, nil
	}
	observed.mu.Unlock()
	if closeErr := closeAMD64OriginalFixedLocal(revoked); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	return err
}

func (observed *AMD64OriginalPackageObservation) Close() error {
	if observed == nil {
		return nil
	}
	observed.mu.Lock()
	observed.ready = false
	observed.generation++
	bindings := observed.fixedLocal
	observed.fixedLocal = nil
	observed.mu.Unlock()
	return closeAMD64OriginalFixedLocal(bindings)
}

func validateAMD64OriginalObservationRequest(ctx context.Context, request AMD64OriginalObservationRequest, run Runner) error {
	if ctx == nil || ctx.Err() != nil || run == nil || !filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) {
		return fmt.Errorf("original observation needs a live bounded actual Go invocation")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return fmt.Errorf("original observation needs a bounded context")
	}
	if request.Target != "linux/amd64" && request.Target != "darwin/amd64" && request.Target != "windows/amd64" ||
		request.PackagePath == "" || strings.ContainsAny(request.PackagePath, "@ \\\t\r\n") {
		return fmt.Errorf("invalid original AMD64 package/target")
	}
	env := make(map[string]string)
	for _, item := range request.Environment {
		key, value, valid := strings.Cut(item, "=")
		if !valid || key == "" || strings.ContainsRune(item, '\x00') {
			return fmt.Errorf("incomplete original command environment")
		}
		if _, duplicate := env[key]; duplicate {
			return fmt.Errorf("duplicate original command environment: %s", key)
		}
		env[key] = value
	}
	goos, _, _ := strings.Cut(request.Target, "/")
	for key, wanted := range map[string]string{"GOOS": goos, "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "", "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local"} {
		if value, present := env[key]; !present || value != wanted {
			return fmt.Errorf("%w: ordinary observation requires exact %s=%q", plan9asm.ErrProbeNeedsContext, key, wanted)
		}
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(env[key]) {
			return fmt.Errorf("original observation needs explicit owned %s", key)
		}
	}
	return nil
}

func captureAMD64OriginalObservationState(ctx context.Context, request AMD64OriginalObservationRequest, downloaded *amd64DownloadedSources, run Runner) (_ *amd64OriginalObservationState, result error) {
	if downloaded != nil {
		if err := downloaded.verify(); err != nil {
			return nil, err
		}
	}
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, request.GoBinary, request.Directory, request.Environment, run)
	if err != nil {
		return nil, err
	}
	if actual["GOOS"]+"/"+actual["GOARCH"] != request.Target || actual["CGO_ENABLED"] != "0" || commandContext["GOFLAGS"] != "" {
		return nil, fmt.Errorf("actual original environment differs from its ordinary profile")
	}
	tmp := originalObservationEnvironment(request.Environment, "GOTMPDIR")
	marker, err := os.MkdirTemp(tmp, "amd64-original-observation-")
	if err != nil {
		return nil, err
	}
	owned, err := os.Lstat(marker)
	if err != nil {
		return nil, err
	}
	created := marker
	defer func() {
		info, err := os.Lstat(created)
		if err != nil || !info.IsDir() || !os.SameFile(owned, info) {
			result = errors.Join(result, fmt.Errorf("owned observation marker directory identity changed"))
		} else if err := os.RemoveAll(created); err != nil {
			result = errors.Join(result, err)
		}
	}()
	marker, err = sourcepath.Resolve(created)
	if err != nil {
		return nil, err
	}
	profile, err := Capture(ctx, request.GoBinary, marker, request.Environment, request.Target, map[string]string{"GOAMD64": actual["GOAMD64"], "GOEXPERIMENT": actual["GOEXPERIMENT"]}, run)
	if err != nil {
		return nil, err
	}
	if err := Validate(profile); err != nil {
		return nil, err
	}
	state := &amd64OriginalObservationState{profile: profile, environment: actual, context: commandContext, files: newAMD64OriginalObservationFiles()}
	before, err := captureAMD64OriginalGraph(ctx, request, actual, profile, state.files, downloaded, false, run)
	if err != nil {
		return nil, err
	}
	after, err := captureAMD64OriginalGraph(ctx, request, actual, profile, state.files, downloaded, true, run)
	if err != nil {
		return nil, fmt.Errorf("capture original package selection after export: %w", err)
	}
	if !equalAMD64OriginalSelections(before, after) {
		return nil, fmt.Errorf("original package selection changed during export")
	}
	state.packages = after
	state.declarations, err = checkAMD64OriginalDeclarations(after, request.PackagePath)
	if err != nil {
		return nil, err
	}
	now, nowContext, err := instrumentationObserverEnvironment(ctx, request.GoBinary, request.Directory, request.Environment, run)
	if err != nil {
		return nil, fmt.Errorf("recapture original package environment: %w", err)
	}
	if !reflect.DeepEqual(now, actual) || !reflect.DeepEqual(nowContext, commandContext) {
		return nil, fmt.Errorf("original package environment changed during capture")
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, request.GoBinary, request.Environment, actual, run)
	if err != nil {
		return nil, fmt.Errorf("recapture original Go tools: %w", err)
	}
	if tools.directory != profile.ToolDirectory || tools.routing != profile.ToolRoutingSHA256 || tools.dispatcher != profile.ToolDispatcherSHA256 ||
		!reflect.DeepEqual(tools.digests, profile.ToolBinarySHA256) || !reflect.DeepEqual(tools.origins, profile.ToolBinaryOrigins) {
		return nil, fmt.Errorf("actual Go tool routing/bytes changed during export")
	}
	for file, digest := range profile.ToolSourceSHA256 {
		path := filepath.Join(actual["GOROOT"], filepath.FromSlash(file))
		if err := state.files.retain(path); err != nil {
			return nil, fmt.Errorf("retain registered SDK source %s: %w", file, err)
		}
		if state.files.hashes[path] != digest {
			return nil, fmt.Errorf("registered SDK source changed: %s", file)
		}
	}
	if err := state.files.retainTool(request.GoBinary); err != nil {
		return nil, fmt.Errorf("retain actual Go driver: %w", err)
	}
	if state.files.hashes[request.GoBinary] != profile.DriverSHA256 {
		return nil, fmt.Errorf("actual Go driver changed during capture")
	}
	if downloaded != nil {
		if err := downloaded.verify(); err != nil {
			return nil, err
		}
	}
	return state, state.files.verify()
}

func equalAMD64OriginalObservationStates(a, b *amd64OriginalObservationState) bool {
	if a == nil || b == nil || len(a.files.directories) != len(b.files.directories) {
		return false
	}
	for name, info := range a.files.directories {
		other, present := b.files.directories[name]
		if !present || !os.SameFile(info, other) {
			return false
		}
	}
	return reflect.DeepEqual(a.profile, b.profile) && reflect.DeepEqual(a.environment, b.environment) &&
		reflect.DeepEqual(a.context, b.context) && reflect.DeepEqual(a.packages, b.packages) && reflect.DeepEqual(a.declarations, b.declarations) &&
		reflect.DeepEqual(a.files.hashes, b.files.hashes) && reflect.DeepEqual(a.files.paths, b.files.paths) &&
		reflect.DeepEqual(a.files.entries, b.files.entries) && reflect.DeepEqual(a.files.cpp, b.files.cpp)
}
