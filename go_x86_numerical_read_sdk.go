package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type numericalSBSourceRole uint8

const (
	numericalSBOwnedSource numericalSBSourceRole = iota + 1
	numericalSBSDKSource
)

// Owned sources retain their actual directory query. All SDK observers use
// the same original logical package selector, including its raw Match field;
// a directory query can otherwise select a different module/vendor namespace.
func (source *GoX86NumericalReadSource) packageQuery() string {
	if source.role == numericalSBSDKSource {
		return source.request.PackagePath
	}
	return "."
}

// This is input/object observation, not an instruction certificate. It cannot
// create a numerical source by deserialization, Standard, or a matching hash.
type numericalSBSDKObservation struct {
	Graph           []byte
	Archive         []byte
	ArchiveMembers  []gostaticstorage.TextMember
	Imports         map[string]goAMD64FrameSelection
	Referenced      map[string]gostaticstorage.SDKReferencedArchive
	Inputs          map[string][32]byte
	origin          *GoX86NumericalReadSource
	seal            [32]byte
	closed          bool
	context         context.Context
	originalContext context.Context
}

// CaptureGoX86SDKNumericalReadSource is an explicit SDK source entry point.
// SDK source identity is separate from the SDK CPU numerical storage owner;
// neither a Standard flag nor an assembly symbol supplies that identity.
func CaptureGoX86SDKNumericalReadSource(ctx context.Context, request GoX86NumericalReadCaptureRequest) (*GoX86NumericalReadSource, error) {
	return captureGoX86NumericalReadSource(ctx, request, numericalSBSDKSource, false)
}

func (source *GoX86NumericalReadSource) verifySDKDirectory(root string) error {
	path := source.request.PackagePath
	if source.role != numericalSBSDKSource || !filepath.IsLocal(filepath.FromSlash(path)) ||
		filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path {
		return numericalSBContext("SDK source needs an exact canonical package path")
	}
	wanted := filepath.Join(root, "src", filepath.FromSlash(path))
	resolved, err := sourcepath.Resolve(wanted)
	actual, actualErr := os.Lstat(source.request.Directory)
	physical, physicalErr := os.Lstat(wanted)
	if err != nil || resolved != wanted || actualErr != nil || physicalErr != nil ||
		!actual.IsDir() || !physical.IsDir() || !os.SameFile(actual, physical) || source.request.Directory != wanted {
		return numericalSBContext("SDK source is not this invoked installation's exact physical package")
	}
	return nil
}

func (source *GoX86NumericalReadSource) captureSourceRole(ctx context.Context) error {
	selected := source.guard.selection
	if source.role == numericalSBOwnedSource {
		if selected.Standard || selected.Module == nil || !selected.Module.Main || selected.Module.Version != "" || selected.Module.Path == "" ||
			len(selected.Module.Replace) != 0 && string(selected.Module.Replace) != "null" ||
			selected.Module.GoMod != filepath.Join(selected.Module.Dir, "go.mod") ||
			!goAssemblyPathWithinRoot(selected.Module.Dir, source.request.Directory) {
			return numericalSBContext("consumer needs complete original owned-main module/source role")
		}
		_, err := source.guard.read(selected.Module.GoMod)
		return err
	}
	if source.role != numericalSBSDKSource || !selected.Standard || selected.Module != nil {
		return numericalSBContext("SDK source must independently retain its actual standard/no-module selection")
	}
	if err := source.verifySDKDirectory(source.guard.env["GOROOT"]); err != nil {
		return err
	}
	compiled := append([]string(nil), selected.CompiledGoFiles...)
	for index, name := range compiled {
		if filepath.IsAbs(name) {
			relative, err := filepath.Rel(selected.Dir, name)
			if err != nil || filepath.Base(relative) != relative {
				return numericalSBContext("SDK effective/generated compiler sources need a separate mapping")
			}
			compiled[index] = relative
		}
	}
	if !reflect.DeepEqual(compiled, selected.GoFiles) {
		return numericalSBContext("SDK selection omitted complete ordinary compiler sources")
	}
	matched := 0
	for _, name := range selected.SFiles {
		if name == source.request.AssemblyFile {
			matched++
		}
	}
	if matched != 1 {
		return numericalSBContext("SDK assembly is not uniquely selected by the actual target")
	}
	if source.sdkAssemblyJoin() != nil {
		return source.captureSDKAssemblySourceRole(ctx)
	}
	graph, err := source.run(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", source.packageQuery())
	if err != nil {
		return err
	}
	imports, err := source.guard.bindOriginalDeclarationImports(graph)
	if err != nil {
		return err
	}
	source.guard.imports = imports
	referenced := make(map[string]gostaticstorage.SDKReferencedArchive)
	paths := make([]string, 0, len(imports))
	for path := range imports {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		dependency := imports[path]
		if path == "unsafe" {
			continue // Builtin package; no compiler export or foreign SymbolDefs.
		}
		data, err := source.guard.read(dependency.Export)
		if err != nil {
			return err
		}
		referenced[path] = gostaticstorage.SDKReferencedArchive{PackagePath: path,
			Sources: append([]string(nil), dependency.SFiles...), Archive: data}
	}
	archive, err := source.guard.read(selected.Export)
	if err != nil {
		return err
	}
	builtin, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		return err
	}
	members, err := gostaticstorage.ObserveX86SDKAssemblyArchiveReferences(archive, builtin, source.request.Target, selected.SFiles, referenced)
	if err != nil {
		return numericalSBContext("SDK actual selected compiler/archive members differ: %v", err)
	}
	inputs := make(map[string][32]byte, len(source.guard.inputs))
	for name, digest := range source.guard.inputs {
		inputs[name] = digest
	}
	source.sdk = &numericalSBSDKObservation{Graph: graph, Archive: archive, ArchiveMembers: members,
		Imports: imports, Referenced: referenced, Inputs: inputs, origin: source, context: ctx, originalContext: ctx}
	source.sdk.seal, err = source.sdkDigest()
	if err != nil {
		return err
	}
	return nil
}

func (source *GoX86NumericalReadSource) sdkDigest() ([32]byte, error) {
	raw, err := json.Marshal(struct {
		Request      GoX86NumericalReadCaptureRequest
		GuardRequest GoAMD64FrameCaptureRequest
		Role         numericalSBSourceRole
		Selection    goAMD64FrameSelection
		Env          map[string]string
		Entries      []string
		SDK          *numericalSBSDKObservation
	}{source.request, source.guard.request, source.role, source.guard.selection, source.guard.env, source.guard.entries, source.sdk})
	return sha256.Sum256(raw), err
}

// The caller owns source.mu during a published Verify. Capture has not
// published this source. This method invokes no caller resolver or callback.
func (source *GoX86NumericalReadSource) verifySDKObservation(ctx context.Context) (result error) {
	defer func() {
		if source != nil && source.identity == source && source.sdk != nil && !source.sdk.closed {
			if err := source.verifySDKCaptureContext(); err != nil {
				result = errors.Join(result, err)
			}
			if ctx != nil && ctx.Err() != nil {
				result = errors.Join(result, fmt.Errorf("verify SDK source postcheck: %w", ctx.Err()))
			}
		}
		if result != nil && source != nil && source.identity == source && source.sdk != nil {
			source.sdk.closed = true
		}
	}()
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("verify SDK numerical source observation: %w", ctx.Err())
	}
	if ctx == nil || source == nil || source.identity != source || source.role != numericalSBSDKSource ||
		source.sdk == nil || source.sdk.origin != source || source.sdk.closed {
		return numericalSBContext("missing live independent SDK source observation")
	}
	if err := source.verifySDKCaptureContext(); err != nil {
		return err
	}
	if source.guard == nil || source.guard.request.NumericalReads != nil {
		return numericalSBContext("SDK source observer cannot borrow a frame/numerical token")
	}
	before, err := source.sdkDigest()
	if err != nil || before != source.sdk.seal {
		return numericalSBContext("sealed independent SDK source/object graph changed")
	}
	if len(source.request.Owners) != len(source.originalOwners) {
		return numericalSBContext("SDK source owner inventory changed")
	}
	for ordinal, owner := range source.originalOwners {
		if owner != source.request.Owners[ordinal] {
			return numericalSBContext("SDK source owner identity/order changed")
		}
		if source.sdkAssemblyJoin() == nil {
			if err := owner.Verify(ctx); err != nil {
				return err
			}
		}
	}
	for name, input := range source.sdk.Inputs {
		if source.guard.inputs[name] != input {
			return numericalSBContext("SDK original source/tool/export input identity changed")
		}
	}
	if err := source.verifySDKDirectory(source.guard.env["GOROOT"]); err != nil {
		return err
	}
	if err := source.guard.verifyInputs(); err != nil {
		return err
	}
	graph, err := source.guard.run(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", source.packageQuery())
	if err != nil {
		return err
	}
	raw, err := numericalSDKGraphRoot(graph, source.request.PackagePath)
	if err != nil {
		return err
	}
	selected, _, err := source.guard.readRawPackageSelection(raw)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(selected, source.guard.selection) || !numericalSameRawSelection(source.rawSelection, raw) {
		return numericalSBContext("actual consumer selection/export changed")
	}
	imports, err := source.guard.bindOriginalDeclarationImports(graph)
	if err != nil {
		return numericalSBContext("complete SDK source/export graph cannot be rebound: %v", err)
	}
	if !reflect.DeepEqual(imports, source.sdk.Imports) || !reflect.DeepEqual(imports, source.guard.imports) {
		return numericalSBContext("complete SDK declaration import bindings changed")
	}
	if !numericalSameRawSDKGraph(source.sdk.Graph, graph) {
		return numericalSBContext("complete SDK source/export/selection graph changed")
	}
	if err := source.guard.verifyInputs(); err != nil {
		return err
	}
	after, err := source.sdkDigest()
	if err != nil || after != source.sdk.seal {
		return numericalSBContext("SDK source/object identity changed during observation")
	}
	return nil
}

func (source *GoX86NumericalReadSource) verifySDKCaptureContext() error {
	if joined := source.sdkAssemblyJoin(); joined != nil {
		// The joined route samples both original contexts outside source.mu.
		// The serialized portion can only consume the already sampled lease.
		if source.sdk.context != joined.context || source.sdk.originalContext != joined.context {
			return numericalSBContext("joined SDK capture context identity changed")
		}
		return source.verifySDKAssemblyIdentity()
	}
	if source.sdk.context == nil || source.sdk.originalContext == nil ||
		reflect.TypeOf(source.sdk.context) != reflect.TypeOf(source.sdk.originalContext) ||
		!reflect.TypeOf(source.sdk.context).Comparable() || source.sdk.context != source.sdk.originalContext {
		return numericalSBContext("SDK capture context identity changed")
	}
	if err := source.sdk.context.Err(); err != nil {
		return fmt.Errorf("original SDK numerical capture context: %w", err)
	}
	return nil
}

func numericalRawSDKGraph(data []byte) ([]json.RawMessage, bool) {
	if len(data) == 0 || len(data) > 16<<20 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var values []json.RawMessage
	for {
		var value json.RawMessage
		if err := decoder.Decode(&value); err == io.EOF {
			return values, len(values) != 0
		} else if err != nil || len(values) >= 4096 {
			return nil, false
		}
		values = append(values, value)
	}
}

func numericalSDKGraphRoot(graph []byte, path string) ([]byte, error) {
	values, valid := numericalRawSDKGraph(graph)
	if !valid {
		return nil, numericalSBContext("incomplete or oversized SDK selection graph")
	}
	var root json.RawMessage
	for _, raw := range values {
		var selected struct{ ImportPath string }
		if json.Unmarshal(raw, &selected) != nil {
			return nil, numericalSBContext("malformed SDK selection graph record")
		}
		if selected.ImportPath == path {
			if root != nil {
				return nil, numericalSBContext("SDK selection graph repeats the original root")
			}
			root = raw
		}
	}
	if root == nil {
		return nil, numericalSBContext("SDK selection graph omitted the original root")
	}
	return root, nil
}

func numericalSameRawSDKGraph(first, second []byte) bool {
	a, validA := numericalRawSDKGraph(first)
	b, validB := numericalRawSDKGraph(second)
	if !validA || !validB || len(a) != len(b) {
		return false
	}
	for index := range a {
		if !numericalSameRawSelection(a[index], b[index]) {
			return false
		}
	}
	return true
}
