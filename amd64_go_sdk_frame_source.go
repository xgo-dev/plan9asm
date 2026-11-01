package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type goAMD64SDKFrameOrigin struct {
	identity *GoAMD64FrameSource
	owner    *GoAMD64SDKFrameObservation
	pkg      GoPackage
	request  GoAMD64FrameCaptureRequest
}

// CaptureGoAMD64SDKFrameSource is a distinct actual SDK-primary typed ABI0
// native frame factory. It authenticates the whole selected source/profile,
// compiler graph and all TEXTs, without relabeling SDK source as owned-main.
// Entries must be Go-declared with exact logical/native names, layout and
// source PCs. Same-source frame-unobserving leaf helpers retain no Go signature.
// Nonzero frames also require automatic BP/SP shapes;
// zero-frame siblings retain their ordinary ABI0 path without local backing.
// Generated split checks are observed separately from the source body.
// Native callers and ABI selectors require separate contracts. BindFixedLocal
// also accounts for the observed private leaf's automatic BP/FLAGS effects and
// proves every full-source access/initialization/CFG requirement before granting
// local bytes.
func CaptureGoAMD64SDKFrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest) (_ *GoAMD64FrameSource, result error) {
	if pkg.Types == nil || pkg.Path != pkg.Types.Path() || request.NumericalReads != nil ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || filepath.Ext(request.AssemblyFile) != ".s" {
		return nil, goAMD64FrameContext("SDK-primary requires its exact complete package/ABI0 source role")
	}
	owner, err := CaptureGoAMD64SDKFrameObservation(ctx, GoX86SDKASMDataCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: pkg.Path,
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		return nil, err
	}
	source := newGoOriginalInputGuard(request)
	source.sdkFrame = &goAMD64SDKFrameOrigin{identity: source, owner: owner, pkg: pkg, request: source.request}
	source.sdkFrame.request.Environment = append([]string(nil), source.request.Environment...)
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	data := owner.source
	data.operation.Lock()
	// Clone complete compiler state: the SDK owner's verification may update
	// its private guard maps, and a frame must neither alias nor mutate them.
	state := struct {
		Selection goAMD64FrameSelection
		Env       map[string]string
		Imports   map[string]goAMD64FrameSelection
	}{data.guard.selection, data.guard.env, data.guard.imports}
	raw, err := json.Marshal(state)
	if err == nil {
		state.Selection, state.Env, state.Imports = goAMD64FrameSelection{}, nil, nil
		err = json.Unmarshal(raw, &state)
		// RawMessage's nil marshals as null but decodes as literal "null".
		// Preserve the actual absent error projection rather than relabeling
		// an independently observed source selection during this private copy.
		state.Selection.Error = append(json.RawMessage(nil), data.guard.selection.Error...)
		for path, copied := range state.Imports {
			copied.Error = append(json.RawMessage(nil), data.guard.imports[path].Error...)
			state.Imports[path] = copied
		}
	}
	if err == nil {
		source.selection, source.env, source.imports = state.Selection, state.Env, state.Imports
		source.copySDKPrimaryInputInventory(data.guard)
		source.owned, source.ownedInfo = data.guard.owned, data.guard.ownedInfo
		source.functions, source.declarations, err = source.sdkFrameRecords()
	}
	data.operation.Unlock()
	if err != nil {
		return nil, err
	}
	source.ready = true
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

// Caller holds the SDK owner's operation lock. Full original/mapped/listing
// objects are already independently joined to the actual compiler archive.
// Reusing their native code is not permission to execute a helper or caller.
func (source *GoAMD64FrameSource) sdkFrameRecords() (map[string]goAMD64FrameFunction, map[string]goAMD64FrameDeclaration, error) {
	origin := source.sdkFrame
	data := origin.owner.source
	declarations, err := source.typedDeclarations(origin.pkg, false)
	if err != nil {
		return nil, nil, err
	}
	functions := make(map[string]goAMD64FrameFunction)
	found := false
	withFrame := false
	for ordinal, input := range data.observation.ObjectInputs.Sources {
		found = found || input.Name == source.request.AssemblyFile
		if ordinal >= len(data.observation.CPP) || ordinal >= len(data.observation.Frames) || ordinal >= len(data.observation.Objects.Sources) {
			return nil, nil, goAMD64FrameContext("SDK-primary complete native frame observation is missing")
		}
		cpp, native := data.observation.CPP[ordinal], data.observation.Frames[ordinal]
		original, err := source.read(filepath.Join(source.request.Directory, input.Name))
		if err != nil || !bytes.Equal(original, input.Original) || native.Source != input.Name {
			return nil, nil, goAMD64FrameContext("SDK-primary original assembly identity changed: %v", err)
		}
		file, err := ParseWithDefines(ArchAMD64, cpp.Output, nil)
		object := data.observation.Objects.Sources[ordinal]
		texts := object.Original.Texts
		if err != nil || len(file.Funcs) == 0 || len(file.UnlinkedPrelude) != 0 || len(file.Funcs) != len(native.Records) || len(file.Funcs) != len(texts) {
			return nil, nil, goAMD64FrameContext("SDK-primary complete parsed/native TEXT inventory differs: %v", err)
		}
		leaves, err := goAMD64FramePrivateLeaves(file, origin.pkg)
		if err != nil {
			return nil, nil, err
		}
		for index, fn := range file.Funcs {
			name := source.selection.ImportPath + "." + strings.TrimPrefix(fn.Sym, "·")
			_, declared := declarations[name]
			if index >= len(object.TextOrder) || object.TextOrder[index].SourceOrdinal != index ||
				object.TextOrder[index].ObjectOrdinal < 0 || object.TextOrder[index].ObjectOrdinal >= len(texts) {
				return nil, nil, goAMD64FrameContext("SDK-primary complete source/TEXT association differs")
			}
			record, text := native.Records[index], texts[object.TextOrder[index].ObjectOrdinal]
			if !record.ordinaryFrameRole() {
				return nil, nil, goAMD64FrameContext("SDK-primary native header has no ordinary/private frame entry role: %s", fn.Sym)
			}
			if leaves[fn.Sym] {
				if declared || record.Symbol != text.Name || record.Locals != uint64(goAMD64FrameNativeLocals(fn.FrameSize)) || !record.NoSplit ||
					record.ArgsKnown && record.Args != 0 || record.Static != strings.HasSuffix(fn.Sym, "<>") {
					return nil, nil, goAMD64FrameContext("SDK-primary private leaf/native identity differs: %s", fn.Sym)
				}
				continue // All original bytes/PCs/relocations are still consumed below.
			}
			// Real -std assembler objects retain qualified ABI0 declarations
			// in the non-package definition block. Its role is authenticated by
			// the complete same-source/compiler archive join, not by the name.
			defined := text.Namespace == gostaticstorage.TextSymbolSelf || text.Namespace == gostaticstorage.TextSymbolNonpkgDefinition
			if !declared || strings.Contains(fn.Sym, "<") || record.Static || !record.ArgsKnown ||
				!defined || text.ABI != 0 || name != record.Symbol || name != text.Name {
				return nil, nil, goAMD64FrameContext("SDK-primary frame requires an exact Go-declared logical ABI0 entry; private/native helper has no role: %s (declared=%t native=%s namespace=%d ABI=%d static=%t args-known=%t)", fn.Sym, declared, record.Symbol, text.Namespace, text.ABI, record.Static, record.ArgsKnown)
			}
			if fn.FrameSize < 0 || fn.FrameSize > 64<<10 || fn.FrameSize%8 != 0 || record.Locals != uint64(goAMD64FrameNativeLocals(fn.FrameSize)) || record.Args != fn.ArgSize {
				return nil, nil, goAMD64FrameContext("SDK-primary original declaration/native fixed-frame layout differs: %s", fn.Sym)
			}
			withFrame = withFrame || fn.FrameSize > 0
		}
		for _, observed := range cpp.Sources {
			expected, captured := source.inputs[observed.File]
			bytes, err := goAMD64FrameRead(observed.File)
			if err != nil || !captured || sha256.Sum256(bytes) != expected {
				return nil, nil, goAMD64FrameContext("SDK-primary native source PC lacks its original physical input: %v", err)
			}
			source.origins[observed.File] = strings.Count(string(bytes), "\n") + 1
		}
		var observed map[string]goAMD64FrameFunction
		if len(file.Data)+len(file.Globl) != 0 || bytes.Contains(native.OriginalListing, []byte("\trel ")) {
			data, readErr := source.fixedLocalDataObservation(input.Name, cpp.Output)
			if readErr != nil {
				return nil, nil, readErr
			}
			listing := native.OriginalListing
			if len(data.Layouts) != 0 {
				listing, readErr = goAMD64FrameDataListing(listing, data)
				if readErr != nil {
					return nil, nil, readErr
				}
			}
			observed, err = goAMD64FrameListingWithDataObject(listing, file, origin.pkg, source.origins, data, nil,
				source.request.Target, source.request.Directory, source.env["GOROOT"])
			if err == nil {
				err = goAMD64FrameDataTextJoin(observed, data, source.request.Directory, source.origins, source.env["GOROOT"])
			}
		} else if goAMD64FrameSplitListing(native.OriginalListing) {
			observed, err = goAMD64FrameListingWithSplitObject(native.OriginalListing, file, origin.pkg, source.origins, texts, nil,
				source.request.Target, source.request.Directory, source.env["GOROOT"])
		} else {
			observed, err = goAMD64FrameListingWithNumericalObject(native.OriginalListing, file, origin.pkg, source.origins, texts)
		}
		if err != nil {
			return nil, nil, err
		}
		for name, fn := range observed {
			declaration, declared := declarations[name]
			if _, duplicate := functions[name]; duplicate || fn.privateLeaf && declared ||
				!fn.privateLeaf && (!declared || !reflect.DeepEqual(fn.signature, declaration.signature)) {
				return nil, nil, goAMD64FrameContext("SDK-primary complete native/declaration frame identity differs")
			}
			fn.transport, fn.languageType = declaration.transport, declaration.languageType
			functions[name] = fn
		}
	}
	if !found {
		return nil, nil, goAMD64FrameContext("SDK-primary requested assembly is absent from complete selection")
	}
	if !withFrame {
		return nil, nil, goAMD64FrameContext("SDK-primary complete source has no nonzero native frame")
	}
	return functions, declarations, nil
}

func (source *GoAMD64FrameSource) verifySDKFrame(ctx context.Context) (result error) {
	origin := source.sdkFrame
	if origin == nil || origin.identity != source || origin.owner == nil || origin.owner.source == nil {
		return goAMD64FrameContext("copied or missing SDK-primary native frame owner")
	}
	defer func() {
		if result != nil {
			source.mu.Lock()
			source.ready = false
			source.mu.Unlock()
		}
	}()
	// SDK Verify samples caller contexts outside all frame/operation locks.
	if err := origin.owner.Verify(ctx); err != nil {
		return err
	}
	data := origin.owner.source
	data.operation.Lock()
	source.mu.Lock()
	err := func() error {
		if !source.ready || !reflect.DeepEqual(source.request, origin.request) ||
			!reflect.DeepEqual(source.selection, data.guard.selection) || !reflect.DeepEqual(source.env, data.guard.env) ||
			!reflect.DeepEqual(source.imports, data.guard.imports) || !reflect.DeepEqual(source.inputs, data.guard.inputs) ||
			source.directoryInventory != data.guard.directoryInventory {
			return goAMD64FrameContext("SDK-primary native frame source/profile/complete input identity changed")
		}
		if err := source.verifyInputs(); err != nil {
			return err
		}
		functions, declarations, err := source.sdkFrameRecords()
		if err != nil || !reflect.DeepEqual(functions, source.functions) || !reflect.DeepEqual(declarations, source.declarations) {
			return goAMD64FrameContext("SDK-primary original typed/native frame witness changed: %v", err)
		}
		return nil
	}()
	source.mu.Unlock()
	data.operation.Unlock()
	if err != nil {
		return err
	}
	return origin.owner.Verify(ctx)
}

func (source *GoAMD64FrameSource) closeSDKFrame() error {
	source.mu.Lock()
	origin := source.sdkFrame
	if origin == nil || origin.identity != source || origin.owner == nil {
		source.mu.Unlock()
		return goAMD64FrameContext("copied SDK-primary frame cannot close its original owner")
	}
	source.ready = false
	source.mu.Unlock()
	return origin.owner.Close()
}

// Called during the existing locked full-file binder. This immutable program
// was authenticated in capture/Verify; the outer postcheck rejects revocation
// or resolver-induced source changes before publishing any signature proof.
func (source *GoAMD64FrameSource) preprocessSDKFrame(name string, original []byte) (string, error) {
	data := source.sdkFrame.owner.source
	for ordinal, input := range data.observation.ObjectInputs.Sources {
		if input.Name == name && bytes.Equal(input.Original, original) && ordinal < len(data.observation.CPP) {
			return data.observation.CPP[ordinal].Output, nil
		}
	}
	return "", goAMD64FrameContext("SDK-primary fixed-local source lacks its complete original CPP identity")
}
