package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"time"
)

// This joins only the complete source/native observation. It supplies no DATA
// initializer, numerical owner, helper ABI or entry state.
type numericalSDKAssemblyJoin struct {
	Observation   sdkASMDataLiveObservation
	SourceOrdinal int
	source        *GoX86SDKASMDataSource
	generation    uint64
	seal          [32]byte
	stateSeal     [32]byte
	context       context.Context
	Deadline      time.Time
}

func captureNumericalSDKAssemblyJoin(ctx context.Context, request GoX86NumericalReadCaptureRequest, role numericalSBSourceRole) (*numericalSDKAssemblyJoin, error) {
	actual := request.AssemblySource
	if actual == nil {
		return nil, nil
	}
	if role != numericalSBSDKSource || actual.identity != actual {
		return nil, numericalSBContext("assembly join requires its independent live SDK source")
	}
	profile := actual.request
	if request.GoBinary != profile.GoBinary || request.Directory != profile.Directory ||
		request.PackagePath != profile.PackagePath || request.Target != profile.Target ||
		!reflect.DeepEqual(request.Environment, profile.Environment) {
		return nil, numericalSBContext("assembly observation source/tool/profile differs")
	}
	if request.ReadonlyLiterals != nil {
		if request.ReadonlyLiterals.source != actual {
			return nil, numericalSBContext("assembly and initializer have different original sources")
		}
		return nil, nil // Existing literal join owns the same source observation.
	}
	raw, err := actual.Readback(ctx)
	if err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !reflect.TypeOf(ctx).Comparable() {
		return nil, numericalSBContext("assembly numerical join requires one bounded original context")
	}
	joined := &numericalSDKAssemblyJoin{source: actual, context: ctx, Deadline: deadline}
	actual.mu.Lock()
	joined.generation, joined.seal, joined.stateSeal = actual.generation, actual.seal, actual.stateSeal
	actual.mu.Unlock()
	if json.Unmarshal(raw, &joined.Observation) != nil || sha256.Sum256(raw) != joined.seal {
		return nil, numericalSBContext("assembly join lost its authenticated complete readback")
	}
	file, ordinal, err := sdkASMMetadataSelectedMember(joined.Observation, request.AssemblyFile)
	if err != nil {
		return nil, err
	}
	joined.SourceOrdinal = ordinal
	if len(file.Funcs) == 0 || len(file.Data)+len(file.Globl)+len(file.UnlinkedPrelude) != 0 {
		return nil, numericalSBContext("metadata-only numerical member must retain its complete TEXT-only role")
	}
	return joined, joined.verifyIdentity(request)
}

// Literal and metadata routes share only immutable observation coordinates.
// The initializer's own owner/generation checks stay independent.
func (source *GoX86NumericalReadSource) sdkAssemblyJoin() *numericalSDKAssemblyJoin {
	if source.literals != nil {
		literal := source.literals
		return &numericalSDKAssemblyJoin{Observation: literal.Observation, SourceOrdinal: literal.SourceOrdinal,
			source: literal.source, context: literal.context, Deadline: literal.Deadline}
	}
	return source.assembly
}

func (joined *numericalSDKAssemblyJoin) verifyIdentity(request GoX86NumericalReadCaptureRequest) error {
	if joined == nil || joined.source == nil || joined.source.identity != joined.source || request.AssemblySource != joined.source {
		return numericalSBContext("assembly source identity changed")
	}
	actual := joined.source
	actual.mu.Lock()
	valid := actual.ready && actual.generation == joined.generation && actual.seal == joined.seal &&
		actual.stateSeal == joined.stateSeal && sha256.Sum256(actual.report) == joined.seal
	actual.mu.Unlock()
	if !valid {
		return numericalSBContext("assembly source generation changed or closed")
	}
	return nil
}

func (source *GoX86NumericalReadSource) verifySDKAssemblyIdentity() error {
	if source.literals != nil {
		return source.literals.verifyIdentity(source.request)
	}
	return source.assembly.verifyIdentity(source.request)
}

func (joined *numericalSDKAssemblyJoin) liveContext(ctx context.Context) error {
	if joined == nil || joined.source == nil {
		return numericalSBContext("assembly numerical join lost its original context")
	}
	if err := joined.source.liveContext(ctx); err != nil {
		return err
	}
	_, err := sampleGoSourceContext(ctx, joined.context,
		goSourceContextLifetime{deadline: joined.Deadline, bounded: true}, false,
		numericalSBContext("assembly numerical join original deadline changed or canceled without a cause"))
	return err
}

func (joined *numericalSDKAssemblyJoin) privateContext(ctx context.Context) (context.Context, func(), error) {
	if err := joined.liveContext(ctx); err != nil {
		return nil, nil, err
	}
	return sdkASMDataPrivateContext(ctx, joined.context, joined.Deadline)
}

func (source *GoX86NumericalReadSource) verifySDKAssemblyNumericalSource(ctx context.Context) (result error) {
	joined := source.assembly
	if source.identity != source || joined == nil {
		return numericalSBContext("copied or missing assembly numerical source")
	}
	defer func() {
		result = errors.Join(result, joined.liveContext(ctx), joined.verifyIdentity(source.request))
		source.mu.Lock()
		ready := source.ready
		source.mu.Unlock()
		if !ready {
			result = errors.Join(result, numericalSBContext("assembly numerical source closed during verification"))
		}
		if result != nil {
			source.revokeNumericalSource()
		}
	}()
	if err := errors.Join(joined.verifyIdentity(source.request), joined.liveContext(ctx)); err != nil {
		return err
	}
	if err := joined.source.Verify(ctx); err != nil {
		return err
	}
	for _, owner := range source.originalOwners {
		if err := owner.Verify(ctx); err != nil {
			return err
		}
	}
	private, stop, err := joined.privateContext(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if err := errors.Join(source.verifyNumericalSource(private), private.Err()); err != nil {
		return err
	}
	for _, owner := range source.originalOwners {
		if err := owner.Verify(ctx); err != nil {
			return err
		}
	}
	return joined.source.Verify(ctx)
}

func (source *GoX86NumericalReadSource) preprocessSDKAssembly() error {
	joined := source.sdkAssemblyJoin()
	if err := source.verifySDKAssemblyIdentity(); err != nil {
		return err
	}
	file, ordinal, err := sdkASMMetadataSelectedMember(joined.Observation, source.request.AssemblyFile)
	if err != nil || ordinal != joined.SourceOrdinal || len(file.Funcs) == 0 || len(file.UnlinkedPrelude) != 0 {
		return numericalSBContext("assembly numerical source lost its complete selected member: %v", err)
	}
	input := joined.Observation.ObjectInputs.Sources[ordinal]
	raw, err := source.guard.read(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil || !bytes.Equal(raw, input.Original) {
		return numericalSBContext("assembly numerical original source bytes changed: %v", err)
	}
	source.cpp, source.file = joined.Observation.CPP[ordinal], file
	if !bytes.Equal([]byte(source.cpp.Output), input.Expanded) {
		return numericalSBContext("assembly numerical complete CPP differs")
	}
	if source.literals != nil {
		return source.literals.verifyFile(file, source.request.PackagePath)
	}
	if len(file.Data)+len(file.Globl) != 0 {
		return numericalSBContext("assembly observation grants no initializer authority")
	}
	return nil
}
