package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// GoX86SDKReadonlyLiteralDataOwner is an opaque, explicit initializer owner.
// It is distinct from a Go numerical variable and supplies no pointer, read,
// native body, Frame, Options or ABI permission.
type GoX86SDKReadonlyLiteralDataOwner struct {
	mu               sync.Mutex
	identity         *GoX86SDKReadonlyLiteralDataOwner
	ready            bool
	generation       uint64
	source           *GoX86SDKASMDataSource
	originalSource   *GoX86SDKASMDataSource
	sourceGeneration uint64
	sourceSeal       [32]byte
	sourceStateSeal  [32]byte
	context          context.Context
	originalContext  context.Context
	originalDeadline time.Time
	report           []byte
	seal             [32]byte
}

type sdkReadonlyLiteralDataReport struct {
	Protocol, PackagePath, Target string
	SourceReportSHA256            [32]byte
	SourceGeneration              uint64
	Initializers                  []gostaticstorage.ReadonlyLiteralDataImage
}

const sdkReadonlyLiteralDataProtocol = "actual_go_sdk_private_readonly_literal_initializer_v1"

// CaptureGoX86SDKReadonlyLiteralDataOwner requires an actual live SDK ASM
// observation. Public reports, names, hashes and types are not constructors.
func CaptureGoX86SDKReadonlyLiteralDataOwner(ctx context.Context, source *GoX86SDKASMDataSource) (*GoX86SDKReadonlyLiteralDataOwner, error) {
	if ctx == nil || source == nil || source.identity != source {
		return nil, sdkASMDataContext("missing actual SDK literal DATA source")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !bounded || !reflect.TypeOf(ctx).Comparable() {
		return nil, sdkASMDataContext("literal initializer requires one bounded original capture context")
	}
	source.mu.Lock()
	generation, seal, stateSeal, ready := source.generation, source.seal, source.stateSeal, source.ready
	source.mu.Unlock()
	if !ready {
		return nil, sdkASMDataContext("literal DATA source is closed or revoked")
	}
	raw, err := source.Readback(ctx)
	if err != nil {
		return nil, err
	}
	// These bytes came only from this exact live source's authenticated retained
	// inputs. Neither the public report nor this decoder is a constructor.
	var observation sdkASMDataLiveObservation
	if sha256.Sum256(raw) != seal || json.Unmarshal(raw, &observation) != nil {
		return nil, sdkASMDataContext("literal DATA source readback changed")
	}
	images, err := gostaticstorage.ReadonlyLiteralDataInitializers(observation.Objects)
	if err != nil {
		return nil, sdkASMDataContext("private readonly literal DATA initialization: %v", err)
	}
	report, err := json.Marshal(sdkReadonlyLiteralDataReport{Protocol: sdkReadonlyLiteralDataProtocol,
		PackagePath: observation.Objects.PackagePath, Target: observation.Objects.Target,
		SourceReportSHA256: seal, SourceGeneration: generation, Initializers: images})
	if err != nil {
		return nil, err
	}
	owner := &GoX86SDKReadonlyLiteralDataOwner{source: source, originalSource: source,
		sourceGeneration: generation, sourceSeal: seal, sourceStateSeal: stateSeal,
		context: ctx, originalContext: ctx, originalDeadline: deadline,
		report: report, seal: sha256.Sum256(report), ready: true, generation: 1}
	owner.identity = owner
	if err := owner.Verify(ctx); err != nil {
		owner.Close()
		return nil, err
	}
	return owner, nil
}

func (owner *GoX86SDKReadonlyLiteralDataOwner) liveContext(ctx context.Context) error {
	if ctx == nil || owner.context == nil || owner.originalContext == nil ||
		reflect.TypeOf(owner.context) != reflect.TypeOf(owner.originalContext) ||
		!reflect.TypeOf(owner.context).Comparable() || owner.context != owner.originalContext {
		return sdkASMDataContext("literal initializer original context identity changed")
	}
	_, err := sampleGoSourceContext(ctx, owner.context,
		goSourceContextLifetime{deadline: owner.originalDeadline, bounded: true}, false,
		sdkASMDataContext("literal initializer original deadline changed or canceled without a cause"))
	return err
}

func (owner *GoX86SDKReadonlyLiteralDataOwner) verifySourceGeneration() error {
	source := owner.source
	if source == nil || source != owner.originalSource || source.identity != source {
		return sdkASMDataContext("literal initializer borrowed a foreign or copied source")
	}
	source.mu.Lock()
	current := source.ready && source.generation == owner.sourceGeneration &&
		source.seal == owner.sourceSeal && source.stateSeal == owner.sourceStateSeal
	source.mu.Unlock()
	if !current {
		return sdkASMDataContext("literal initializer source generation is closed, stale or changed")
	}
	return nil
}

// Verify rechecks the actual complete source/object producer, not a hash-only
// restored observation. All caller callbacks and source operations run outside
// this owner's mutex. Failure permanently revokes only this initializer token.
func (owner *GoX86SDKReadonlyLiteralDataOwner) Verify(ctx context.Context) (result error) {
	if owner == nil || owner.identity != owner {
		return sdkASMDataContext("copied, missing or uninitialized literal owner")
	}
	owner.mu.Lock()
	generation, ready := owner.generation, owner.ready
	owner.mu.Unlock()
	if !ready {
		return sdkASMDataContext("literal initializer is closed or revoked")
	}
	defer func() {
		result = errors.Join(result, owner.liveContext(ctx), owner.verifySourceGeneration())
		owner.mu.Lock()
		if owner.generation != generation || !owner.ready || sha256.Sum256(owner.report) != owner.seal {
			result = errors.Join(result, sdkASMDataContext("literal initializer closed or changed during verification"))
		}
		if result != nil {
			owner.ready = false
			owner.generation++
		}
		owner.mu.Unlock()
	}()
	if err := errors.Join(owner.liveContext(ctx), owner.verifySourceGeneration()); err != nil {
		return err
	}
	private, stop, err := sdkASMDataPrivateContext(ctx, owner.context, owner.originalDeadline)
	if err != nil {
		return err
	}
	defer stop()
	owner.mu.Lock()
	current := owner.ready && owner.generation == generation && sha256.Sum256(owner.report) == owner.seal
	owner.mu.Unlock()
	if !current {
		return sdkASMDataContext("literal initializer revoked during caller callbacks")
	}
	return errors.Join(owner.source.Verify(private), private.Err())
}

// Close revokes this owner only. Source artifacts belong to the independently
// supplied source and are never removed by a copied or ordinary initializer.
func (owner *GoX86SDKReadonlyLiteralDataOwner) Close() error {
	if owner == nil {
		return nil
	}
	if owner.identity != owner {
		return sdkASMDataContext("copied literal initializer cannot close its original owner")
	}
	owner.mu.Lock()
	owner.ready = false
	owner.generation++
	owner.mu.Unlock()
	return nil
}

// Readback returns immutable diagnostic bytes, not storage or read authority.
func (owner *GoX86SDKReadonlyLiteralDataOwner) Readback(ctx context.Context) ([]byte, error) {
	if err := owner.Verify(ctx); err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.ready {
		return nil, sdkASMDataContext("literal initializer closed after verification")
	}
	return append([]byte(nil), owner.report...), nil
}

// CheckReadback checks exact retained bytes. Public JSON cannot recreate the
// owner or turn an initial byte image into an initialized Go Variable.
func (owner *GoX86SDKReadonlyLiteralDataOwner) CheckReadback(ctx context.Context, raw []byte) error {
	if err := owner.Verify(ctx); err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.ready || !bytes.Equal(raw, owner.report) {
		owner.ready = false
		owner.generation++
		return sdkASMDataContext("literal initializer readback differs from retained original bytes")
	}
	return nil
}
