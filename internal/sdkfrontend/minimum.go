package sdkfrontend

import (
	"context"
	"errors"
	"reflect"

	"github.com/xgo-dev/plan9asm"
)

// BindNumericalReads composes independent owners only when the complete typed
// source requests their role. Ordinary reads retain their ordinary binder.
func (source *Source) BindNumericalReads(ctx context.Context, pkg plan9asm.GoPackage, file *plan9asm.File, options plan9asm.Options) (bound plan9asm.Options, result error) {
	if err := source.begin(ctx); err != nil {
		return plan9asm.Options{}, err
	}
	defer func() {
		result = errors.Join(result, source.end())
		if result != nil {
			bound = plan9asm.Options{}
		}
	}()
	requested := plan9asm.GoX86SDKLiteralAlignmentRequested(file, options)
	if err := source.stillLive(); err != nil {
		return plan9asm.Options{}, err
	}
	if !requested {
		return source.Numerical.BindNumericalReads(ctx, pkg, file, options)
	}
	if source.literalOwner == nil {
		return plan9asm.Options{}, contextError("metadata-only source has no literal-minimum owner")
	}
	if !source.minimumAttempted {
		source.minimumAttempted = true // One actual attempt under the original bounded context.
		source.minimum, source.minimumError = plan9asm.CaptureGoX86SDKLiteralAlignment(ctx, source.literalOwner)
		if source.minimumError == nil {
			source.originalMinimum = source.minimum
			source.cleanup = append(source.cleanup, source.minimum.Close)
		}
	}
	if source.minimumError != nil {
		return plan9asm.Options{}, source.minimumError
	}
	if err := source.stillLive(); err != nil {
		return plan9asm.Options{}, err
	}
	// The core binder independently authenticates the exact same original
	// owner/source/context/profile, minimum generation and complete function.
	return source.Numerical.BindNumericalReadsWithLiteralAlignment(ctx, pkg, file, options, source.minimum)
}

func (source *Source) Verify(ctx context.Context) (result error) {
	if err := source.begin(ctx); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, source.end()) }()
	result = source.Numerical.Verify(ctx)
	if source.minimum != nil {
		result = errors.Join(result, source.minimum.Verify(ctx))
	}
	return result
}

// Active operations are exclusive, but Close never waits on user/context
// callbacks. It permanently revokes the handle and defers owned cleanup until
// that operation unwinds. Reentry cannot duplicate a capture or deadlock.
func (source *Source) begin(ctx context.Context) error {
	if source == nil || ctx == nil {
		return contextError("source lacks its original bounded context")
	}
	source.mu.Lock()
	if source.identity != source {
		source.mu.Unlock()
		return contextError("foreign source cannot enter borrowed ownership")
	}
	// Active cache publication is exclusively owned by the operation. Never
	// read its in-progress fields or call a user context from another entrant.
	if source.active {
		source.mu.Unlock()
		return contextError("source operation is already active")
	}
	if !source.originalComponents() {
		source.closePending = true
		cleanup := source.cleanup
		source.cleanup, source.closed = nil, true
		source.mu.Unlock()
		return errors.Join(contextError("original source components changed permanently"), source.revoke(), closeSDKSource(cleanup))
	}
	if source.closed || source.closePending ||
		!reflect.TypeOf(ctx).Comparable() || ctx != source.context {
		source.mu.Unlock()
		return contextError("source/owner/context/minimum is closed, reentrant or changed")
	}
	source.active = true
	source.mu.Unlock()
	// Reserve exclusivity before any caller context callback. Nested begin
	// must reject before sampling Err/Deadline/Done, not recursively invoke it.
	if err := ctx.Err(); err != nil {
		source.mu.Lock()
		source.closePending = true
		source.mu.Unlock()
		return errors.Join(err, source.end())
	}
	return nil
}

func (source *Source) stillLive() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.originalComponents() || source.closed || source.closePending {
		return contextError("source closed or changed during its active operation")
	}
	return nil
}

func (source *Source) end() error {
	source.mu.Lock()
	source.active = false
	if !source.originalComponents() {
		source.closePending = true
	}
	if !source.closePending {
		source.mu.Unlock()
		return nil
	}
	cleanup := source.cleanup
	source.cleanup, source.closed = nil, true
	source.mu.Unlock()
	return errors.Join(contextError("source closed or changed during its active operation"), source.revoke(), closeSDKSource(cleanup))
}

// Called under mu before/after every user callback boundary. Public Numerical
// replacement cannot silently change the source whose resources we own.
func (source *Source) originalComponents() bool {
	return source.identity == source && source.Numerical != nil && source.Numerical == source.originalNumerical &&
		source.literalOwner == source.originalLiteralOwner && source.minimum == source.originalMinimum
}

func (source *Source) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	if source.identity != source {
		source.mu.Unlock()
		return contextError("foreign source cannot close borrowed owners")
	}
	if source.closed {
		source.mu.Unlock()
		return nil
	}
	source.closePending = true
	if source.active {
		source.mu.Unlock()
		return source.revoke() // Immediate publication revocation; no locks/callbacks/artifact disposal.
	}
	cleanup := source.cleanup
	source.cleanup, source.closed = nil, true
	source.mu.Unlock()
	return errors.Join(source.revoke(), closeSDKSource(cleanup))
}

func (source *Source) revoke() error {
	if source.originalNumerical == nil {
		return nil
	}
	return source.originalNumerical.Revoke()
}

func closeSDKSource(cleanup []func() error) error {
	var result error
	for index := len(cleanup) - 1; index >= 0; index-- {
		result = errors.Join(result, cleanup[index]())
	}
	return result
}
