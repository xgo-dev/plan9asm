package main

import (
	"context"
	"fmt"

	"github.com/xgo-dev/plan9asm"
)

// Both frontends use the shared actual-owner/context demand planner. This
// adapter contributes no source role, minimum floor or new signature.
func (source *x86SDKNumericalCLISource) bindNumericalReads(ctx context.Context, file *plan9asm.File, options plan9asm.Options) (plan9asm.Options, error) {
	if source == nil || source.frontend == nil {
		return plan9asm.Options{}, fmt.Errorf("%w: SDK numerical source lacks its original shared handoff", plan9asm.ErrProbeNeedsContext)
	}
	var err error
	options, err = x86SDKDirectTailDeclarationOptions(source.goPackage, file, options)
	if err != nil {
		return plan9asm.Options{}, err
	}
	return source.frontend.BindNumericalReads(ctx, source.goPackage, file, options)
}
