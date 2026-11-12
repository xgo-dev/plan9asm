package plan9asm

import "context"

// GoAMD64SDKFrameObservation is a query-only complete SDK-primary source,
// default/config profile and native frame observation. It retains all selected
// Go/ASM sources and native TEXTs, including private and stack-splitting bodies.
// It grants no local backing, ABI transport, caller, loop, DATA read or extent
// permission. Ordinary owned-main and numerical factories remain distinct.
type GoAMD64SDKFrameObservation struct {
	identity *GoAMD64SDKFrameObservation
	source   *GoX86SDKASMDataSource
}

// CaptureGoAMD64SDKFrameObservation consumes the original producer environment,
// including an actual bounded GOENV file (or off) and the observed cgo default.
// No config, proxy, feature profile or compiler input is replaced for capture.
func CaptureGoAMD64SDKFrameObservation(ctx context.Context, request GoX86SDKASMDataCaptureRequest) (*GoAMD64SDKFrameObservation, error) {
	source, err := captureGoX86SDKASMDataSource(ctx, request, true)
	if err != nil {
		return nil, err
	}
	observed := &GoAMD64SDKFrameObservation{source: source}
	observed.identity = observed
	return observed, nil
}

func (observed *GoAMD64SDKFrameObservation) Verify(ctx context.Context) error {
	if observed == nil || observed.identity != observed || observed.source == nil {
		return sdkASMDataContext("missing or copied SDK-primary frame observation")
	}
	return observed.source.Verify(ctx)
}

// Readback returns diagnostics only. Serialized observations cannot construct
// a live source or a frame capability.
func (observed *GoAMD64SDKFrameObservation) Readback(ctx context.Context) ([]byte, error) {
	if observed == nil || observed.identity != observed || observed.source == nil {
		return nil, sdkASMDataContext("missing or copied SDK-primary frame observation")
	}
	return observed.source.Readback(ctx)
}

func (observed *GoAMD64SDKFrameObservation) Close() error {
	if observed == nil {
		return nil
	}
	if observed.identity != observed || observed.source == nil {
		return sdkASMDataContext("copied SDK-primary observation cannot close its original source")
	}
	return observed.source.Close()
}
