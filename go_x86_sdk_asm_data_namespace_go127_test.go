//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGoX86SDKASMDataOriginalVendorPackageNamespace(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "vendor/golang.org/x/crypto/chacha20poly1305")
	const assembly = "chacha20poly1305_amd64.s"
	filename := filepath.Join(request.Directory, assembly)
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("complete original vendored SDK namespace", err)
	}
	defer data.Close()
	cpp, positions := data.observation.CPP[0], data.observation.Positions[0]
	var eventTokens, positionBytes, eventBytes, sourceBytes int
	for _, event := range cpp.Events {
		eventTokens += len(event.Tokens)
		for _, token := range event.Tokens {
			eventBytes += len(token.Text) + len(token.RecordedValue) + len(token.Position.File)
		}
	}
	for _, token := range positions.Tokens {
		positionBytes += len(token.Text) + len(token.Position.File) + len(token.Position.Base.File) + len(token.Position.FinalBase.File)
	}
	for _, source := range cpp.Sources {
		sourceBytes += source.Bytes
	}
	used := eventBytes + positionBytes + len(positions.Mapped)
	t.Logf("complete CPP bytes: original=%d sources=%d event=%d position=%d mapped=%d used=%d/%d; tokens=%d+%d/%d",
		len(original), sourceBytes, eventBytes, positionBytes, len(positions.Mapped), used, ppGoObservationBytes,
		eventTokens, len(positions.Tokens), ppGoObservationTokens)
	if used > ppGoObservationBytes || eventTokens+len(positions.Tokens) > ppGoObservationTokens {
		t.Fatal("complete SDK position observation escaped its unchanged shared budget")
	}
	if data.guard.selection.ImportPath != request.PackagePath || !data.guard.selection.Standard ||
		data.guard.selection.Module != nil || len(data.observation.ObjectInputs.Sources) != 1 ||
		data.observation.ObjectInputs.Sources[0].Name != assembly ||
		!bytes.Equal(data.observation.ObjectInputs.Sources[0].Original, original) ||
		len(data.observation.Objects.Sources[0].Original.Texts) != 3 {
		t.Fatal("selected original Go/whole ASM namespace changed or cropped")
	}
	for _, command := range data.observation.Commands {
		if len(command.Arguments) > 0 && command.Arguments[0] == "list" && command.Arguments[len(command.Arguments)-1] != request.PackagePath {
			t.Fatal("SDK package query borrowed a CWD module namespace", command.Arguments)
		}
	}
	if err := data.Verify(ctx); err != nil {
		t.Fatal("live complete original vendor source", err)
	}
	request.PackagePath = "std/" + request.PackagePath
	bad, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if bad != nil {
		bad.Close()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("SDK-looking namespace alias acquired actual original source", err)
	}
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("original SDK source was changed", err)
	}
}
