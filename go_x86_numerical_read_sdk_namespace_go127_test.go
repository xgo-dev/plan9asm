//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGoX86SDKNumericalReadPackageQueryMatchesOriginalLiteralSource(t *testing.T) {
	ctx, request, literalSource := numericalSDKLiteralFixture(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("independent numerical/literal SDK observers selected different packages", err)
	}
	defer source.Close()

	var selected struct{ Match []string }
	if json.Unmarshal(source.rawSelection, &selected) != nil ||
		!reflect.DeepEqual(selected.Match, []string{request.PackagePath}) ||
		!numericalSameRawSelection(source.rawSelection, literalSource.observation.RawSelection) {
		t.Fatal("exact original logical SDK selector was replaced or ignored", selected.Match)
	}
	for _, command := range source.commands {
		args := command.Arguments
		if len(args) > 0 && args[0] == "list" && args[len(args)-1] != request.PackagePath {
			t.Fatal("numerical SDK command receipt borrowed the owned-directory selector", args)
		}
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("live numerical SDK selection used a different query", err)
	}
	if err := literalSource.Verify(ctx); err != nil {
		t.Fatal("numerical observer changed its original borrowed SDK source", err)
	}
}
