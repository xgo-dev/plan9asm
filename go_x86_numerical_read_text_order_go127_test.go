//go:build go1.27

package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This consumes real complete source/header/compiler objects, not a fabricated
// numerical source or an entry token. Physical records must remain unchanged.
func TestGoX86SDKNumericalNativeOriginalMixedTextOrder(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, "amd64", "internal/bytealg")
			request.Target = target
			goos, _, _ := strings.Cut(target, "/")
			for index, entry := range request.Environment {
				if strings.HasPrefix(entry, "GOOS=") {
					request.Environment[index] = "GOOS=" + goos
				}
			}
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal("complete actual original SDK precondition", err)
			}
			defer source.Close()
			found := false
			for ordinal, observed := range source.observation.Objects.Sources {
				input := source.observation.ObjectInputs.Sources[ordinal]
				original, expanded, err := gostaticstorage.ObserveX86SDKASMDataListingObjects(source.observation.ObjectInputs,
					ordinal, input.OriginalObject, input.ExpandedObject)
				if err != nil {
					t.Fatal("complete actual native listing/object replay", err)
				}
				beforeOriginal, beforeExpanded := append([]byte(nil), original[0].Code...), append([]byte(nil), expanded[0].Code...)
				order, err := numericalSDKNativeTextOrder(source.observation.CPP[ordinal].Output,
					request.PackagePath, observed, original, expanded)
				if err != nil || len(order) != len(original) {
					t.Fatal("complete native consumer association", observed.Name, err)
				}
				if observed.Name == "equal_amd64.s" {
					found = true
					if !reflect.DeepEqual(order, []int{1, 2, 0}) || original[0].Name != "memeqbody" || original[0].ABI != 65535 {
						t.Error("consumer confused source ordinal with unchanged physical order", order)
					}
				}
				if !reflect.DeepEqual(beforeOriginal, original[0].Code) || !reflect.DeepEqual(beforeExpanded, expanded[0].Code) {
					t.Fatal("association rewrote physical native evidence")
				}
			}
			if !found {
				t.Fatal("original equal source was cropped")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("consumer changed the live original observation", err)
			}
		})
	}
}

func TestGoX86SDKNumericalNativeTextOrderLiveRevocation(t *testing.T) {
	ctx, request, _ := numericalSDKLiteralFixture(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("actual complete numerical/source native precondition", err)
	}
	defer source.Close()
	order := source.literals.Observation.Objects.Sources[source.literals.SourceOrdinal].TextOrder
	if len(order) == 0 {
		t.Fatal("native numerical join omitted its complete source mapping")
	}
	before := order[0]
	order[0].ObjectOrdinal++
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed native source association retained a numerical certificate", err)
	}
	order[0] = before
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restoring changed metadata revived its revoked numerical source", err)
	}
}
