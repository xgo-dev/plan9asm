//go:build go1.27

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The original SDK helper deliberately fixes GOAMD64=v1 for its strict DATA
// role. These separate fresh requests test the actual inactive field instead;
// they retain the complete original source and never authorize its execution.
func TestX86SDKOriginalSource386InactiveAMD64ProfileCompleteCapture(t *testing.T) {
	for _, profile := range []struct {
		name, value string
		provided    bool
	}{
		{"unset", "", false},
		{"empty", "", true},
		{"v3", "v3", true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, "386", "internal/runtime/atomic")
			var environment []string
			for _, pair := range request.Environment {
				if !strings.HasPrefix(pair, "GOAMD64=") {
					environment = append(environment, pair)
				}
			}
			if profile.provided {
				environment = append(environment, "GOAMD64="+profile.value)
			}
			request.Environment = environment
			before := append([]string(nil), environment...)
			actual, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary,
				"env", "-json", "GOOS", "GOARCH", "GOAMD64", "GO386")
			var profileObservation map[string]string
			if err != nil || json.Unmarshal(actual, &profileObservation) != nil {
				t.Fatal("independent actual Go profile observation failed", err)
			}
			inactive, present := profileObservation["GOAMD64"]
			if !present || inactive != profile.value || profileObservation["GO386"] != "sse2" ||
				profileObservation["GOOS"] != "linux" || profileObservation["GOARCH"] != "386" {
				t.Fatal("actual inactive/active architecture fields differ", profileObservation)
			}
			t.Logf("independent actual original386 profile before capture: %s", actual)
			if public, err := CaptureGoX86SDKASMDataSource(ctx, request); public != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("inactive original-source profile leaked into strict DATA/NUM observation", err)
			}
			if frame, err := CaptureGoAMD64SDKFrameObservation(ctx, request); frame != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("386 source-only profile acquired an AMD64 native-frame observation", err)
			}
			source, err := captureGoX86SDKASMDataSourceRole(ctx, request, sdkASMDataOriginalSourceRole)
			if err != nil {
				t.Fatal("complete actual original386 inactive-profile source capture", err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error("close original source observation", err)
				}
			})
			var observed map[string]string
			rawEnvironment := append([]byte(nil), source.observation.RawEnvironment...)
			if err := json.Unmarshal(rawEnvironment, &observed); err != nil {
				t.Fatal("actual command environment is not complete JSON", err)
			}
			value, present := observed["GOAMD64"]
			if !present || value != profile.value || observed["GO386"] != "sse2" ||
				observed["GOOS"] != "linux" || observed["GOARCH"] != "386" ||
				!reflect.DeepEqual(observed, source.guard.env) ||
				!reflect.DeepEqual(before, request.Environment) || !reflect.DeepEqual(before, source.request.Environment) {
				t.Fatal("capture changed an original observed/active profile or its request", observed)
			}
			if source.captureRole != sdkASMDataOriginalSourceRole || len(source.observation.Frames) != 0 ||
				source.frameListingBytes != 0 || source.guard.ready || source.guard.sdkFrame != nil ||
				len(source.guard.functions) != 0 || source.guard.numericalOrigin != nil {
				t.Fatal("inactive-field observation acquired frame or numerical authority")
			}
			objects := source.observation.Objects
			inputs := source.observation.ObjectInputs
			if objects == nil || len(objects.Sources) != 1 || len(objects.Sources[0].Original.Texts) != 42 ||
				len(objects.Sources[0].Expanded.Texts) != 42 || len(objects.Members) != 3 ||
				len(objects.Sources[0].GeneratedFuncdata) != 1 || len(objects.Sources[0].GeneratedFuncdata[0].Owners) != 5 ||
				len(objects.Sources[0].ExpandedLayouts) != 0 || len(inputs.Sources) != 1 || len(inputs.Archive) == 0 ||
				len(source.observation.CPP) != 1 || len(source.observation.Positions) != 1 {
				t.Fatal("inactive profile lost complete compiler/archive/42-TEXT/generated-source identity")
			}
			original := inputs.Sources[0]
			if strings.Count(string(original.Original), "\nTEXT ") != 42 || len(original.OriginalObject) == 0 ||
				len(original.ExpandedObject) == 0 || !bytes.Equal(original.Expanded, []byte(source.observation.CPP[0].Output)) {
				t.Fatal("complete original/expanded assembly or native objects were cropped")
			}
			if images, err := gostaticstorage.ReadonlyLiteralDataInitializers(objects); images != nil || !errors.Is(err, gostaticstorage.ErrContext) {
				t.Fatal("generated metadata became a readonly/numerical initializer owner", images, err)
			}
			pkg, err := source.typedPackage("go1.27")
			if err != nil || len(pkg.SourceSelection.Assembly) != 1 {
				t.Fatal("actual complete typed SDK selection differs", err)
			}
			for _, file := range pkg.SourceSelection.Assembly {
				if len(file.Funcs) != 42 {
					t.Fatal("actual selected source lost an original TEXT")
				}
			}
			sdkASMDataRetain(t, source) // Optional owned artifact directory retains the full raw observation.
			if err := source.Verify(ctx); err != nil || !bytes.Equal(rawEnvironment, source.observation.RawEnvironment) {
				t.Fatal("complete live verification changed original observed bytes", err)
			}
			t.Logf("source-only42TEXT inactive GOAMD64=%q provided=%t activeGO386=sse2 rawenv=%s original=%x expanded=%x originalobject=%x expandedobject=%x",
				value, profile.provided, rawEnvironment, sha256.Sum256(original.Original), sha256.Sum256(original.Expanded),
				sha256.Sum256(original.OriginalObject), sha256.Sum256(original.ExpandedObject))
			// An observed inactive field does not weaken the actual active profile
			// or the permanent complete-source seal, even if bytes are restored.
			for index, pair := range source.request.Environment {
				if strings.HasPrefix(pair, "GO386=") {
					source.request.Environment[index] = "GO386=softfloat"
				}
			}
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed active profile retained the source observation", err)
			}
			source.request.Environment = append([]string(nil), before...)
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("restoring a changed active profile revived its observation", err)
			}
		})
	}
}
