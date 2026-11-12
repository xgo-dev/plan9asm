//go:build go1.27

package sdkfrontend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSharedSDKMetadataOriginalEmptyDATACompleteThreeOS(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			ctx, request := sdkMetadataOriginalRequest(t, target)
			original := &sdkMinimumCallbackContext{Context: ctx}
			file, source, err := CaptureMetadata(original, request)
			if err != nil {
				t.Fatal("actual complete SDK metadata precondition", err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			if len(file.Funcs) != 3 || len(file.Data)+len(file.Globl) != 0 ||
				file.Funcs[0].Sym != "runtime·memequal<ABIInternal>" || file.Funcs[2].Sym != "memeqbody<>" {
				t.Fatal("actual selected original member was cropped or relabeled")
			}
			raw, err := source.Readback(original)
			if err != nil {
				t.Fatal(err)
			}
			var observed struct {
				CPP          []plan9asm.AssemblyCPPObservation
				Positions    []json.RawMessage
				ObjectInputs gostaticstorage.SDKASMDataObservationRequest
				Objects      *gostaticstorage.SDKASMDataObservation
			}
			if json.Unmarshal(raw, &observed) != nil || observed.Objects == nil ||
				len(observed.Objects.Sources) < 2 || len(observed.Objects.Members) != len(observed.Objects.Sources)+2 ||
				len(observed.CPP) != len(observed.Objects.Sources) || len(observed.Positions) != len(observed.CPP) {
				t.Fatal("metadata lost the complete selected package/header/CPP inventory")
			}
			replayed, err := gostaticstorage.ObserveX86SDKCPPASMData(observed.ObjectInputs)
			if err != nil || !reflect.DeepEqual(replayed, observed.Objects) {
				t.Fatal("whole original/expanded/compiler object tuples differ", err)
			}
			found := false
			for index, member := range observed.Objects.Sources {
				if len(member.ExpandedLayouts) != 0 {
					t.Fatal("empty DATA inventory became an initializer")
				}
				if member.Name == "equal_amd64.s" {
					found = true
					var order []int
					for _, association := range member.TextOrder {
						order = append(order, association.ObjectOrdinal)
					}
					if !reflect.DeepEqual(order, []int{1, 2, 0}) || member.Original.Texts[0].Name != "memeqbody" ||
						!reflect.DeepEqual(member.Original.Texts, observed.Objects.Members[index+2].Texts) {
						t.Fatal("source ordinals replaced unchanged physical records")
					}
				}
			}
			if !found {
				t.Fatal("selected original member is absent")
			}
			owner, err := plan9asm.CaptureGoX86SDKReadonlyLiteralDataOwner(original, source)
			if owner != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "no private readonly literal DATA initializers") {
				t.Fatal("metadata manufactured an empty initializer owner", err)
			}
			for _, method := range []string{"BindNumericalReads", "BindNumericalReadsWithLiteralAlignment", "Options"} {
				if _, present := reflect.TypeOf(source).MethodByName(method); present {
					t.Fatal("metadata leaf exposes another permission", method)
				}
			}
			if missing, err := source.Assembly(original, "unselected.s"); missing != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("unselected member acquired source identity", err)
			}
			if err := source.Verify(original); err != nil {
				t.Fatal("unsupported member selection revoked its independent live observer", err)
			}
			var reached atomic.Bool
			original.mu.Lock()
			original.callback = func(method string) {
				if method == "Err" && reached.CompareAndSwap(false, true) {
					if err := source.Close(); err != nil {
						t.Error(err)
					}
				}
			}
			original.mu.Unlock()
			if closed, err := source.Assembly(original, "equal_amd64.s"); closed != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !reached.Load() {
				t.Fatal("callback Close published parsed metadata after revocation", err)
			}
			original.mu.Lock()
			original.callback = nil
			original.mu.Unlock()
			if err := source.Verify(original); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("restored callback revived the closed original observer", err)
			}
			if closed, err := source.Readback(original); closed != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("closed owner retained diagnostic publication", err)
			}
		})
	}
}

// Only command/profile setup lives here; all ASM/header/object observation
// remains in the existing production producer. CGO is the actual Go default.
func sdkMetadataOriginalRequest(t *testing.T, target string) (context.Context, CaptureRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	goos, arch, valid := strings.Cut(target, "/")
	if !valid {
		t.Fatal("invalid test target")
	}
	for key, value := range map[string]string{"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "",
		"GOPACKAGESDRIVER": "off", "GOPROXY": "off", "GOOS": goos, "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2"} {
		t.Setenv(key, value)
	}
	t.Setenv("CGO_ENABLED", "")
	if err := os.Unsetenv("CGO_ENABLED"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		directory, err := sourcepath.Resolve(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, directory)
	}
	root, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "src", "internal", "bytealg")
	environment := os.Environ()
	cgo, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, binary, "env", "CGO_ENABLED")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual default CGO profile: %v\n%s", err, stderr)
	}
	values, err := EnvironmentValues(environment)
	if err != nil {
		t.Fatal(err)
	}
	values["CGO_ENABLED"] = strings.TrimSpace(string(cgo))
	return ctx, CaptureRequest{GoBinary: binary, Directory: directory, PackagePath: "internal/bytealg",
		AssemblyFile: filepath.Join(directory, "equal_amd64.s"), Target: target, Environment: EncodeEnvironment(values)}
}
