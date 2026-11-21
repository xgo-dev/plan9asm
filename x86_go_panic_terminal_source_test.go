package plan9asm

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestX86GoPanicTerminalBindsSourceOSToBackend(t *testing.T) {
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	for _, row := range []struct{ source, goos, triple string }{
		{"linux/386", "windows", "i686-pc-windows-msvc"},
		{"windows/386", "windows", "i686-unknown-linux-gnu"},
		{"windows/386", "linux", "i386-unknown-linux-gnu"},
		{"windows/386", "windows", "x86_64-pc-windows-msvc"},
		{"windows/386", "windows", "i686-pc-windows-msvc-elf"},
		{"linux/386", "linux", "i386-unknown-linux-gnu-coff"},
		{"freebsd/386", "freebsd", "i386-unknown-freebsd"},
	} {
		request := GoSDKAssemblyCaptureRequest{Target: row.source}
		options := GoModuleOptions{GOARCH: "386", GOOS: row.goos, TargetTriple: row.triple}
		result, err := TranslateGoX86SDKPanicTerminalModuleInContext(context.Background(), ctx, request, options)
		if result != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "target-matched 386") {
			t.Errorf("mismatched target %+v acquired a producer: %v", row, err)
		}
		result, err = TranslateGoX86SDKABI0TailModuleInContext(context.Background(), ctx, request, options)
		if result != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "target-matched 386") {
			t.Errorf("mismatched target %+v acquired an ABI0 tail: %v", row, err)
		}
	}
}

func TestX86GoPanicTerminalSourceCannotBeReconstructedFromReports(t *testing.T) {
	for _, source := range []*GoX86SDKASMDataSource{nil, {}, {ready: true, generation: 1, captureRole: sdkASMDataOriginalSourceRole}} {
		if source != nil {
			source.identity = source
		}
		if observed, err := source.panicTerminalObservation(context.Background(), &x86ResultFlowBudget{}); !errors.Is(err, ErrProbeNeedsContext) || observed != nil {
			t.Fatal("a caller value or report acquired a live actual-source association", observed, err)
		}
	}
	actual := &GoX86SDKASMDataSource{}
	actual.identity = actual
	copy := new(GoX86SDKASMDataSource)
	reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(actual).Elem())
	if observed, err := copy.panicTerminalObservation(context.Background(), &x86ResultFlowBudget{}); !errors.Is(err, ErrProbeNeedsContext) || observed != nil {
		t.Fatal("copied source acquired original compiler-body association", observed, err)
	}
}

func TestX86GoPanicTerminalGeneratedCompilerKeepsWholeBody(t *testing.T) {
	pkg, symABI, objects := x86PanicTerminalCompilerFixture(t)
	bodies, err := x86GoPanicTerminalCompilerBodies(pkg, symABI, objects, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := x86GoPanicTerminalGeneratedBodies(bodies, objects.Members[1].Texts, ""); err != nil {
		t.Fatal("complete independently generated compiler body did not match its actual selected definition", err)
	}
	for name, mutate := range map[string]func(*gostaticstorage.TextRecord){
		"code":        func(text *gostaticstorage.TextRecord) { text.Code[0] ^= 1 },
		"ABI":         func(text *gostaticstorage.TextRecord) { text.ABI = 0 },
		"source":      func(text *gostaticstorage.TextRecord) { text.Positions[0].File += ".other" },
		"source-line": func(text *gostaticstorage.TextRecord) { text.Positions[0].Line++ },
		"namespace":   func(text *gostaticstorage.TextRecord) { text.Namespace = gostaticstorage.TextSymbolNonpkgDefinition },
		"auxiliary": func(text *gostaticstorage.TextRecord) {
			text.Auxiliary = append(text.Auxiliary, gostaticstorage.TextAuxiliary{Type: 2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			text := x86GoPanicTerminalCloneText(objects.Members[1].Texts[0])
			mutate(&text)
			if err := x86GoPanicTerminalGeneratedBodies(bodies, []gostaticstorage.TextRecord{text}, ""); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("partial/different fresh compiler body acquired an association", err)
			}
		})
	}
}

func TestX86GoPanicTerminalCompilerObservationDoesNotAliasInputs(t *testing.T) {
	pkg, symABI, objects := x86PanicTerminalCompilerFixture(t)
	bodies, err := x86GoPanicTerminalCompilerBodies(pkg, symABI, objects, "")
	if err != nil {
		t.Fatal(err)
	}
	bodies[0].text.Code[0] ^= 1
	bodies[0].text.Positions[0].Line++
	if objects.Members[1].Texts[0].Code[0] != 0xe8 || objects.Members[1].Texts[0].Positions[0].Line != 2 {
		t.Fatal("returned diagnostic compiler bytes/positions changed the original complete observation")
	}
}

func TestX86GoPanicTerminalCompilerSchemaNeedsActual386Producer(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"missing":     nil,
		"version":     {"GOVERSION": "go1.20.14", "GOOS": "linux", "GOARCH": "386", "GO386": "sse2"},
		"target":      {"GOVERSION": "go1.27.2", "GOOS": "linux", "GOARCH": "amd64", "GO386": "sse2"},
		"OS":          {"GOVERSION": "go1.27.2", "GOOS": "freebsd", "GOARCH": "386", "GO386": "sse2"},
		"CPU":         {"GOVERSION": "go1.27.2", "GOOS": "linux", "GOARCH": "386", "GO386": "softfloat"},
		"experiments": {"GOVERSION": "go1.27.2", "GOOS": "linux", "GOARCH": "386", "GO386": "sse2", "GOEXPERIMENT": "regabiwrappers"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := x86GoPanicTerminalCompilerSources(env, func(string) ([]byte, error) { t.Fatal("invalid profile consulted producer bytes"); return nil, nil }); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unobserved target/version/profile acquired an ABI normalization", err)
			}
		})
	}
}
