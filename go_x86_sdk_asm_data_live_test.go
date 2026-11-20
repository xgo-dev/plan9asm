//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This test-only RED asks the existing producer to observe the complete real
// SDK package. Its r2r1 Context is the class boundary the separate observation
// producer must cross, without granting the existing producer read authority.
func TestGoX86SDKASMDataLiveOriginalCRC32Red(t *testing.T) {
	ctx, request, _ := numericalSDKCRC32Request(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if source != nil {
		defer source.Close()
	}
	if source != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "r2r1") {
		t.Fatal("existing read producer lost its independent DATA boundary", err)
	}
	live, err := CaptureGoX86SDKASMDataSource(ctx, GoX86SDKASMDataCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment})
	if err != nil {
		t.Fatal("actual original SDK DATA observation is not closed", err)
	}
	t.Cleanup(func() { live.Close() })
	if len(live.observation.Objects.Sources) != 1 || len(live.observation.Objects.Sources[0].ExpandedLayouts) != 4 {
		t.Fatal("complete real CRC32 private DATA observation is absent")
	}
	sdkASMDataRetain(t, live)
}

func sdkASMDataRequest(t testing.TB, arch, pkg string) (context.Context, GoX86SDKASMDataCaptureRequest) {
	t.Helper()
	_, profile, _, _ := numericalSBFixture(t, arch)
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	return ctx, GoX86SDKASMDataCaptureRequest{GoBinary: profile.GoBinary,
		Directory:   filepath.Join(filepath.Dir(filepath.Dir(profile.GoBinary)), "src", filepath.FromSlash(pkg)),
		PackagePath: pkg, Target: profile.Target, Environment: profile.Environment}
}

func sdkASMDataCapture(t *testing.T) (context.Context, *GoX86SDKASMDataSource) {
	t.Helper()
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("actual finite SDK observation precondition", err)
	}
	t.Cleanup(func() { source.Close() })
	return ctx, source
}

func sdkASMDataRetain(t *testing.T, source *GoX86SDKASMDataSource) {
	t.Helper()
	raw, err := source.Readback(source.context)
	if err != nil {
		t.Fatal(err)
	}
	if folder := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); folder != "" {
		name := strings.ReplaceAll(t.Name(), "/", "-")
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, name+".sdk-data-live.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGoX86SDKASMDataLiveTwoTargets(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, arch, "internal/cpu")
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if source.guard.ready || source.guard.request.NumericalReads != nil ||
				source.observation.Objects.Protocol != gostaticstorage.ASMDataCPPProtocol ||
				len(source.observation.Header.Definitions) == 0 || len(source.observation.CPP) != len(source.guard.selection.SFiles) {
				t.Fatal("live observation omitted complete SDK/header inputs or granted another role")
			}
			for index, observed := range source.observation.Objects.Sources {
				input := source.observation.ObjectInputs.Sources[index]
				if observed.OriginalProgramSHA256 != "" || observed.Layouts != nil ||
					!bytes.Equal(input.Expanded, []byte(source.observation.CPP[index].Output)) || bytes.Equal(input.Original, input.Expanded) {
					t.Fatal("raw bytes were presented as a token-program certificate")
				}
			}
			if _, err := gostaticstorage.ObserveX86SDKASMData(source.observation.ObjectInputs); !errors.Is(err, gostaticstorage.ErrContext) {
				t.Fatal("old offline token-equal API admitted CPP/header input", err)
			}
			for _, name := range []string{"BindNumericalReads", "Bind", "Options", "GoPackage", "Owners"} {
				if _, present := reflect.TypeOf(source).MethodByName(name); present {
					t.Fatal("observation API gained an authority handoff", name)
				}
			}
			sdkASMDataRetain(t, source)
		})
	}
}

func TestGoX86SDKASMDataLiveSealedInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*GoX86SDKASMDataSource)
	}{
		{"target", func(s *GoX86SDKASMDataSource) { s.request.Target = "linux/386" }},
		{"package", func(s *GoX86SDKASMDataSource) { s.request.PackagePath = "hash/crc32" }},
		{"guard target", func(s *GoX86SDKASMDataSource) { s.guard.request.Target = "linux/386" }},
		{"environment", func(s *GoX86SDKASMDataSource) { s.request.Environment = append(s.request.Environment, "GOFLAGS=-N") }},
		{"source selection", func(s *GoX86SDKASMDataSource) { s.guard.selection.GoFiles = s.guard.selection.GoFiles[:1] }},
		{"member ordinal", func(s *GoX86SDKASMDataSource) { s.observation.Objects.Members[2].Ordinal++ }},
		{"object index", func(s *GoX86SDKASMDataSource) {
			members := s.observation.Objects.Members
			members[len(members)-1].Texts[0].Index++
		}},
		{"original ASM", func(s *GoX86SDKASMDataSource) { s.observation.ObjectInputs.Sources[0].Original[0] ^= 1 }},
		{"expanded ASM", func(s *GoX86SDKASMDataSource) {
			inputs := s.observation.ObjectInputs.Sources
			inputs[len(inputs)-1].Expanded[0] ^= 1
		}},
		{"original object", func(s *GoX86SDKASMDataSource) { s.observation.ObjectInputs.Sources[0].OriginalObject[0] ^= 1 }},
		{"expanded object", func(s *GoX86SDKASMDataSource) { s.observation.ObjectInputs.Sources[0].ExpandedObject[0] ^= 1 }},
		{"header", func(s *GoX86SDKASMDataSource) { s.observation.Header.Actual[0] ^= 1 }},
		{"unused definition", func(s *GoX86SDKASMDataSource) { s.observation.Header.Definitions["unused_foreign"] = "17" }},
		{"CPP event", func(s *GoX86SDKASMDataSource) {
			cpp := s.observation.CPP
			cpp[len(cpp)-1].Events[0].Ordinal++
		}},
		{"position physical source", func(s *GoX86SDKASMDataSource) {
			positions := s.observation.Positions
			positions[len(positions)-1].Tokens[0].Position.File += ".foreign"
		}},
		{"position logical filename", func(s *GoX86SDKASMDataSource) {
			positions := s.observation.Positions
			positions[len(positions)-1].Tokens[0].Position.FinalBase.File += ".foreign"
		}},
		{"position raw line", func(s *GoX86SDKASMDataSource) {
			positions := s.observation.Positions
			positions[len(positions)-1].Tokens[0].Position.Line++
		}},
		{"position pragma line", func(s *GoX86SDKASMDataSource) {
			positions := s.observation.Positions
			positions[len(positions)-1].Tokens[0].Position.Base.Line++
		}},
		{"position lineage", func(s *GoX86SDKASMDataSource) {
			positions := s.observation.Positions
			positions[len(positions)-1].Tokens[0].Position.Include++
		}},
		{"mapped bytes", func(s *GoX86SDKASMDataSource) { s.observation.Positions[0].Mapped += "\n" }},
		{"ImportMap", func(s *GoX86SDKASMDataSource) { s.guard.selection.ImportMap = map[string]string{"unsafe": "foreign"} }},
		{"export", func(s *GoX86SDKASMDataSource) { s.guard.selection.Export += ".foreign" }},
		{"archive", func(s *GoX86SDKASMDataSource) { s.observation.ObjectInputs.Archive[0] ^= 1 }},
		{"report", func(s *GoX86SDKASMDataSource) { s.report[0] ^= 1 }},
		{"context identity", func(s *GoX86SDKASMDataSource) { s.context = context.Background() }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, source := sdkASMDataCapture(t)
			test.mutate(source)
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed source/header/CPP/object role verified", err)
			}
			if source.ready || !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("failed observation revived")
			}
		})
	}
}

func TestGoX86SDKASMDataLivePhysicalHeaderTOCTOU(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	file := filepath.Join(source.guard.owned, "go_asm.h")
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(original, []byte("#define unused_foreign 17\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("actual physical header mutation verified", err)
	}
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restored physical input revived revoked source", err)
	}
}

func TestGoX86SDKASMDataLiveCopyCloseAndReadback(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	copy := reflect.New(reflect.TypeOf(source).Elem())
	copy.Elem().Set(reflect.ValueOf(source).Elem())
	copied := copy.Interface().(*GoX86SDKASMDataSource)
	owned := source.guard.owned
	if !errors.Is(copied.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(copied.Close(), ErrProbeNeedsContext) {
		t.Fatal("copied source borrowed live identity or deleted original artifacts")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("copy failure revoked the actual original", err)
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatal("copy disposed original artifacts", err)
	}
	raw, err := source.Readback(ctx)
	if err != nil || source.CheckReadback(ctx, raw) != nil {
		t.Fatal("actual original report cannot be checked", err)
	}
	if source.CheckReadback(ctx, append(raw, ' ')) == nil || source.ready {
		t.Fatal("modified readback verified or failed verification was not permanent")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("original Close did not dispose its own artifact directory", err)
	}
}

func TestGoX86SDKASMDataLiveOriginalCancellation(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
	captured, cancel := context.WithCancel(ctx)
	source, err := CaptureGoX86SDKASMDataSource(captured, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	cancel()
	if err := source.Verify(ctx); !errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("fresh context revived original cancelled capture or lost cause", err)
	}
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("cancelled source revived")
	}
	expired, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stop()
	if source, err := CaptureGoX86SDKASMDataSource(expired, request); source != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired capture launched or lost deadline cause", err)
	}
}

func TestGoX86SDKASMDataLiveOwnedAndTargetRoles(t *testing.T) {
	_, owned, _, _ := numericalSBFixture(t, "amd64")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	request := GoX86SDKASMDataCaptureRequest{GoBinary: owned.GoBinary, Directory: owned.Directory,
		PackagePath: "example.invalid/numericalfixture", Target: owned.Target, Environment: owned.Environment}
	if source, err := CaptureGoX86SDKASMDataSource(ctx, request); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("owned-main source borrowed the explicit SDK role", err)
	}
	for _, target := range []string{"windows/amd64", "darwin/amd64", "linux/arm64", "linux/arm", "js/wasm"} {
		request.Target = target
		if source, err := CaptureGoX86SDKASMDataSource(ctx, request); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unregistered SDK object target admitted", target, err)
		}
	}
}
