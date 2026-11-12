//go:build go1.27

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestX86SDKOriginalSource386HasNoFrameOrTerminalAuthority(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "386", "internal/runtime/atomic")
	config := filepath.Join(t.TempDir(), "actual-go-env")
	if err := os.WriteFile(config, []byte("GOPROXY=https://original-source.invalid,direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := sourcepath.Resolve(config)
	if err != nil {
		t.Fatal(err)
	}
	var environment []string
	for _, value := range request.Environment {
		if !strings.HasPrefix(value, "GOENV=") && !strings.HasPrefix(value, "GOPROXY=") {
			environment = append(environment, value)
		}
	}
	request.Environment = append(environment, "GOENV="+config)
	if public, err := CaptureGoX86SDKASMDataSource(ctx, request); public != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("original profile leaked into the unchanged strict public DATA producer", err)
	}
	if frame, err := CaptureGoAMD64SDKFrameObservation(ctx, request); frame != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("386 source-only observation acquired an AMD64 native frame", err)
	}
	source, err := captureGoX86SDKASMDataSourceRole(ctx, request, sdkASMDataOriginalSourceRole)
	if err != nil {
		t.Fatal("complete actual original-profile386 source/header/compiler/ASM observation", err)
	}
	defer source.Close()
	if source.guard.env["GOENV"] != config || source.guard.env["GOPROXY"] != "https://original-source.invalid,direct" ||
		source.captureRole != sdkASMDataOriginalSourceRole || len(source.observation.Frames) != 0 || source.frameListingBytes != 0 ||
		source.guard.ready || source.guard.sdkFrame != nil || len(source.guard.functions) != 0 || source.guard.numericalOrigin != nil {
		t.Fatal("source observation changed the original profile or acquired frame/numerical authority")
	}
	if len(source.observation.Objects.Sources) != 1 || len(source.observation.Objects.Sources[0].GeneratedFuncdata) != 1 ||
		len(source.observation.Objects.Sources[0].GeneratedFuncdata[0].Owners) != 5 || len(source.observation.Objects.Sources[0].ExpandedLayouts) != 0 {
		t.Fatal("the complete generated metadata/source-owner inventory was omitted or became DATA")
	}
	if images, err := gostaticstorage.ReadonlyLiteralDataInitializers(source.observation.Objects); images != nil || !errors.Is(err, gostaticstorage.ErrContext) {
		t.Fatal("actual generated metadata acquired literal/numerical backing", images, err)
	}
	if err := gostaticstorage.GeneratedFuncdataSources(source.guard.env["GOVERSION"], func(role string) ([]byte, error) {
		data, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role)))
		if role == "pkg/include/funcdata.h" && len(data) != 0 {
			data = append([]byte(nil), data...)
			data[0] ^= 1
		}
		return data, err
	}); !errors.Is(err, gostaticstorage.ErrContext) {
		t.Fatal("changed actual metadata producer source retained its registered role", err)
	}
	x86SDKGeneratedMetadataAddressSyntax(t, source)
	pkg, err := source.typedPackage("go1.27")
	if err != nil {
		t.Fatal("same sealed compiler selection did not reconstruct its complete typed source", err)
	}
	bodies, err := x86GoSinglePanicBodies(pkg)
	if err != nil || len(bodies) != 1 || len(pkg.SourceSelection.Assembly) != 1 {
		t.Fatal("actual complete selected Go body/ASM inventory differs", len(bodies), err)
	}
	for _, file := range pkg.SourceSelection.Assembly {
		if len(file.Funcs) != 42 {
			t.Fatal("the untouched actual assembly was cropped", len(file.Funcs))
		}
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("actual complete source/selection/compiler object lost its identity", err)
	}
	source.captureRole = sdkASMDataOriginalFrameRole
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed private role survived the complete observation seal", err)
	}
}

// These fresh assembler observations classify syntax, not metadata authority.
// In particular, rejection of quoted/base64 names is not the reason that the
// independent source/object classifier denies address aliases.
func x86SDKGeneratedMetadataAddressSyntax(t *testing.T, source *GoX86SDKASMDataSource) {
	t.Helper()
	whole := string(source.observation.ObjectInputs.Sources[0].Original)
	if strings.Count(whole, "\nTEXT ") != 42 || !strings.Contains(whole, "\n\tRET") {
		t.Fatal("the alias oracle requires the complete actual 42-TEXT source")
	}
	name := source.observation.Objects.Sources[0].GeneratedFuncdata[0].Definition.Name
	driver, driverHash := x86LEAActualSDKDriver(t)
	if driver != source.request.GoBinary {
		t.Fatal("the syntax oracle changed the selected original SDK")
	}
	for _, row := range []struct {
		name, instruction string
		accepted          bool
	}{
		{"complete-original", "", true},
		{"reserved-address", "MOVL $no_pointers_stackmap(SB),AX", true},
		{"generated-bare", "LEAL " + name + "(SB),AX", false},
		{"generated-quoted", "MOVL $\"" + name + "\"(SB),AX", false},
		{"generated-quoted-offset", "LEAL \"" + name + "\"+4(SB),AX", false},
		{"generated-quoted-slash", "LEAL \"" + name + "/\"(SB),AX", false},
	} {
		t.Run("actual-Go-syntax/"+row.name, func(t *testing.T) {
			if err := source.Verify(source.context); err != nil {
				t.Fatal(err)
			}
			assembly := whole
			if row.instruction != "" {
				assembly = strings.Replace(assembly, "\n\tRET", "\n\t"+row.instruction+"\n\tRET", 1)
			}
			directory := t.TempDir()
			input, object := filepath.Join(directory, "whole.s"), filepath.Join(directory, "whole.o")
			if err := os.WriteFile(input, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			args := append(source.asmArguments(source.guard.owned), "-o", object, input)
			observed, err := goasmcmd.Observe(stage, source.request.Directory, source.request.Environment, driver, args...)
			output := append(append([]byte(nil), observed.Stdout...), observed.Stderr...)
			if failure := goAssemblerOracleOutcome(input, object, output, err, stage.Err(), row.accepted, "386"); failure != nil {
				t.Fatalf("complete actual source syntax classification: %v\n%s", failure, output)
			}
			current, readErr := os.ReadFile(input)
			tool, toolErr := os.ReadFile(driver)
			if readErr != nil || toolErr != nil || !bytes.Equal(current, []byte(assembly)) || sha256.Sum256(tool) != driverHash ||
				!observed.Waited || observed.ExitCode != 0 && observed.ExitCode != 1 {
				t.Fatal("the actual source/tool/owned-command identity changed", readErr, toolErr)
			}
			t.Logf("complete 42-TEXT syntax observation: accepted=%t source=%x driver=%x exit=%d diagnostic=%q",
				row.accepted, sha256.Sum256(current), driverHash, observed.ExitCode, output)
			if row.accepted {
				x86LEAReadObjectReceipt(t, "386", "linux", assembly, input, driver, driverHash, object)
			}
			if err := source.Verify(source.context); err != nil {
				t.Fatal("the syntax observation changed the live source producer", err)
			}
		})
	}
}
