//go:build go1.27

package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoNumericalStorageOriginalSDKMutableGlobals(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, profile, _, _ := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleProofContext(t)
			defer cancel()
			request := GoNumericalStorageCaptureRequest{
				GoBinary: profile.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(profile.GoBinary)), "src", "internal", "runtime", "maps"),
				PackagePath: "internal/runtime/maps", Target: profile.Target, Environment: profile.Environment,
				Variables: []GoNumericalStorageReference{{PackagePath: "internal/runtime/maps", Name: "aeskeysched"}},
			}
			for _, cpu := range []bool{false, true} {
				request.SDKCPU = cpu
				owner, err := CaptureGoNumericalStorageOwner(ctx, request)
				if owner != nil {
					owner.Close()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("maps data borrowed ordinary/CPU producer authority", cpu, err)
				}
			}
			request.SDKCPU, request.SDKGlobals = false, true
			owner, err := CaptureGoNumericalStorageOwner(ctx, request)
			if err != nil {
				t.Fatal("independent SDK Go-defined mutable storage producer absent", err)
			}
			defer owner.Close()
			report, err := owner.observation.Readback(ctx)
			if err != nil || len(report.Variables) != 1 {
				t.Fatal("actual source/object/type readback", err)
			}
			variable := report.Variables[0]
			extent := int64(128)
			if arch == "386" {
				extent = 64
			}
			if variable.NativeName != "internal/runtime/maps.aeskeysched" || variable.GoType != fmt.Sprintf("[%d]byte", extent) || variable.Size != extent ||
				variable.Kind != 10 || !numericalOwnerContains(variable, 0, extent) || numericalOwnerContains(variable, extent-16, 17) ||
				variable.DefinitionMember != "_go_.o" ||
				report.Protocol == gostaticstorage.SDKCPUProtocol {
				t.Fatal("mutable object original identity/layout/extent differs", variable)
			}
		})
	}
}

func TestGoNumericalStorageSDKGlobalGeneralTypedClass(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			_, profile, _, _ := numericalSBFixture(t, "amd64")
			ctx, cancel := runtimeOracleProofContext(t)
			defer cancel()
			request := GoNumericalStorageCaptureRequest{GoBinary: profile.GoBinary,
				Directory:   filepath.Join(filepath.Dir(filepath.Dir(profile.GoBinary)), "src", "math", "bits"),
				PackagePath: "math/bits", Target: target, Environment: profile.Environment, SDKGlobals: true,
				Variables: []GoNumericalStorageReference{{PackagePath: "math/bits", Name: "deBruijn32tab"}},
			}
			owner, err := CaptureGoNumericalStorageOwner(ctx, request)
			if err != nil {
				t.Fatal("independent numerical-array DATA family", err)
			}
			defer owner.Close()
			report, err := owner.observation.Readback(ctx)
			if err != nil || len(report.Variables) != 1 {
				t.Fatal(err)
			}
			variable := report.Variables[0]
			if variable.Size != 32 || variable.Kind != 5 || variable.GoType != "[32]byte" ||
				variable.NativeName != "math/bits.deBruijn32tab" || variable.DefinitionMember != "_go_.o" ||
				!numericalOwnerContains(variable, 0, 32) {
				t.Fatal("complete numerical DATA/source/object role differs", variable)
			}
		})
	}
}

func TestGoNumericalStorageSDKGlobalExactProfileAndGuards(t *testing.T) {
	_, profile, _, _ := numericalSBFixture(t, "amd64")
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	for index, pair := range profile.Environment {
		if strings.HasPrefix(pair, "CGO_ENABLED=") {
			profile.Environment[index] = "CGO_ENABLED=1"
		}
	}
	request := GoNumericalStorageCaptureRequest{GoBinary: profile.GoBinary,
		Directory:   filepath.Join(filepath.Dir(filepath.Dir(profile.GoBinary)), "src", "internal", "runtime", "maps"),
		PackagePath: "internal/runtime/maps", Target: profile.Target, Environment: profile.Environment, SDKGlobals: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/runtime/maps", Name: "hashkey"}},
	}
	owner, err := CaptureGoNumericalStorageOwner(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	report, err := owner.observation.Readback(ctx)
	if err != nil || report.Environment["CGO_ENABLED"] != "1" || report.CommandEnvironment["CGO_ENABLED"] != "1" ||
		report.Variables[0].GoType != "[4]uintptr" || !numericalOwnerContains(report.Variables[0], 0, 32) {
		t.Fatal("SDK producer replaced actual cgo/uintptr numerical profile", err)
	}
	for name, mutation := range map[string]func(*gostaticstorage.Report){
		"extent":          func(report *gostaticstorage.Report) { report.Variables[0].Size++ },
		"object index":    func(report *gostaticstorage.Report) { report.Variables[0].DefinitionIndex++ },
		"member identity": func(report *gostaticstorage.Report) { report.Variables[0].DefinitionMember = "memhash_amd64.o" },
		"CPU role":        func(report *gostaticstorage.Report) { report.Protocol = gostaticstorage.SDKCPUProtocol },
		"dependency source": func(report *gostaticstorage.Report) {
			for name := range report.Source {
				if strings.HasPrefix(name, "_sdk/") {
					delete(report.Source, name)
					delete(report.SourceSHA256, name)
					return
				}
			}
		},
		"missing export": func(report *gostaticstorage.Report) {
			delete(report.Archives, "internal/abi")
			delete(report.ArchiveSHA256, "internal/abi")
		},
		"cgo profile": func(report *gostaticstorage.Report) { report.Environment["CGO_ENABLED"] = "0" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var changed gostaticstorage.Report
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutation(&changed)
			if !errors.Is(gostaticstorage.ValidateReport(changed), gostaticstorage.ErrContext) ||
				!errors.Is(owner.observation.CheckReport(ctx, changed), gostaticstorage.ErrContext) {
				t.Fatal("edited original SDK report acquired live storage authority")
			}
		})
	}
	request.Variables = []GoNumericalStorageReference{{PackagePath: "internal/runtime/maps", Name: "zeroVal"}}
	bad, err := CaptureGoNumericalStorageOwner(ctx, request)
	if bad != nil {
		bad.Close()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("aliased SDK storage acquired ordinary global identity", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := owner.Verify(canceled); !errors.Is(err, context.Canceled) {
		// The public storage wrapper preserves its caller cancellation cause.
		t.Fatal("cancellation lost its original infrastructure cause", err)
	}
	if err := owner.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restored caller context revived a failed SDK owner")
	}
}
