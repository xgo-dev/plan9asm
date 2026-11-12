//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func numericalSDKCRC32Request(t *testing.T) (context.Context, GoX86NumericalReadCaptureRequest, *GoNumericalStorageOwner) {
	t.Helper()
	_, profile, _, _ := numericalSBFixture(t, "amd64")
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	root := filepath.Dir(filepath.Dir(profile.GoBinary))
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: profile.GoBinary, Directory: filepath.Join(root, "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: profile.Target, Environment: profile.Environment,
		SDKCPU: true, Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal("actual SDK CPU owner precondition", err)
	}
	t.Cleanup(owner.Close)
	request := GoX86NumericalReadCaptureRequest{
		GoBinary: profile.GoBinary, Directory: filepath.Join(root, "src", "hash", "crc32"),
		PackagePath: "hash/crc32", AssemblyFile: "crc32_amd64.s", Target: profile.Target,
		Environment: profile.Environment, Owners: []*GoNumericalStorageOwner{owner},
	}
	data, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil || !strings.Contains(string(data), "CMPB internal∕cpu·X86+const_offsetX86HasAVX512VPCLMULQDQL(SB), $1") {
		t.Fatal("actual unchanged SDK crc32 counterexample is absent", err)
	}
	actual, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary,
		"list", "-json", "-compiled", "-export", "-mod=readonly", ".")
	if err != nil {
		t.Fatal("stock Go failed the original complete CRC32 package", err)
	}
	var selected goAMD64FrameSelection
	if err := json.Unmarshal(actual, &selected); err != nil || !selected.Standard || selected.Module != nil ||
		selected.ImportPath != request.PackagePath || selected.Dir != request.Directory || selected.Export == "" {
		t.Fatal("actual SDK selection differs from the exact package", err)
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil || len(archive) == 0 {
		t.Fatal("actual selected SDK compiler archive is absent", err)
	}
	if artifacts := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifacts != "" {
		folder := filepath.Join(artifacts, "sdk-crc32-original")
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		for name, bytes := range map[string][]byte{"source.s": data, "selection.json": actual, "original.a": archive} {
			if err := os.WriteFile(filepath.Join(folder, name), bytes, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return ctx, request, owner
}

func numericalSDKCPURequest(t *testing.T, arch string) (context.Context, GoX86NumericalReadCaptureRequest, *GoNumericalStorageOwner) {
	t.Helper()
	_, profile, _, _ := numericalSBFixture(t, arch)
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	root := filepath.Dir(filepath.Dir(profile.GoBinary))
	directory := filepath.Join(root, "src", "internal", "cpu")
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: profile.GoBinary, Directory: directory, PackagePath: "internal/cpu",
		Target: profile.Target, Environment: profile.Environment, SDKCPU: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal("actual independent SDK CPU owner precondition", err)
	}
	t.Cleanup(owner.Close)
	return ctx, GoX86NumericalReadCaptureRequest{GoBinary: profile.GoBinary, Directory: directory,
		PackagePath: "internal/cpu", AssemblyFile: "cpu_x86.s", Target: profile.Target,
		Environment: profile.Environment, Owners: []*GoNumericalStorageOwner{owner}}, owner
}

func TestGoX86SDKNumericalReadOriginalArchiveFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, request, owner := numericalSDKCPURequest(t, arch)
			report, err := owner.observation.Readback(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var selected gostaticstorage.Package
			decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
			for {
				var candidate gostaticstorage.Package
				if err := decoder.Decode(&candidate); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if candidate.ImportPath == request.PackagePath {
					if selected.ImportPath != "" {
						t.Fatal("duplicate selected SDK CPU package")
					}
					selected = candidate
				}
			}
			if selected.ImportPath != request.PackagePath || len(selected.SFiles) == 0 {
				t.Fatal("complete actual SDK CPU source selection is absent")
			}
			archive := report.Archives[request.PackagePath]
			observed, err := gostaticstorage.ObserveX86SDKAssemblyArchive(archive, report.TextBuiltinSource,
				request.Target, selected.SFiles)
			if err != nil || !reflect.DeepEqual(observed, report.TextArchives[request.PackagePath]) {
				t.Fatal("explicit SDK observation differs from complete original SDK owner metadata", err)
			}
			if _, err := gostaticstorage.ObserveX86AssemblyArchive(archive, report.TextBuiltinSource,
				request.Target, selected.SFiles); !errors.Is(err, gostaticstorage.ErrContext) {
				t.Fatal("owned observer admitted SDK Std flags", err)
			}
			for _, member := range observed[1:] {
				body := archive[member.Offset : member.Offset+member.Size]
				header := bytes.Index(body, []byte("\x00go120ld"))
				if header < 0 || header+20 > len(body) || binary.LittleEndian.Uint32(body[header+16:]) != member.Flags {
					t.Fatal("actual SDK object flags have no complete member-bound header")
				}
				for _, flags := range []uint32{member.Flags ^ 16, member.Flags ^ 4, member.Flags | 1, member.Flags | 8} {
					changed := append([]byte(nil), archive...)
					binary.LittleEndian.PutUint32(changed[int(member.Offset)+header+16:], flags)
					if _, err := gostaticstorage.ObserveX86SDKAssemblyArchive(changed, report.TextBuiltinSource,
						request.Target, selected.SFiles); !errors.Is(err, gostaticstorage.ErrContext) {
						t.Fatal("SDK decoder accepted changed Std/assembly/shared/unlinkable object flags", flags, err)
					}
				}
			}
		})
	}
}

func TestGoX86SDKNumericalReadOriginalInputObservationNoAuthority(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, request, _ := numericalSDKCPURequest(t, arch)
			source, err := captureGoX86NumericalReadSource(ctx, request, numericalSBSDKSource, true)
			if err != nil {
				t.Fatal("complete actual SDK input observation is absent", err)
			}
			t.Cleanup(func() { source.Close() })
			if source.ready || source.file != nil || len(source.reads) != 0 || source.sdk == nil {
				t.Fatal("SDK input-only observation created numerical permission")
			}
			if err := source.verifySDKObservation(ctx); err != nil {
				t.Fatal("actual independent SDK observation does not verify", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadCompleteOriginalSelectedSource(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	source, err := captureGoX86NumericalReadSource(ctx, request, numericalSBSDKSource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, files := range [][]string{source.guard.selection.GoFiles, source.guard.selection.SFiles, source.guard.selection.HFiles} {
		for _, name := range files {
			file := filepath.Join(request.Directory, name)
			if _, present := source.sdk.Inputs[file]; !present {
				t.Errorf("SDK source role omitted complete selected original bytes: %s", name)
			}
		}
	}
}

func TestGoX86SDKNumericalReadOriginalCaptureContextCannotRevive(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	captured, cancel := context.WithCancel(ctx)
	source, err := captureGoX86NumericalReadSource(captured, request, numericalSBSDKSource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	cancel()
	if err := source.verifySDKObservation(ctx); !errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("fresh context revived the original cancelled SDK capture", err)
	}
	if err := source.verifySDKObservation(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("failed SDK source lease did not remain revoked", err)
	}
}

func TestGoX86SDKNumericalReadOriginalCommandRequestSealed(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	for _, field := range []string{"target", "assembly"} {
		t.Run(field, func(t *testing.T) {
			source, err := captureGoX86NumericalReadSource(ctx, request, numericalSBSDKSource, true)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			original := source.guard.request
			if field == "target" {
				source.guard.request.Target = "linux/386"
			} else {
				source.guard.request.AssemblyFile = "foreign.s"
			}
			err = source.verifySDKObservation(ctx)
			source.guard.request = original
			if !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(source.verifySDKObservation(ctx), ErrProbeNeedsContext) {
				t.Fatal("mutated/restored actual SDK command request revived the source role", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadDefaultOwnedRemainsContext(t *testing.T) {
	ctx, request, owner := numericalSDKCRC32Request(t)
	source, err := CaptureGoX86NumericalReadSource(ctx, request)
	if source != nil {
		source.Close()
	}
	if source != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "owned source role") {
		t.Fatal("default owned factory borrowed SDK source identity", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("refusing SDK source revoked the independent data owner", err)
	}
}

func TestGoX86SDKNumericalReadOriginalCRC32KeepsUnadmittedArchiveContext(t *testing.T) {
	ctx, request, owner := numericalSDKCRC32Request(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if source != nil {
		source.Close()
	}
	if source != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "assembly DATA definition needs an independent role: r2r1") {
		t.Fatal("explicit SDK source authentication lost its exact unadmitted private DATA boundary", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("unadmitted archive Context revoked the independent SDK CPU data owner", err)
	}
	t.Logf("ACTUAL_SDK_CRC32_FIRST_BLOCK %v", err)
}

func TestGoX86SDKNumericalReadCompleteCPPAssemblerWithoutNumericalReadRemainsContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, request, owner := numericalSDKCPURequest(t, arch)
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
			if source != nil {
				source.Close()
			}
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "no certified numerical SB reads") {
				t.Fatal("complete actual SDK CPP/native program acquired an uncertified read", err)
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("unrelated SDK source Context revoked the CPU numerical owner", err)
			}
		})
	}
}
