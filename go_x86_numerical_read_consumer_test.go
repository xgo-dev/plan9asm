//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestGoX86NumericalSBReadBoundConsumer(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg, original, file, options := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
				GoBinary: original.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(original.GoBinary)), "src", "internal", "cpu"),
				PackagePath: "internal/cpu", Target: original.Target, Environment: original.Environment, SDKCPU: true,
				Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
				GoBinary: original.GoBinary, Directory: original.Directory, PackagePath: pkg.Path,
				AssemblyFile: original.AssemblyFile, Target: original.Target, Environment: original.Environment,
				Owners: []*GoNumericalStorageOwner{owner},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer closeNumericalConsumerSource(t, source)
			bound, err := source.BindNumericalReads(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("successful actual source/object/owner precondition failed at binding", err)
			}
			for _, api := range []string{"text", "module", "context"} {
				t.Run(api, func(t *testing.T) {
					var ir string
					var err error
					if api == "text" {
						ir, err = Translate(file, bound)
					} else {
						context := llvm.NewContext()
						var module llvm.Module
						if api == "module" {
							module, err = TranslateModule(file, bound)
						} else {
							module, err = TranslateModuleInContext(context, file, bound)
						}
						if !module.IsNil() {
							ir = module.String()
							module.Dispose()
						}
						context.Dispose()
					}
					if err != nil {
						t.Fatal("live exact numerical read still lacks coherent consumer effects", err)
					}
					if !strings.Contains(ir, "load volatile i8") || !strings.Contains(ir, "external global [") || strings.Contains(ir, "constant [") {
						t.Fatal("mutable numerical read lost exact live-load/global role", ir)
					}
				})
			}
		})
	}
}

func closeNumericalConsumerSource(reporter interface{ Error(...any) }, source *GoX86NumericalReadSource) error {
	err := source.Close()
	if err != nil {
		reporter.Error(err)
	}
	return err
}

type numericalConsumerCleanupRecorder struct {
	errors []error
}

func (recorder *numericalConsumerCleanupRecorder) Error(values ...any) {
	if len(values) != 1 {
		panic("numerical consumer cleanup must report its one original error")
	}
	err, ok := values[0].(error)
	if !ok {
		panic("numerical consumer cleanup must preserve its error object")
	}
	recorder.errors = append(recorder.errors, err)
}

func TestGoX86NumericalConsumerCleanupReportsActualCloseOutcome(t *testing.T) {
	pkg, original, _, _ := numericalSBFixture(t, "amd64")
	// Both directories and every factory artifact belong to this fixture.
	temporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for index, pair := range original.Environment {
		if strings.HasPrefix(pair, "TMPDIR=") {
			original.Environment[index] = "TMPDIR=" + temporary
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: original.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(original.GoBinary)), "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: original.Target, Environment: original.Environment, SDKCPU: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()

	for _, replacement := range []bool{false, true} {
		name := "normal"
		if replacement {
			name = "directory-identity-changed"
		}
		t.Run(name, func(t *testing.T) {
			source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
				GoBinary: original.GoBinary, Directory: original.Directory, PackagePath: pkg.Path,
				AssemblyFile: original.AssemblyFile, Target: original.Target, Environment: original.Environment,
				Owners: []*GoNumericalStorageOwner{owner},
			})
			if err != nil {
				t.Fatal("actual capture precondition", err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if !source.ready || source.guard == nil || source.guard.owned == "" {
				t.Fatal("actual capture did not establish its live artifact owner")
			}

			if replacement {
				owned := source.guard.owned
				identity, err := sourcepath.Lstat(owned)
				if err != nil {
					t.Fatal(err)
				}
				spare := t.TempDir()
				displaced := filepath.Join(spare, "original-owned-directory")
				foreign := filepath.Join(spare, "replacement-directory")
				if err := os.Mkdir(foreign, 0700); err != nil {
					t.Fatal(err)
				}
				foreignIdentity, err := sourcepath.Lstat(foreign)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "fixture-canary"), []byte("replacement fixture owner\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(owned, displaced); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if info, err := os.Lstat(displaced); err != nil || !os.SameFile(identity, info) {
						t.Error("cannot restore the fixture's original owned directory identity", err)
						return
					}
					if info, err := os.Lstat(owned); err == nil {
						if !os.SameFile(foreignIdentity, info) {
							t.Error("refuse to move an unexpected replacement directory")
							return
						}
						if err := os.Rename(owned, foreign); err != nil {
							t.Error("restore replacement directory", err)
							return
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Error("inspect original owned-directory path", err)
						return
					}
					if err := os.Rename(displaced, owned); err != nil {
						t.Error("restore original owned-directory identity", err)
					}
				}()
				if err := os.Rename(foreign, owned); err != nil {
					t.Fatal(err)
				}
			}

			recorder := &numericalConsumerCleanupRecorder{}
			err = closeNumericalConsumerSource(recorder, source)
			if !replacement {
				if err != nil || len(recorder.errors) != 0 {
					t.Fatalf("normal successful Close reported an error: %v, %v", err, recorder.errors)
				}
				if source.ready || source.guard.owned != "" {
					t.Fatal("normal successful Close retained its ready/artifact role")
				}
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("actual changed-directory Close did not reject its owned identity", err)
			}
			if source.ready {
				t.Fatal("failed Close retained the source's ready authority")
			}
			canary, readErr := os.ReadFile(filepath.Join(source.guard.owned, "fixture-canary"))
			if readErr != nil || string(canary) != "replacement fixture owner\n" {
				t.Fatal("failed Close changed the replacement fixture owner's canary", readErr)
			}
			if len(recorder.errors) != 1 || recorder.errors[0] != err {
				t.Fatalf("successful producer cleanup discarded the actual Close error: returned %v, reported %v", err, recorder.errors)
			}
		})
	}
}
