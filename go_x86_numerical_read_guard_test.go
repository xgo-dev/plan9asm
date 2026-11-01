//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGoX86NumericalSBReadCompleteCommandAndReadbackReceipts(t *testing.T) {
	ownerRequest, request := numericalMutableFixture(t, "amd64", "READ(4,AX)\nCMPB DATA+8(SB),$1")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	request.Owners = []*GoNumericalStorageOwner{owner}
	source, err := CaptureGoX86NumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	raw, err := source.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		RawSelection, RawEnvironment []byte
		Commands                     []numericalSBCommand
		Reads                        []numericalSBReadFact
	}
	if err := json.Unmarshal(raw, &report); err != nil || len(report.Commands) != 6 || len(report.Reads) != 2 {
		t.Fatal("incomplete actual command/source/native read receipts", err)
	}
	for index, receipt := range report.Commands {
		if receipt.Directory != request.Directory || receipt.Binary != request.GoBinary || len(receipt.Arguments) == 0 || len(receipt.Stdout) == 0 {
			t.Fatal("actual command role/output was not retained", index)
		}
	}
	for index, expected := range map[int][]byte{0: source.rawEnvironment, 3: source.rawSelection,
		4: source.native.OriginalListing, 5: source.native.ExpandedListing} {
		if !bytes.Equal(report.Commands[index].Stdout, expected) {
			t.Fatal("retained actual whole command stdout changed", index)
		}
	}
	if !bytes.Equal(report.RawSelection, source.rawSelection) || !bytes.Equal(report.RawEnvironment, source.rawEnvironment) {
		t.Fatal("whole actual selection/environment bytes were substituted")
	}
	for _, read := range report.Reads {
		if read.Owner != 0 || read.Variable.NativeName != "example.invalid/numericalfixture.Mutable" {
			t.Fatal("portable owner ordinal/typed identity was not retained")
		}
	}
	retainNumericalRead(t, source, "receipts")
}

func TestGoX86NumericalSBReadInvalidVerificationContextPermanentlyRevokes(t *testing.T) {
	ownerRequest, request := numericalMutableFixture(t, "386", "MOVB DATA+0(SB),AL")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	request.Owners = []*GoNumericalStorageOwner{owner}
	for _, kind := range []string{"nil", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			source, err := CaptureGoX86NumericalReadSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var invalid context.Context
			if kind == "cancelled" {
				cancelled, stop := context.WithCancel(ctx)
				stop()
				invalid = cancelled
			}
			first := source.Verify(invalid)
			invalidCause := ErrProbeNeedsContext
			if kind == "cancelled" {
				invalidCause = context.Canceled
				if errors.Is(first, ErrProbeNeedsContext) {
					t.Fatal("cancelled verification was classified as a source exclusion")
				}
			}
			if !errors.Is(first, invalidCause) || !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("fresh context revived a failed live source verification")
			}
		})
	}
}

func TestGoX86NumericalSBReadSealedOwnerOrderAndJoinMutations(t *testing.T) {
	ownerRequest, readRequest := numericalMutableFixture(t, "amd64", "MOVB DATA+0(SB),AL")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	cpuRequest := ownerRequest
	cpuRequest.Directory = filepath.Join(filepath.Dir(filepath.Dir(cpuRequest.GoBinary)), "src", "internal", "cpu")
	cpuRequest.PackagePath, cpuRequest.SDKCPU = "internal/cpu", true
	cpuRequest.Variables = []GoNumericalStorageReference{{"internal/cpu", "X86"}}
	cpu, err := CaptureGoNumericalStorageOwner(ctx, cpuRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer cpu.Close()
	readRequest.Owners = []*GoNumericalStorageOwner{owner, cpu}
	for _, test := range []struct {
		name   string
		mutate func(*GoX86NumericalReadSource) func()
	}{
		{"owner order", func(s *GoX86NumericalReadSource) func() {
			s.request.Owners[0], s.request.Owners[1] = s.request.Owners[1], s.request.Owners[0]
			return func() { s.request.Owners[0], s.request.Owners[1] = s.request.Owners[1], s.request.Owners[0] }
		}},
		{"read owner rebind", func(s *GoX86NumericalReadSource) func() {
			s.reads[0].owner = cpu
			return func() { s.reads[0].owner = owner }
		}},
		{"read owner ordinal", func(s *GoX86NumericalReadSource) func() {
			s.reads[0].ownerOrdinal++
			return func() { s.reads[0].ownerOrdinal-- }
		}},
		{"source package", func(s *GoX86NumericalReadSource) func() {
			old := s.request.PackagePath
			s.request.PackagePath += "/other"
			return func() { s.request.PackagePath = old }
		}},
		{"target profile", func(s *GoX86NumericalReadSource) func() {
			s.request.Target = "linux/386"
			return func() { s.request.Target = "linux/amd64" }
		}},
		{"actual command environment", func(s *GoX86NumericalReadSource) func() {
			old := s.request.Environment
			s.request.Environment = append(append([]string(nil), old...), "GOOS=darwin")
			return func() { s.request.Environment = old }
		}},
		{"whole selection stdout", func(s *GoX86NumericalReadSource) func() {
			s.rawSelection[0] ^= 1
			return func() { s.rawSelection[0] ^= 1 }
		}},
		{"whole environment stdout", func(s *GoX86NumericalReadSource) func() {
			s.rawEnvironment[0] ^= 1
			return func() { s.rawEnvironment[0] ^= 1 }
		}},
		{"CPP output", func(s *GoX86NumericalReadSource) func() {
			old := s.cpp.Output
			s.cpp.Output += "\n"
			return func() { s.cpp.Output = old }
		}},
		{"whole original native code", func(s *GoX86NumericalReadSource) func() {
			s.native.OriginalText[0].Code[0] ^= 1
			return func() { s.native.OriginalText[0].Code[0] ^= 1 }
		}},
		{"complete relocation Add", func(s *GoX86NumericalReadSource) func() {
			s.reads[0].relocation.Add++
			return func() { s.reads[0].relocation.Add-- }
		}},
		{"source read width", func(s *GoX86NumericalReadSource) func() {
			s.reads[0].width++
			return func() { s.reads[0].width-- }
		}},
		{"command directory receipt", func(s *GoX86NumericalReadSource) func() {
			old := s.commands[0].Directory
			s.commands[0].Directory = filepath.Dir(old)
			return func() { s.commands[0].Directory = old }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			restore := test.mutate(source)
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("mutated source/native/owner join kept its live seal")
			}
			restore()
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restoration resurrected revoked source")
			}
		})
	}
}

func TestGoX86NumericalSBReadOriginalInputAndDirectoryMutations(t *testing.T) {
	for _, kind := range []string{"assembly bytes", "active header bytes", "preferred include miss", "selected Go addition", "physical directory"} {
		t.Run(kind, func(t *testing.T) {
			ownerRequest, readRequest := numericalMutableFixture(t, "386", "MOVB DATA+0(SB),AL")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			readRequest.Owners = []*GoNumericalStorageOwner{owner}
			source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var restore func()
			switch kind {
			case "assembly bytes", "active header bytes":
				name := filepath.Join(readRequest.Directory, readRequest.AssemblyFile)
				if kind == "active header bytes" {
					name = filepath.Join(readRequest.Directory, "local.h")
				}
				old, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, append(append([]byte(nil), old...), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.WriteFile(name, old, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "preferred include miss", "selected Go addition":
				name := filepath.Join(readRequest.Directory, "textflag.h")
				data := []byte("#define NOSPLIT 4\n")
				if kind == "selected Go addition" {
					name = filepath.Join(readRequest.Directory, "added.go")
					data = []byte("package consumer\nvar Added byte\n")
				}
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
			case "physical directory":
				old := readRequest.Directory + ".retained"
				if err := os.Rename(readRequest.Directory, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(readRequest.Directory, 0700); err != nil {
					t.Fatal(err)
				}
				restore = func() {
					if err := os.Remove(readRequest.Directory); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(old, readRequest.Directory); err != nil {
						t.Fatal(err)
					}
				}
			}
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("changed original source role retained the read join")
			}
			restore()
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restored source role resurrected revoked read join")
			}
		})
	}
}

func TestGoX86NumericalSBReadConcurrentCloseAndNilOwners(t *testing.T) {
	ownerRequest, readRequest := numericalMutableFixture(t, "amd64", "MOVB DATA+0(SB),AL")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoNumericalStorageOwner(ctx, ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	readRequest.Owners = []*GoNumericalStorageOwner{nil}
	if source, err := CaptureGoX86NumericalReadSource(ctx, readRequest); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("nil owner did not return exact Context", err)
	}
	readRequest.Owners = []*GoNumericalStorageOwner{owner}
	source, err := CaptureGoX86NumericalReadSource(ctx, readRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = source.Readback(ctx)
		}()
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("closed source remained live")
	}
	var absent *GoX86NumericalReadSource
	if !errors.Is(absent.Verify(ctx), ErrProbeNeedsContext) || absent.Close() != nil {
		t.Fatal("nil source was not safely rejected/closed")
	}
}
