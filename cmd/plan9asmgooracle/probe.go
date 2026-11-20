package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func probe(ctx context.Context, dir string, inputs *inputTransaction, index int, row string) result {
	item := result{Index: index, CorpusRow: row, Status: "failed", ExitCode: -1}
	asm, ok := instruction(row)
	item.Instruction = asm
	fail := func(err error) result { item.Failure = err.Error(); return item }
	if !ok {
		return fail(fmt.Errorf("invalid selected original row"))
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fail(err)
	}
	physical, err := sourcepath.Resolve(dir)
	if err != nil || physical != dir {
		return fail(fmt.Errorf("owned case directory was redirected"))
	}
	directory, err := os.Lstat(dir)
	if err != nil || !directory.IsDir() {
		return fail(fmt.Errorf("owned case directory is missing: %v", err))
	}
	item.directory = directory
	item.Source, item.Object = filepath.Join(dir, "probe.s"), filepath.Join(dir, "probe.o")
	source := []byte(fmt.Sprintf("#include \"textflag.h\"\nTEXT ·probe%d(SB),NOSPLIT,$0-0\n\t%s\n\tRET\n", index, asm))
	if err := writeNew(item.Source, source); err != nil {
		return fail(err)
	}
	guard := gooriginalsrc.NewSnapshot()
	item.guard = guard
	if err := guard.Retain(item.Source); err != nil {
		return fail(err)
	}
	before, err := os.Lstat(item.Source)
	if err != nil {
		return fail(err)
	}
	initial, valid := goasmoracle.ReadSource(item.Source)
	if !valid || !bytes.Equal(initial, source) {
		return fail(fmt.Errorf("created exact fixture changed"))
	}
	if _, err := os.Lstat(item.Object); !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("current case object already exists or is inaccessible: %v", err))
	}
	item.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(source))
	item.Argv = []string{inputs.driver, "tool", "asm", "-I", filepath.Join(inputs.goroot, "pkg", "include"), "-o", item.Object, item.Source}
	stage, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	item.Started = time.Now()
	observed, commandErr := goasmcmd.Observe(stage, dir, inputs.environment, inputs.driver, item.Argv[1:]...)
	item.Ended = time.Now()
	item.PID, item.PGID, item.Waited, item.ExitCode = observed.PID, observed.PGID, observed.Waited, observed.ExitCode
	item.Attempted = observed.PID > 0
	item.Stdout, item.Stderr = string(observed.Stdout), string(observed.Stderr)
	item.TimedOut = errors.Is(stage.Err(), context.DeadlineExceeded)
	item.Complete = item.Attempted && item.Waited && stage.Err() == nil
	if commandErr != nil {
		// A joined cleanup/pipe failure never becomes a completed source exit.
		if _, direct := commandErr.(*exec.ExitError); !direct {
			item.Complete = false
		}
	}
	endedSource, valid := goasmoracle.ReadSource(item.Source)
	after, sourceErr := os.Lstat(item.Source)
	endedDirectory, directoryErr := os.Lstat(dir)
	endedPhysical, physicalErr := sourcepath.Resolve(dir)
	if !valid || sourceErr != nil || guard.Verify() != nil || !os.SameFile(before, after) ||
		!reflect.DeepEqual(generation(before), generation(after)) || !bytes.Equal(endedSource, source) ||
		directoryErr != nil || !os.SameFile(directory, endedDirectory) || physicalErr != nil || endedPhysical != dir {
		return fail(fmt.Errorf("actual case source/directory changed"))
	}
	entries, _, err := gooriginalsrc.ReadDirectory(dir, 2)
	if err != nil {
		return fail(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() != "probe.s" && entry.Name() != "probe.o" {
			return fail(fmt.Errorf("foreign/nonregular case member: %s", entry.Name()))
		}
	}
	if err := goasmoracle.CheckOutcome(item.Source, item.Object, observed.Stdout, observed.Stderr,
		commandErr, stage.Err(), commandErr == nil, 3, nil); err != nil {
		return fail(err)
	}
	if commandErr == nil {
		// No -S was requested. Success output cannot silently become a listing.
		if len(observed.Stdout) != 0 || len(observed.Stderr) != 0 {
			return fail(fmt.Errorf("unexpected successful Go assembler diagnostics"))
		}
		object, ok := goasmoracle.ReadSource(item.Object)
		if !ok {
			return fail(fmt.Errorf("complete fresh object observation failed"))
		}
		if err := gostaticstorage.ObserveDecoderARM64Object(object, fmt.Sprintf("<unlinkable>.probe%d", index)); err != nil {
			return fail(fmt.Errorf("actual Go object kind/target/version/probe differs: %w", err))
		}
		if err := guard.Retain(item.Object); err != nil {
			return fail(err)
		}
		retained, err := guard.ReadRetained(item.Object)
		if err != nil || !bytes.Equal(retained, object) || guard.Verify() != nil {
			return fail(fmt.Errorf("actual new object changed during structural observation: %v", err))
		}
		objectInfo, err := os.Lstat(item.Object)
		if err != nil {
			return fail(err)
		}
		item.ObjectKind, item.ObjectTarget, item.ObjectVersion = "GoAssemblyUnlinkable", "linux/arm64", inputs.record.Identity.Environment["GOVERSION"]
		if err := gostaticstorage.ValidateObjectVersion(object, item.ObjectTarget, item.ObjectVersion); err != nil {
			return fail(err)
		}
		item.ObjectPhysical = guard.View().Paths[item.Object]
		item.ObjectIdentity = generation(objectInfo)
		item.ObjectSHA256 = fmt.Sprintf("%x", sha256.Sum256(object))
		item.Status = "accepted"
	} else {
		item.Status = "rejected"
	}
	return item
}
