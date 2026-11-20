//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Access time may change when reading. All other physical metadata, including
// link count, ownership and change time, belongs to this isolation observation.
func moduleFixtureStableMetadata(info os.FileInfo) map[string]any {
	result := map[string]any{
		"mode": info.Mode(), "size": info.Size(), "mtime": info.ModTime(),
	}
	value := reflect.ValueOf(info.Sys()).Elem()
	for index := 0; index < value.NumField(); index++ {
		field := value.Type().Field(index)
		if field.PkgPath != "" {
			continue
		}
		switch field.Name {
		case "Atim", "Atimespec", "Atime", "Atimensec":
			continue
		}
		result[field.Name] = value.Field(index).Interface()
	}
	return result
}

type moduleFixtureToolObservation struct {
	Physical string
	Metadata map[string]any
	SHA256   string
}

// This is a fixture-only file extent bound, not a source or proof-role budget.
const moduleFixtureToolMaxBytes int64 = 512 << 20

func observeModuleFixtureTool(name string) (moduleFixtureToolObservation, error) {
	var result moduleFixtureToolObservation
	physical, err := filepath.EvalSymlinks(name)
	if err != nil {
		return result, err
	}
	before, err := os.Stat(name)
	if err != nil {
		return result, err
	}
	if !before.Mode().IsRegular() || before.Size() > moduleFixtureToolMaxBytes {
		return result, fmt.Errorf("fixture tool exceeds its regular bounded role")
	}
	file, err := os.Open(name)
	if err != nil {
		return result, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		return result, fmt.Errorf("fixture tool changed while opening: %v / %v", statErr, file.Close())
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(file, before.Size()+1))
	end, endErr := file.Stat()
	closeErr := file.Close()
	after, afterErr := os.Stat(name)
	resolved, resolveErr := filepath.EvalSymlinks(name)
	if readErr != nil || endErr != nil || closeErr != nil || afterErr != nil || resolveErr != nil {
		return result, fmt.Errorf("fixture tool full read failed: %v / %v / %v / %v / %v",
			readErr, endErr, closeErr, afterErr, resolveErr)
	}
	metadata := moduleFixtureStableMetadata(before)
	if n != before.Size() || resolved != physical || !os.SameFile(before, end) || !os.SameFile(before, after) ||
		!reflect.DeepEqual(metadata, moduleFixtureStableMetadata(end)) ||
		!reflect.DeepEqual(metadata, moduleFixtureStableMetadata(after)) {
		return result, fmt.Errorf("fixture tool identity, extent or metadata changed during complete read")
	}
	return moduleFixtureToolObservation{Physical: physical, Metadata: metadata,
		SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

func TestModuleRelocatedProducerDoesNotMutateHostTools(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	configBinary := moduleFixtureLLVMConfig(t)
	cfg := config{Go: goBinary, Timeout: 2 * time.Minute}
	data, err := moduleDependencyCommand(context.Background(), cfg,
		filepath.Join(t.TempDir(), "actual-host-libraries"), configBinary, "--libfiles", "--link-shared")
	if err != nil {
		t.Fatal(err)
	}
	libraries, err := moduleSharedLibraries(data)
	if err != nil {
		t.Fatal(err)
	}
	names := append([]string{configBinary}, libraries...)
	before := make([]moduleFixtureToolObservation, len(names))
	for index, name := range names {
		before[index], err = observeModuleFixtureTool(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Run the actual fixture and all its cleanups. An invented copying stub
	// would not exercise the selected library inode or the real loader route.
	if !t.Run("actual-producer", TestModuleActualDependencyArtifactsSurviveProducerOriginRemoval) {
		t.Fatal("actual relocated producer fixture failed")
	}
	for index, name := range names {
		after, err := observeModuleFixtureTool(name)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before[index], after) {
			t.Errorf("actual host tool bytes or metadata changed across producer setup/cleanup: %s\nbefore=%+v\nafter=%+v",
				name, before[index], after)
		}
	}
}
