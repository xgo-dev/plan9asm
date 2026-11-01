package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type fileInput struct {
	Path, Physical, SHA256, Mode, Modified string
	Size                                   int64
	Identity                               map[string]string
}

type inputIdentity struct {
	Files             []fileInput
	Directories       map[string][]string
	DirectoryIdentity map[string]map[string]string
	Environment       map[string]string
	ASM, ASMVersion   string
}

type inputCommand struct {
	Argv           []string
	Started, Ended time.Time
	Observation    goasmcmd.Observation
	Failure        string
}

type inputRecord struct {
	CaptureComplete bool
	Failure         string
	Identity        inputIdentity
	SelectedSHA256  string
	Commands        []inputCommand
}

type inputTransaction struct {
	snapshot       *gooriginalsrc.Snapshot
	record         inputRecord
	corpus, family []byte
	driver, goroot string
	environment    []string
}

// Access time is not an input generation: the read itself can update it. Keep
// inode, link count, change/write time and physical route where the OS exposes
// them, together with Snapshot's actual SameFile and complete-byte guards.
func generation(info os.FileInfo) map[string]string {
	result := map[string]string{"Mode": info.Mode().String(), "Size": fmt.Sprint(info.Size()),
		"Modified": info.ModTime().UTC().Format(time.RFC3339Nano)}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		for _, name := range []string{"Dev", "Ino", "Nlink", "Ctim", "Ctimespec", "FileAttributes", "CreationTime", "LastWriteTime", "FileSizeHigh", "FileSizeLow"} {
			field := value.FieldByName(name)
			if field.IsValid() && field.CanInterface() {
				result[name] = fmt.Sprint(field.Interface())
			}
		}
	}
	return result
}

func oracleEnvironment(goroot string) []string {
	forced := map[string]string{"GOROOT": goroot, "GOTOOLCHAIN": "local", "GOENV": "off",
		"GOWORK": "off", "GOFLAGS": "", "GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0"}
	var environment []string
	for _, assignment := range os.Environ() {
		key, _, found := strings.Cut(assignment, "=")
		if found {
			if _, replaced := forced[key]; !replaced {
				environment = append(environment, assignment)
			}
		}
	}
	keys := make([]string, 0, len(forced))
	for key := range forced {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+forced[key])
	}
	return environment
}

func (inputs *inputTransaction) command(ctx context.Context, args ...string) ([]byte, error) {
	stage, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	item := inputCommand{Argv: append([]string{inputs.driver}, args...), Started: time.Now()}
	observed, err := goasmcmd.Observe(stage, inputs.goroot, inputs.environment, inputs.driver, args...)
	item.Ended, item.Observation = time.Now(), observed
	if err == nil && (len(observed.Stderr) != 0 || !observed.Waited || observed.ExitCode != 0) {
		err = fmt.Errorf("selected Go query is not a quiet completed success: %s", observed.Stderr)
	}
	if err != nil {
		item.Failure = err.Error()
	}
	inputs.record.Commands = append(inputs.record.Commands, item)
	return observed.Stdout, err
}

func captureInputs(ctx context.Context, opt options) (inputs *inputTransaction, failure error) {
	inputs = &inputTransaction{snapshot: gooriginalsrc.NewSnapshot(), driver: opt.driver, goroot: opt.goroot}
	defer func() {
		if failure != nil {
			inputs.record.Failure = failure.Error()
		}
	}()
	if ctx == nil || ctx.Err() != nil {
		return inputs, fmt.Errorf("input transaction requires live context")
	}
	for _, name := range []string{opt.cases, opt.families, opt.driver, opt.goroot} {
		if !filepath.IsAbs(name) {
			return inputs, fmt.Errorf("original input must be absolute")
		}
		physical, err := sourcepath.Resolve(name)
		if err != nil || physical != name {
			return inputs, fmt.Errorf("original input path must be canonical and accessible: %s", filepath.Base(name))
		}
	}
	if opt.driver != filepath.Join(opt.goroot, "bin", "go") && opt.driver != filepath.Join(opt.goroot, "bin", "go.exe") {
		return inputs, fmt.Errorf("selected driver is not this exact SDK's Go")
	}
	for _, name := range []string{opt.cases, opt.families} {
		if _, ok := goasmoracle.ReadSource(name); !ok {
			return inputs, fmt.Errorf("original corpus/family requires complete eight-MiB physical read")
		}
	}
	inputs.environment = oracleEnvironment(opt.goroot)
	for _, name := range []string{opt.cases, opt.families, filepath.Join(opt.goroot, "VERSION")} {
		if err := inputs.snapshot.Retain(name); err != nil {
			return inputs, err
		}
	}
	if err := inputs.snapshot.RetainTool(opt.driver); err != nil {
		return inputs, err
	}
	for _, name := range []string{opt.goroot, filepath.Dir(opt.driver), filepath.Dir(opt.cases), filepath.Dir(opt.families)} {
		if err := inputs.snapshot.Directory(name, false); err != nil {
			return inputs, err
		}
	}
	include := filepath.Join(opt.goroot, "pkg", "include")
	if err := inputs.snapshot.Directory(include, true); err != nil {
		return inputs, err
	}
	for name, expected := range gostaticstorage.DecoderObjectFormatSourceHashes() {
		path := filepath.Join(opt.goroot, filepath.FromSlash(name))
		if err := inputs.snapshot.Retain(path); err != nil {
			return inputs, err
		}
		if inputs.snapshot.View().Hashes[path] != expected {
			return inputs, fmt.Errorf("selected SDK object schema differs: %s", name)
		}
	}
	for _, name := range []string{"src/cmd/asm/main.go", "src/cmd/asm/internal/flags/flags.go", "src/cmd/internal/obj/objfile.go", "src/cmd/internal/objabi/util.go"} {
		if err := inputs.snapshot.Retain(filepath.Join(opt.goroot, filepath.FromSlash(name))); err != nil {
			return inputs, err
		}
	}
	data, err := inputs.command(ctx, "env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOHOSTOS", "GOHOSTARCH", "GOOS", "GOARCH", "GOARM64", "GOTOOLCHAIN", "GOEXPERIMENT")
	if err != nil {
		return inputs, err
	}
	var environment map[string]string
	if err := json.Unmarshal(data, &environment); err != nil {
		return inputs, err
	}
	if len(environment) != 10 || environment["GOROOT"] != opt.goroot || !gotoolchain.AuditedGo127(environment["GOVERSION"]) ||
		environment["GOOS"] != "linux" || environment["GOARCH"] != "arm64" || environment["GOARM64"] != "v8.0" || environment["GOTOOLCHAIN"] != "local" {
		return inputs, fmt.Errorf("actual selected Go SDK/version/target differs")
	}
	version, err := inputs.snapshot.ReadRetained(filepath.Join(opt.goroot, "VERSION"))
	if err != nil || !strings.HasPrefix(string(version), environment["GOVERSION"]+"\n") {
		return inputs, fmt.Errorf("original SDK VERSION differs")
	}
	asm, err := inputs.command(ctx, "tool", "-n", "asm")
	if err != nil {
		return inputs, err
	}
	asmPath := strings.TrimSpace(string(asm))
	if !filepath.IsAbs(asmPath) || strings.TrimSuffix(string(asm), "\n") != asmPath {
		return inputs, fmt.Errorf("selected lazy ASM route is not exact")
	}
	if err := inputs.snapshot.RetainTool(asmPath); err != nil {
		return inputs, err
	}
	if err := inputs.snapshot.Directory(filepath.Dir(asmPath), false); err != nil {
		return inputs, err
	}
	asmVersion, err := inputs.command(ctx, "tool", "asm", "-V=full")
	if err != nil || string(asmVersion) != "asm version "+environment["GOVERSION"]+"\n" {
		return inputs, fmt.Errorf("actual ASM version differs: %q: %w", asmVersion, err)
	}
	inputs.corpus, err = inputs.snapshot.ReadRetained(opt.cases)
	if err != nil {
		return inputs, err
	}
	inputs.family, err = inputs.snapshot.ReadRetained(opt.families)
	if err != nil {
		return inputs, err
	}
	if _, ok := goasmoracle.ReadSource(opt.cases); !ok {
		return inputs, fmt.Errorf("original corpus exceeds the existing eight-MiB fixture bound")
	}
	if _, ok := goasmoracle.ReadSource(opt.families); !ok {
		return inputs, fmt.Errorf("original family manifest exceeds the existing eight-MiB fixture bound")
	}
	if err := inputs.snapshot.Verify(); err != nil {
		return inputs, err
	}
	view := inputs.snapshot.View()
	identity := inputIdentity{Environment: environment, ASM: asmPath, ASMVersion: string(asmVersion),
		Directories: make(map[string][]string), DirectoryIdentity: make(map[string]map[string]string)}
	names := make([]string, 0, len(view.Hashes))
	for name := range view.Hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		info, err := os.Lstat(name)
		if err != nil {
			return inputs, err
		}
		identity.Files = append(identity.Files, fileInput{Path: name, Physical: view.Paths[name], SHA256: view.Hashes[name],
			Size: info.Size(), Mode: info.Mode().String(), Modified: info.ModTime().UTC().Format(time.RFC3339Nano), Identity: generation(info)})
	}
	for name, entries := range view.Entries {
		identity.Directories[name] = append([]string(nil), entries...)
		identity.DirectoryIdentity[name] = generation(view.Directories[name])
	}
	inputs.record.Identity = identity
	inputs.record.CaptureComplete = true
	return inputs, nil
}
