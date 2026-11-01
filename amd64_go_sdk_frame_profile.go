package plan9asm

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const sdkAMD64FrameConfigBytes = 64 << 10

func (source *GoX86SDKASMDataSource) captureSDKFrameConfig(path string) error {
	resolved, err := sourcepath.Resolve(path)
	before, statErr := sourcepath.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || resolved != path || statErr != nil ||
		!before.Mode().IsRegular() || before.Size() > sdkAMD64FrameConfigBytes {
		return sdkASMDataContext("SDK-primary GOENV is not one bounded canonical original config")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return errors.Join(sdkASMDataContext("SDK-primary GOENV role changed while opening"), file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, sdkAMD64FrameConfigBytes+1))
	closeErr := file.Close()
	after, statErr := sourcepath.Lstat(path)
	resolved, resolveErr := sourcepath.Resolve(path)
	if err := errors.Join(readErr, closeErr); err != nil || statErr != nil || resolveErr != nil || resolved != path ||
		len(data) > sdkAMD64FrameConfigBytes || int64(len(data)) != opened.Size() || !after.Mode().IsRegular() ||
		after.Size() != opened.Size() || !os.SameFile(opened, after) {
		return sdkASMDataContext("SDK-primary bounded GOENV changed while reading: %v", err)
	}
	source.guard.inputs[path] = sha256.Sum256(data)
	source.originalConfig, source.originalConfigID = path, before
	return nil
}

// The original SDK-primary role consumes the exact producer environment. It
// never substitutes a config, proxy, cgo default, cache or CPU profile. Complete
// actual SDK selection and compiler-source/export/object joins remain required.
// This profile is private to the distinct SDK frame factory: ordinary owned
// sources, public ASM DATA and numerical producers keep their existing rules.
func sdkAMD64FrameEnvironment(request GoX86SDKASMDataCaptureRequest) (map[string]string, error) {
	if request.Target != "linux/amd64" && request.Target != "darwin/amd64" && request.Target != "windows/amd64" {
		return nil, sdkASMDataContext("SDK-primary frame profile requires an original AMD64 target")
	}
	return sdkX86OriginalSourceEnvironment(request)
}

// Original source observation does not select a native frame/entry role. The
// AMD64 factory above retains its separate exact target check.
func sdkX86OriginalSourceEnvironment(request GoX86SDKASMDataCaptureRequest) (map[string]string, error) {
	if !gostaticstorage.X86SDKTarget(request.Target) {
		return nil, sdkASMDataContext("SDK-primary source profile requires an original x86 target")
	}
	provided := make(map[string]string)
	for _, pair := range request.Environment {
		key, value, valid := strings.Cut(pair, "=")
		if _, duplicate := provided[key]; !valid || key == "" || duplicate || strings.ContainsRune(pair, '\x00') {
			return nil, sdkASMDataContext("SDK-primary malformed or duplicate actual command environment")
		}
		provided[key] = value
	}
	goos, arch, _ := strings.Cut(request.Target, "/")
	for key, value := range map[string]string{"GOOS": goos, "GOARCH": arch, "GOFLAGS": "", "GOTOOLCHAIN": "local", "GOWORK": "off"} {
		if actual, present := provided[key]; !present || actual != value {
			return nil, sdkASMDataContext("SDK-primary unbound actual command profile: %s", key)
		}
	}
	if provided["CGO_ENABLED"] != "0" && provided["CGO_ENABLED"] != "1" {
		return nil, sdkASMDataContext("SDK-primary needs the actual explicit compiler cgo default")
	}
	if provided["GOENV"] != "off" && !filepath.IsAbs(provided["GOENV"]) {
		return nil, sdkASMDataContext("SDK-primary requires the actual resolved GOENV or explicit off")
	}
	if provided["GOEXPERIMENT"] != "" || provided["GOPACKAGESDRIVER"] != "" && provided["GOPACKAGESDRIVER"] != "off" {
		return nil, sdkASMDataContext("SDK-primary custom experiment or package driver needs a separate role")
	}
	return provided, nil
}
