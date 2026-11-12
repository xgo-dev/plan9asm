package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This is an observation, not a trusted index. Both the producer and the
// independent artifact reader reconstruct the complete normalized environment.
type ciEnvironmentContext struct {
	Directory string            `json:"request_directory"`
	Physical  string            `json:"physical_request_directory"`
	TempRoot  string            `json:"actual_temp_root"`
	Process   map[string]string `json:"process_controls"`
}

var ciProcessControls = []string{
	"PATH", "GOENV", "GOWORK", "GOTOOLCHAIN", "GODEBUG", "GOGC", "GOMEMLIMIT",
	"GOMAXPROCS", "GOTRACEBACK", "GORACE", "LLVM_CONFIG", "CC", "CXX",
	"LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
	"CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
	"LIBRARY_PATH", "COMPILER_PATH", "GCC_EXEC_PREFIX", "SDKROOT",
	"MACOSX_DEPLOYMENT_TARGET", "SOURCE_DATE_EPOCH", "ASAN_OPTIONS", "MSAN_OPTIONS",
	"TSAN_OPTIONS", "UBSAN_OPTIONS", "LC_ALL", "LANG", "TZ", "SELF_BL_SINK",
	"TMPDIR", "TMP", "TEMP",
	"NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA",
}

func captureCIEnvironmentContext(directory string, environment map[string]string) (ciEnvironmentContext, error) {
	observation := ciEnvironmentContext{Directory: directory, Process: map[string]string{}}
	var err error
	observation.Physical, err = sourcepath.Resolve(directory)
	if err != nil {
		return observation, err
	}
	observation.TempRoot = environment["GOTMPDIR"]
	if observation.TempRoot == "" {
		observation.TempRoot = os.TempDir()
	}
	observation.TempRoot = filepath.Clean(observation.TempRoot)
	for _, key := range ciProcessControls {
		observation.Process[key] = os.Getenv(key)
	}
	// Capture all current and future explicit test/runtime controls, including
	// pinned QEMU controls. Do not copy unrelated CI credentials into artifacts.
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PLAN9ASM_") || strings.HasPrefix(key, "QEMU_") {
			observation.Process[key] = value
		}
	}
	return observation, nil
}

func ciAbsolutePath(path string) bool {
	// Windows Go environments can retain forward or mixed separators (for
	// example setup-go's cache roots). Only separator spelling is equivalent;
	// dot segments, repeated separators and relative roots still fail.
	return filepath.IsAbs(path) && filepath.Clean(path) == filepath.FromSlash(path) && !strings.ContainsAny(path, "\x00\r\n")
}

func normalizeCIEnvironment(environment map[string]string, observation ciEnvironmentContext) (map[string]string, error) {
	if len(environment) == 0 || len(environment) > 256 || !ciAbsolutePath(observation.Directory) || !ciAbsolutePath(observation.Physical) || !ciAbsolutePath(observation.TempRoot) {
		return nil, fmt.Errorf("complete bounded actual Go environment and absolute source/temp identities required")
	}
	for _, key := range ciProcessControls {
		if _, present := observation.Process[key]; !present {
			return nil, fmt.Errorf("process control %s observation missing", key)
		}
	}
	if observation.Process["GOENV"] != "off" || observation.Process["GOWORK"] != "off" || observation.Process["GOTOOLCHAIN"] != "local" {
		return nil, fmt.Errorf("actual process must disable user environment, workspace and toolchain switching")
	}
	root, toolDir := environment["GOROOT"], environment["GOTOOLDIR"]
	if !ciAbsolutePath(root) || !ciAbsolutePath(toolDir) || filepath.Dir(toolDir) != filepath.Join(root, "pkg", "tool") {
		return nil, fmt.Errorf("actual SDK/tool directory relationship differs")
	}
	module := environment["GOMOD"]
	if module != filepath.Join(observation.Directory, "go.mod") && module != filepath.Join(observation.Physical, "go.mod") {
		return nil, fmt.Errorf("actual main module must be the guarded request's go.mod")
	}
	if environment["GOTMPDIR"] != "" && filepath.Clean(environment["GOTMPDIR"]) != observation.TempRoot {
		return nil, fmt.Errorf("actual Go temporary root differs")
	}
	if environment["GOCACHEPROG"] != "" || environment["GOPACKAGESDRIVER"] != "" {
		return nil, fmt.Errorf("external cache/package drivers are not source-bound in this CI protocol")
	}
	result := make(map[string]string, len(environment)+len(observation.Process))
	for key, value := range environment {
		validKey := key != ""
		for _, char := range key {
			validKey = validKey && (char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_')
		}
		if !validKey || len(key) > 256 || len(value) > 1<<20 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid actual environment field %q", key)
		}
		result[key] = value // Includes unknown future Go fields, never a whitelist.
	}
	result["GOROOT"], result["GOTOOLDIR"] = "<sdk>", "<sdk>/pkg/tool/"+filepath.Base(toolDir)
	result["GOMOD"] = "<source>/go.mod"
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOBIN", "GOTMPDIR", "GOTELEMETRYDIR"} {
		value, present := environment[key]
		if !present || value == "" {
			continue // Empty and absent remain different, as observed by Go.
		}
		// Multiple GOPATH roots are not registered in this initial CI protocol.
		if !ciAbsolutePath(value) || (key == "GOPATH" && len(filepath.SplitList(value)) != 1) {
			return nil, fmt.Errorf("unregistered infrastructure path %s", key)
		}
		result[key] = "<" + strings.ToLower(key) + ">"
	}
	if _, present := environment["GOGCCFLAGS"]; !present {
		return nil, fmt.Errorf("actual GOGCCFLAGS observation missing")
	}
	flags, err := normalizeCIGCCFlags(environment["GOGCCFLAGS"], observation.TempRoot)
	if err != nil {
		return nil, err
	}
	result["GOGCCFLAGS"] = flags
	for key, value := range observation.Process {
		if len(value) > 1<<20 || strings.ContainsAny(key+value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid process control %q", key)
		}
		if key == "PATH" {
			parts := filepath.SplitList(value)
			for index, path := range parts {
				if filepath.FromSlash(path) == filepath.Join(root, "bin") {
					parts[index] = "<sdk>/bin"
				}
			}
			value = strings.Join(parts, string(os.PathListSeparator))
		}
		if key == "TMPDIR" || key == "TMP" || key == "TEMP" {
			if value != "" {
				if !ciAbsolutePath(strings.TrimSuffix(filepath.FromSlash(value), string(filepath.Separator))) && value != string(filepath.Separator) {
					return nil, fmt.Errorf("invalid process temporary root %s", key)
				}
				value = "<" + strings.ToLower(key) + ">"
			}
		}
		result["process/"+key] = value
	}
	return result, nil
}

// cmd/go envcmd uses quoted.Join(GccCmd(...)[3:]); GccCmd's debug/file
// prefix-map maps the builder's disposable WorkDir to exactly /tmp/go-build.
// Only that direct go-build<decimal> child changes. Everything else, including
// flag ordering and original quote spelling, is retained byte-for-byte.
// The actual SDK's complete source and driver/tool bytes are separately bound.
func normalizeCIGCCFlags(flags, tempRoot string) (string, error) {
	count := 0
	var normalized strings.Builder
	for cursor := 0; cursor < len(flags); {
		start := cursor
		if strings.ContainsRune(" \t", rune(flags[cursor])) {
			normalized.WriteByte(flags[cursor])
			cursor++
			continue
		}
		quote := byte(0)
		if flags[cursor] == '\'' || flags[cursor] == '"' {
			quote = flags[cursor]
			cursor++
		}
		payloadStart := cursor
		for cursor < len(flags) && ((quote != 0 && flags[cursor] != quote) || (quote == 0 && !strings.ContainsRune(" \t", rune(flags[cursor])))) {
			cursor++
		}
		payloadEnd := cursor
		if quote != 0 {
			if cursor == len(flags) {
				return "", fmt.Errorf("unterminated actual GOGCCFLAGS quote")
			}
			cursor++
			if cursor < len(flags) && !strings.ContainsRune(" \t", rune(flags[cursor])) {
				return "", fmt.Errorf("ambiguous actual GOGCCFLAGS quoted token")
			}
		}
		argument := flags[payloadStart:payloadEnd]
		prefix := ""
		for _, candidate := range []string{"-fdebug-prefix-map=", "-ffile-prefix-map="} {
			if strings.HasPrefix(argument, candidate) {
				prefix = candidate
			}
		}
		if prefix == "" {
			normalized.WriteString(flags[start:cursor])
			continue
		}
		count++
		mapped := strings.TrimPrefix(argument, prefix)
		from, to, found := strings.Cut(mapped, "=")
		base := filepath.Base(from)
		digits := strings.TrimPrefix(base, "go-build")
		if count != 1 || !found || to != "/tmp/go-build" || from != filepath.Join(tempRoot, base) || len(digits) < 1 || len(digits) > 10 || digits == base {
			return "", fmt.Errorf("unregistered actual GOGCCFLAGS prefix-map")
		}
		for _, digit := range digits {
			if digit < '0' || digit > '9' {
				return "", fmt.Errorf("actual Go temporary nonce is not decimal")
			}
		}
		// Both selected SDKs derive MkdirTemp's suffix from uint32 and emit
		// canonical base-10 text (os.nextRandom), not arbitrary decimal input.
		nonce, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || strconv.FormatUint(nonce, 10) != digits {
			return "", fmt.Errorf("actual Go temporary nonce is not canonical uint32")
		}
		normalized.WriteString(flags[start:payloadStart])
		normalized.WriteString(prefix + "<tmp>/go-build<decimal>=/tmp/go-build")
		normalized.WriteString(flags[payloadEnd:cursor])
	}
	return normalized.String(), nil
}
