package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// These literal command-profile controls supply no source, compiler, object or
// terminal authority. The live producer must still authenticate every input.
func sdkOriginalObservedProfile(t *testing.T, role sdkASMDataCaptureRole, arch string) (*GoX86SDKASMDataSource, map[string]string, map[string]string) {
	t.Helper()
	directory := t.TempDir()
	root := filepath.Join(directory, "sdk")
	source := &GoX86SDKASMDataSource{captureRole: role, originalProfile: role != sdkASMDataStrictRole,
		request: GoX86SDKASMDataCaptureRequest{Target: "linux/" + arch, GoBinary: filepath.Join(root, "bin", gotoolchain.HostExecutable("go"))}}
	provided := map[string]string{"GOCACHE": filepath.Join(directory, "build"), "GOMODCACHE": filepath.Join(directory, "mod"),
		"CGO_ENABLED": "0", "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local"}
	source.request.Environment = []string{"GOOS=linux", "GOARCH=" + arch, "GOFLAGS=", "GOEXPERIMENT="}
	for key, value := range provided {
		source.request.Environment = append(source.request.Environment, key+"="+value)
	}
	env := map[string]string{"GOROOT": root, "GOVERSION": "go1.27.2", "GOOS": "linux", "GOARCH": arch,
		"GOAMD64": "v1", "GO386": "sse2", "GOFLAGS": "", "GOEXPERIMENT": "",
		"GOCACHE": provided["GOCACHE"], "GOMODCACHE": provided["GOMODCACHE"], "CGO_ENABLED": "0",
		"GOENV": "", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off"}
	return source, provided, env
}

func sdkCheckOriginalObservedProfile(t *testing.T, source *GoX86SDKASMDataSource, provided, env map[string]string, accept bool) {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), raw...)
	requestBefore := append([]string(nil), source.request.Environment...)
	providedBefore := make(map[string]string, len(provided))
	for key, value := range provided {
		providedBefore[key] = value
	}
	observed, err := source.validateObservedEnvironment(raw, provided)
	if accept && (err != nil || !reflect.DeepEqual(observed, env)) {
		t.Fatal("the actual selected architecture's profile was rejected or rewritten", observed, err)
	}
	if !accept && (!errors.Is(err, ErrProbeNeedsContext) || observed != nil) {
		t.Fatal("another role or changed active profile acquired admission", observed, err)
	}
	if !bytes.Equal(raw, before) || !reflect.DeepEqual(provided, providedBefore) || !reflect.DeepEqual(source.request.Environment, requestBefore) {
		t.Fatal("profile validation rewrote actual command metadata or supplied environment")
	}
}

func TestX86SDKOriginalObservedInactiveCPUField(t *testing.T) {
	for _, role := range []sdkASMDataCaptureRole{sdkASMDataStrictRole, sdkASMDataOriginalFrameRole, sdkASMDataOriginalSourceRole} {
		for _, arch := range []string{"386", "amd64"} {
			for _, inactive := range []string{"", "v1", "v2", "v3", "v4", "future-profile"} {
				t.Run(profileRoleName(role)+"/"+arch+"/GOAMD64="+inactive, func(t *testing.T) {
					source, provided, env := sdkOriginalObservedProfile(t, role, arch)
					env["GOAMD64"] = inactive
					if inactive != "" {
						provided["GOAMD64"] = inactive
						source.request.Environment = append(source.request.Environment, "GOAMD64="+inactive)
					}
					accept := inactive == "v1" || arch == "386" && role == sdkASMDataOriginalSourceRole
					sdkCheckOriginalObservedProfile(t, source, provided, env, accept)
				})
			}
		}
	}
}

func profileRoleName(role sdkASMDataCaptureRole) string {
	switch role {
	case sdkASMDataStrictRole:
		return "strict-DATA-NUM"
	case sdkASMDataOriginalFrameRole:
		return "original-frame"
	default:
		return "original-source"
	}
}

func TestX86SDKOriginalObservedActiveAndCompleteProfileStillRequired(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for key, value := range map[string]string{"GOOS": "windows", "GOARCH": "arm64", "GOROOT": "other-sdk",
			"GOVERSION": "go1.20.14", "GOFLAGS": "-overlay=changed", "GOEXPERIMENT": "changed",
			"GOCACHE": "other-cache", "GOMODCACHE": "other-mod", "CGO_ENABLED": "1",
			"GOENV": "other-config", "GOWORK": "other-work", "GOTOOLCHAIN": "auto"} {
			t.Run(arch+"/"+key, func(t *testing.T) {
				source, provided, env := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, arch)
				if arch == "386" {
					env["GOAMD64"] = ""
				}
				env[key] = value
				sdkCheckOriginalObservedProfile(t, source, provided, env, false)
			})
		}
	}
	for _, active := range []string{"", "softfloat", "sse3", "changed"} {
		t.Run("386/active-GO386="+active, func(t *testing.T) {
			source, provided, env := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, "386")
			env["GO386"] = active
			sdkCheckOriginalObservedProfile(t, source, provided, env, false)
		})
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch+"/missing-observed-GOAMD64", func(t *testing.T) {
			source, provided, env := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, arch)
			delete(env, "GOAMD64")
			sdkCheckOriginalObservedProfile(t, source, provided, env, false)
		})
	}
	for _, inactive := range []string{"", "sse2", "softfloat", "future-profile"} {
		t.Run("amd64/inactive-GO386="+inactive, func(t *testing.T) {
			source, provided, env := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, "amd64")
			env["GO386"] = inactive
			sdkCheckOriginalObservedProfile(t, source, provided, env, true)
		})
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch+"/original-config-and-cgo-default", func(t *testing.T) {
			source, provided, env := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, arch)
			provided["GOENV"] = filepath.Join(t.TempDir(), "selected-config")
			provided["CGO_ENABLED"] = "1"
			env["GOENV"], env["CGO_ENABLED"] = provided["GOENV"], provided["CGO_ENABLED"]
			for index, pair := range source.request.Environment {
				key, _, _ := strings.Cut(pair, "=")
				if value, present := provided[key]; present {
					source.request.Environment[index] = key + "=" + value
				}
			}
			if arch == "386" {
				env["GOAMD64"] = ""
				source.request.Environment = append(source.request.Environment, "GOAMD64=")
			}
			sdkCheckOriginalObservedProfile(t, source, provided, env, true)
		})
	}
	for _, raw := range []string{"null", "[]", "{", `{"GOAMD64":1}`} {
		t.Run("malformed-observation="+raw, func(t *testing.T) {
			source, provided, _ := sdkOriginalObservedProfile(t, sdkASMDataOriginalSourceRole, "386")
			if observed, err := source.validateObservedEnvironment([]byte(raw), provided); !errors.Is(err, ErrProbeNeedsContext) || observed != nil {
				t.Fatal("malformed command metadata acquired profile admission", observed, err)
			}
		})
	}
}
