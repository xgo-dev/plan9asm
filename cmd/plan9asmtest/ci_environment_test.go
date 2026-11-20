//go:build unix

package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func ciEnvironmentFixture() (map[string]string, ciEnvironmentContext) {
	observation := ciEnvironmentContext{Directory: "/source", Physical: "/source", TempRoot: "/temporary", Process: map[string]string{}}
	for _, key := range ciProcessControls {
		observation.Process[key] = ""
	}
	observation.Process["GOENV"], observation.Process["GOWORK"], observation.Process["GOTOOLCHAIN"] = "off", "off", "local"
	observation.Process["PATH"] = "/sdk/bin:/usr/bin"
	environment := map[string]string{
		"GOROOT": "/sdk", "GOTOOLDIR": "/sdk/pkg/tool/linux_amd64", "GOMOD": "/source/go.mod",
		"GOTMPDIR": "/temporary", "GOCACHE": "/cache", "GOMODCACHE": "/modules",
		"GOPATH": "/gopath", "GOBIN": "/gopath/bin", "GOTELEMETRYDIR": "/telemetry",
		"GOGCCFLAGS": "-m64 -pthread -ffile-prefix-map=/temporary/go-build123=/tmp/go-build -fno-common",
		"GOARCH":     "amd64", "GOOS": "linux", "GOTOOLCHAIN": "local", "GOENV": "",
		"GOFLAGS": "", "GOWORK": "off", "GOCACHEPROG": "", "FUTURE_SDK_INPUT": "exact",
	}
	return environment, observation
}

func TestCICompleteEnvironmentPortableRootsAndExactSemantics(t *testing.T) {
	environment, observation := ciEnvironmentFixture()
	wanted, err := normalizeCIEnvironment(environment, observation)
	if err != nil {
		t.Fatal(err)
	}
	if wanted["FUTURE_SDK_INPUT"] != "exact" || wanted["GOCACHEPROG"] != "" {
		t.Fatal("complete actual Go environment was projected")
	}
	portable, context := ciEnvironmentFixture()
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOBIN", "GOTELEMETRYDIR"} {
		portable[key] = filepath.Join("/other", strings.ToLower(key))
	}
	portable["GOROOT"], portable["GOTOOLDIR"], portable["GOMOD"] = "/other/sdk", "/other/sdk/pkg/tool/linux_amd64", "/other/source/go.mod"
	portable["GOTMPDIR"] = "/other/tmp"
	portable["GOGCCFLAGS"] = strings.Replace(portable["GOGCCFLAGS"], "/temporary/go-build123", "/other/tmp/go-build987654", 1)
	context.Directory, context.Physical, context.TempRoot = "/other/source", "/other/source", "/other/tmp"
	context.Process["PATH"] = "/other/sdk/bin:/usr/bin"
	actual, err := normalizeCIEnvironment(portable, context)
	if err != nil || !reflect.DeepEqual(wanted, actual) {
		t.Fatal("same semantics under different SDK/source/cache/temp roots", err, wanted, actual)
	}
	context.Process["TMPDIR"] = "/observed/temp/"
	if _, err := normalizeCIEnvironment(portable, context); err != nil {
		t.Fatal("actual macOS trailing temp separator", err)
	}
	for _, key := range []string{"GOGCCFLAGS", "GOCACHEPROG", "FUTURE_SDK_INPUT", "GOTOOLCHAIN", "GOWORK", "CGO_LDFLAGS"} {
		t.Run("exact/"+key, func(t *testing.T) {
			changed, context := ciEnvironmentFixture()
			changed[key] += " changed"
			actual, err := normalizeCIEnvironment(changed, context)
			if err == nil && reflect.DeepEqual(wanted, actual) {
				t.Fatal("semantic field mutation admitted")
			}
		})
	}
	for _, key := range []string{"FUTURE_SDK_INPUT", "GOCACHEPROG", "GOGCCFLAGS"} {
		changed, context := ciEnvironmentFixture()
		delete(changed, key)
		actual, err := normalizeCIEnvironment(changed, context)
		if err == nil && reflect.DeepEqual(wanted, actual) {
			t.Fatal("paired absence/empty mutation admitted", key)
		}
	}
	for _, key := range []string{"PLAN9ASM_CROSS_EXEC", "QEMU_CPU", "LLVM_CONFIG", "LD_PRELOAD", "PATH", "SELF_BL_SINK", "GOMAXPROCS"} {
		changed, context := ciEnvironmentFixture()
		context.Process[key] += " changed"
		actual, err := normalizeCIEnvironment(changed, context)
		if err == nil && reflect.DeepEqual(wanted, actual) {
			t.Fatal("runtime/routing control mutation admitted", key)
		}
	}
}

func TestCIGCCFlagsOnlyDirectDecimalTemporaryNonce(t *testing.T) {
	for _, prefix := range []string{"-ffile-prefix-map=", "-fdebug-prefix-map="} {
		for _, quote := range []string{"", "'", "\""} {
			flags := "-m64 " + quote + prefix + "/tmp/go-build123=/tmp/go-build" + quote + " -fno-common"
			actual, err := normalizeCIGCCFlags(flags, "/tmp")
			wanted := "-m64 " + quote + prefix + "<tmp>/go-build<decimal>=/tmp/go-build" + quote + " -fno-common"
			if err != nil || actual != wanted {
				t.Fatal(flags, actual, err)
			}
		}
	}
	spaces := "-m64 '-ffile-prefix-map=/owned tmp/go-build123=/tmp/go-build' -pthread"
	if _, err := normalizeCIGCCFlags(spaces, "/owned tmp"); err != nil {
		t.Fatal("actual Go quoted.Join space path", err)
	}
	for _, flags := range []string{
		"-ffile-prefix-map=/other/go-build123=/tmp/go-build",
		"-ffile-prefix-map=/tmp/child/../go-build123=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build123/child=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build123x=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build12345678901=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build4294967296=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build000123=/tmp/go-build",
		"-ffile-prefix-map=/tmp/go-build123=/other",
		"-ffile-prefix-map=/tmp/go-build123=/tmp/go-build=extra",
		"-ffile-prefix-map=/tmp/go-build123=/tmp/go-build -fdebug-prefix-map=/tmp/go-build456=/tmp/go-build",
		"'-ffile-prefix-map=/tmp/go-build123=/tmp/go-build'bad",
		"'-ffile-prefix-map=/tmp/go-build123=/tmp/go-build",
	} {
		if _, err := normalizeCIGCCFlags(flags, "/tmp"); err == nil {
			t.Fatal("foreign/ambiguous nonce normalization admitted", flags)
		}
	}
	unchanged := "-m64  -pthread\t-fno-common"
	if actual, err := normalizeCIGCCFlags(unchanged, "/tmp"); err != nil || actual != unchanged {
		t.Fatal("non-nonce flags or whitespace changed", actual, err)
	}
	for _, nonce := range []string{"0", "4294967295"} {
		if _, err := normalizeCIGCCFlags("-ffile-prefix-map=/tmp/go-build"+nonce+"=/tmp/go-build", "/tmp"); err != nil {
			t.Fatal("actual uint32 nonce boundary", nonce, err)
		}
	}
}

func TestCIEnvironmentContextRejectsMissingAndForeignRoots(t *testing.T) {
	mutations := []func(map[string]string, *ciEnvironmentContext){
		func(e map[string]string, c *ciEnvironmentContext) { e["GOMOD"] = "/other/go.mod" },
		func(e map[string]string, c *ciEnvironmentContext) { e["GOTOOLDIR"] = "/other/pkg/tool/linux_amd64" },
		func(e map[string]string, c *ciEnvironmentContext) { e["GOTMPDIR"] = "/other" },
		func(e map[string]string, c *ciEnvironmentContext) { e["GOPATH"] = "/one:/two" },
		func(e map[string]string, c *ciEnvironmentContext) { e["GOCACHE"] = "relative" },
		func(e map[string]string, c *ciEnvironmentContext) { e["process/PATH"] = "collision" },
		func(e map[string]string, c *ciEnvironmentContext) { delete(c.Process, "PATH") },
		func(e map[string]string, c *ciEnvironmentContext) { c.Process["GOENV"] = "/user/config" },
		func(e map[string]string, c *ciEnvironmentContext) { c.Directory = "/source/.." },
	}
	for index, mutation := range mutations {
		environment, observation := ciEnvironmentFixture()
		mutation(environment, &observation)
		if _, err := normalizeCIEnvironment(environment, observation); err == nil {
			t.Fatal("foreign/incomplete identity admitted", index)
		}
	}
}
