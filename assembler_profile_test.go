package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestGoAssemblerExplicitEnvironmentFamilies(t *testing.T) {
	for _, tc := range []struct {
		arch, key, value, want string
	}{
		{"386", "GO386", "sse2", "GO386_sse2"},
		{"386", "GO386", "softfloat", "GO386_softfloat"},
		{"amd64", "GOAMD64", "v1", "GOAMD64_v1"},
		{"amd64", "GOAMD64", "v2", "GOAMD64_v2"},
		{"amd64", "GOAMD64", "v3", "GOAMD64_v3"},
		{"amd64", "GOAMD64", "v4", "GOAMD64_v4"},
		{"arm", "GOARM", "5,softfloat", "GOARM_5"},
		{"arm", "GOARM", "6", "GOARM_6,GOARM_5"},
		{"arm", "GOARM", "7,hardfloat", "GOARM_7,GOARM_6,GOARM_5"},
		{"arm64", "GOARM64", "v8.0", ""},
		{"arm64", "GOARM64", "v8.0,crypto", ""},
		{"arm64", "GOARM64", "v8.0,lse,crypto", "GOARM64_LSE"},
		{"arm64", "GOARM64", "v8.1", "GOARM64_LSE"},
		{"arm64", "GOARM64", "v9.5", "GOARM64_LSE"},
		{"wasm", "GOWASM", "", ""},
		{"wasm", "GOWASM", "satconv,signext", ""},
	} {
		t.Run(tc.arch+"/"+tc.value, func(t *testing.T) {
			env := map[string]string{"GOOS": "linux", "GOARCH": tc.arch, "GOVERSION": "go1.27.1", tc.key: tc.value, "GOEXPERIMENT": "fieldtrack"}
			got, err := GoAssemblerDefinesForEnvironment("linux", tc.arch, env)
			want := []string{"GOOS_linux", "GOARCH_" + tc.arch}
			if tc.want != "" {
				want = append(want, strings.Split(tc.want, ",")...)
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("defines = %v, %v; want %v", got, err, want)
			}
		})
	}
}

func TestGoAssemblerExplicitEnvironmentRejectsUnknownOrMissing(t *testing.T) {
	for _, tc := range []struct{ arch, key, value string }{
		{"386", "GO386", ""}, {"386", "GO386", "avx"},
		{"amd64", "GOAMD64", "v5"}, {"arm", "GOARM", "8"},
		{"arm", "GOARM", "6,unknown"}, {"arm64", "GOARM64", "v9.6"},
		{"arm64", "GOARM64", "v8.0,unknown"}, {"wasm", "GOWASM", "avx"},
	} {
		env := map[string]string{"GOOS": "linux", "GOARCH": tc.arch, "GOVERSION": "go1.27.1", tc.key: tc.value}
		if _, err := GoAssemblerDefinesForEnvironment("linux", tc.arch, env); err == nil {
			t.Errorf("accepted invalid %s=%q", tc.key, tc.value)
		}
	}
	for _, env := range []map[string]string{
		{"GOOS": "darwin", "GOARCH": "amd64", "GOAMD64": "v1"},
		{"GOOS": "linux", "GOARCH": "arm64", "GOAMD64": "v1"},
		{"GOOS": "linux", "GOARCH": "amd64"},
	} {
		if _, err := GoAssemblerDefinesForEnvironment("linux", "amd64", env); err == nil {
			t.Errorf("accepted incomplete/conflicting environment %v", env)
		}
	}
}

func TestGoAssemblerExplicitEnvironmentVersionBoundaries(t *testing.T) {
	for _, version := range []string{"go1.20.14", "go1.21.13", "go1.22.12", "go1.27.1"} {
		env := map[string]string{"GOOS": "linux", "GOARCH": "arm", "GOVERSION": version, "GOARM": "6"}
		got, err := GoAssemblerDefinesForEnvironment("linux", "arm", env)
		want := []string{"GOOS_linux", "GOARCH_arm"}
		if version != "go1.20.14" && version != "go1.21.13" {
			want = append(want, "GOARM_6", "GOARM_5")
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s defines=%v, %v; want %v", version, got, err, want)
		}
	}
	for _, version := range []string{"", "go1.19.13", "go1.28.1", "devel go1.27"} {
		env := map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOVERSION": version, "GOAMD64": "v1"}
		if _, err := GoAssemblerDefinesForEnvironment("linux", "amd64", env); err == nil {
			t.Fatalf("accepted missing/unaudited GOVERSION=%q", version)
		}
	}
	for _, tc := range []struct{ version, value string }{{"go1.20.14", ""}, {"go1.22.12", ""}} {
		if _, err := GoAssemblerDefinesForEnvironment("linux", "arm64", map[string]string{"GOOS": "linux", "GOARCH": "arm64", "GOVERSION": tc.version, "GOARM64": tc.value}); err != nil {
			t.Fatal(err)
		}
	}
}
