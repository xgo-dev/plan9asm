package goasmmacros

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCaptureActualSourceRules(t *testing.T) {
	minor, err := GoMinor(runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{"example.invalid/ordinary", "runtime", "reflect"} {
		reads := make(map[string]int)
		read := func(name string) ([]byte, error) {
			reads[name]++
			return os.ReadFile(name)
		}
		proof, err := Capture(runtime.GOROOT(), runtime.Version(), pkg, read)
		if err != nil {
			t.Fatal(err)
		}
		role, files := "ordinary_path", 4
		if minor < 22 {
			role, files = "legacy_no_experiment_macros", 3
		} else if pkg != "example.invalid/ordinary" {
			role = "allow_asm_abi_path"
		}
		if proof.GoVersion != runtime.Version() || proof.PackageRole != role || len(proof.ToolSourceSHA256) != files || len(reads) != files {
			t.Fatal("actual source registration differs from complete ordinary/special role", proof)
		}
		for name, digest := range proof.ToolSourceSHA256 {
			full := filepath.Join(runtime.GOROOT(), filepath.FromSlash(name))
			data, err := os.ReadFile(full)
			if err != nil || reads[full] != 1 || fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
				t.Fatal("registration escaped original input observer", name, err)
			}
		}
		if proof.RegistrationSHA256["asmArgs"] != ArgsFingerprint(minor) || ArgsFingerprint(minor) == "" {
			t.Fatal("complete assembler argument AST is unbound")
		}
		if minor >= 22 && (proof.RegistrationSHA256["package_special_registration"] != SpecialFingerprint(minor) || SpecialFingerprint(minor) == "") {
			t.Fatal("package-special AST is unbound")
		}
	}
}

func TestCaptureRejectsUnknownRegistrationsAndReadFailures(t *testing.T) {
	minor, err := GoMinor(runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct{ file, before, after string }{
		{"VERSION", runtime.Version(), "go1.99.1"},
		{"src/cmd/go/internal/work/gc.go", "\"GOARCH_\"", "\"UNKNOWN_ARCH_\""},
		{"src/cmd/asm/main.go", "package main", "package wrong"},
	}
	if minor >= 22 {
		mutations = append(mutations, struct{ file, before, after string }{
			"src/cmd/asm/main.go", "GOEXPERIMENT_", "UNKNOWN_EXPERIMENT_",
		}, struct{ file, before, after string }{
			"src/cmd/internal/objabi/pkgspecial.go", "\"runtime\",", "\"example.invalid/ordinary\",",
		})
	}
	for _, mutation := range mutations {
		t.Run(mutation.file+"/"+mutation.before, func(t *testing.T) {
			changed := false
			read := func(name string) ([]byte, error) {
				data, err := os.ReadFile(name)
				if err == nil && name == filepath.Join(runtime.GOROOT(), filepath.FromSlash(mutation.file)) {
					text := strings.Replace(string(data), mutation.before, mutation.after, 1)
					changed = text != string(data)
					data = []byte(text)
				}
				return data, err
			}
			if proof, err := Capture(runtime.GOROOT(), runtime.Version(), "example.invalid/ordinary", read); err == nil || proof != nil || !changed {
				t.Fatal("changed actual source acquired registered macros", proof, err, changed)
			}
		})
	}
	for _, file := range []string{"VERSION", "src/cmd/go/internal/work/gc.go", "src/cmd/asm/main.go"} {
		read := func(name string) ([]byte, error) {
			if name == filepath.Join(runtime.GOROOT(), filepath.FromSlash(file)) {
				return nil, errors.New("fixture unreadable input")
			}
			return os.ReadFile(name)
		}
		if proof, err := Capture(runtime.GOROOT(), runtime.Version(), "example.invalid/ordinary", read); err == nil || proof != nil {
			t.Fatal("unreadable actual source supplied macro registration", file)
		}
	}
}

func TestCaptureRejectsUnboundInputs(t *testing.T) {
	for _, version := range []string{"", "1.27", "go1.", "go1.27.x", "go1.27.1.extra", "go1.0.1", "go1.999.0", "go1.19.13", "go1.28.0"} {
		if _, err := Capture(runtime.GOROOT(), version, "example.invalid/ordinary", os.ReadFile); err == nil {
			t.Fatal("unregistered SDK accepted", version)
		}
	}
	for _, pkg := range []string{"", "../ordinary", "/ordinary", "example.invalid/ordinary@v1.0.0", "example.invalid/ordinary\n"} {
		if _, err := Capture(runtime.GOROOT(), runtime.Version(), pkg, os.ReadFile); err == nil {
			t.Fatal("invalid package role accepted", pkg)
		}
	}
	if _, err := Capture("relative", runtime.Version(), "example.invalid/ordinary", os.ReadFile); err == nil {
		t.Fatal("relative SDK source root accepted")
	}
	if _, err := Capture(runtime.GOROOT(), runtime.Version(), "example.invalid/ordinary", nil); err == nil {
		t.Fatal("missing actual source observer accepted")
	}
}
