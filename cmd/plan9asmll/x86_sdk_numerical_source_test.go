package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestX86SDKNumericalRetryCannotHidePostGuardErrors(t *testing.T) {
	cause := fmt.Errorf("translate: %w", plan9asm.ErrProbeNeedsContext)
	retry := &x86SDKNumericalRetryError{cause: cause}
	guard := errors.New("original input changed")
	for _, row := range []struct {
		name string
		err  error
		want bool
	}{
		{"marker", retry, true},
		{"nil-guard", errors.Join(retry, nil), true},
		{"wrapped", fmt.Errorf("whole source: %w", retry), true},
		{"changed-source", errors.Join(retry, guard), false},
		{"context-alone", cause, false},
		{"ordinary-failure", guard, false},
		{"success", nil, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, ok := x86SDKNumericalRetryCause(row.err)
			if ok != row.want || ok && got != cause || !ok && got != nil {
				t.Fatalf("retry = (%v, %v), want %v", got, ok, row.want)
			}
		})
	}
}

func TestX86SDKNumericalCleanupOrderAndErrors(t *testing.T) {
	first, second := errors.New("numerical close"), errors.New("SDK close")
	var closed []string
	source := &x86SDKNumericalCLISource{}
	for _, item := range []struct {
		name string
		err  error
	}{
		{"workspace", nil}, {"CPU owner", nil}, {"SDK", second}, {"literal", nil}, {"numerical", first},
	} {
		item := item
		source.cleanup = append(source.cleanup, func() error {
			closed = append(closed, item.name)
			return item.err
		})
	}
	err := source.close()
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("cleanup lost an authoritative error: %v", err)
	}
	want := []string{"numerical", "literal", "SDK", "CPU owner", "workspace"}
	if !reflect.DeepEqual(closed, want) {
		t.Fatalf("close order = %v, want %v", closed, want)
	}
	if source.close() != nil || !reflect.DeepEqual(closed, want) {
		t.Fatal("closed handles were invoked twice")
	}
}

func TestX86SDKNumericalPrivateNamespaceRemainsExact(t *testing.T) {
	source := &x86SDKNumericalCLISource{pkg: &packages.Package{PkgPath: "hash/crc32"}}
	for input, want := range map[string]string{
		"·ieeeCLMUL": "hash/crc32.ieeeCLMUL", "internal∕cpu·X86": "internal/cpu.X86",
		"·r2r1<>": "hash/crc32.r2r1<>", "·r2r1": "hash/crc32.r2r1", "·r2r1$local": "hash/crc32.r2r1$local",
	} {
		if actual := source.resolve(input); actual != want {
			t.Fatalf("resolve(%q) = %q, want %q", input, actual, want)
		}
	}
	if ordinary := resolveSymFunc("hash/crc32")("·r2r1<>"); ordinary != "hash/crc32.r2r1$local" {
		t.Fatal("ordinary local naming changed", ordinary)
	}
}

func TestX86SDKNumericalOwnerQueryIsNotPackageExemption(t *testing.T) {
	for _, row := range []struct {
		name, pkg, target, operand string
		module                     bool
		want                       bool
	}{
		{"amd64", "hash/crc32", "linux/amd64", "internal∕cpu·X86+82(SB)", false, true},
		{"386", "arbitrary/sdk/package", "linux/386", "internal∕cpu·X86+64(SB)", false, true},
		{"darwin-amd64", "hash/crc32", "darwin/amd64", "internal∕cpu·X86+82(SB)", false, true},
		{"windows-amd64", "hash/crc32", "windows/amd64", "internal∕cpu·X86+82(SB)", false, true},
		{"windows-386", "arbitrary/sdk/package", "windows/386", "internal∕cpu·X86+64(SB)", false, true},
		{"self", "internal/cpu", "linux/386", "·X86(SB)", false, true},
		{"substring", "hash/crc32", "linux/amd64", "internal∕cpu·X86Other+82(SB)", false, false},
		{"local", "hash/crc32", "linux/amd64", "internal∕cpu·X86<>+82(SB)", false, false},
		{"external", "hash/crc32", "linux/amd64", "internal∕cpu·X86+82(SB)", true, false},
		{"foreign-target", "hash/crc32", "freebsd/amd64", "internal∕cpu·X86+82(SB)", false, false},
		{"unavailable-darwin-386", "hash/crc32", "darwin/386", "internal∕cpu·X86+64(SB)", false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg := &packages.Package{PkgPath: row.pkg}
			if row.module {
				pkg.Module = &packages.Module{Path: row.pkg}
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·Probe(SB),4,$0-0\nCMPB "+row.operand+",$1\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if actual := x86SDKCPUOwnerRequested(pkg, file, row.target); actual != row.want {
				t.Fatalf("cost query = %v, want %v", actual, row.want)
			}
		})
	}
}
