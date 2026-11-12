package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func x86DirectTailOriginalObject(t *testing.T, arch, goos, source string) ([]byte, string) {
	t.Helper()
	root := strings.TrimSpace(string(x86FloatCompareCaptureCommand(t, exec.Command("go", "env", "GOROOT"))))
	dir := t.TempDir()
	input, object := filepath.Join(dir, "whole.s"), filepath.Join(dir, "whole.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "tool", "asm", "-S", "-p", "bitview", "-I", filepath.Join(root, "pkg", "include"), "-o", object, input)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH="+arch)
	listing := string(x86FloatCompareCaptureCommand(t, command))
	data, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	// Fourteen original typed roots and nine private TEXTs: seven bodies plus
	// the original chain and diamond joins. Physical namespace/order remains
	// exactly Go's; the consumer must not manufacture standalone helper ABIs.
	headers := 0
	for _, line := range strings.Split(listing, "\n") {
		if strings.Contains(line, " STEXT ") {
			headers++
			if !strings.Contains(line, " size=") || strings.Contains(line, " size=0 ") {
				t.Fatal("missing complete original Go code", line)
			}
		}
	}
	// Older official listings print the native relocation number; current
	// listings print its name. Bind the numeric spelling to this exact SDK's
	// generated enum assertion, not a current-schema decoder or guessed value.
	enum, err := os.ReadFile(filepath.Join(root, "src", "cmd", "internal", "objabi", "reloctype_string.go"))
	if err != nil {
		t.Fatal(err)
	}
	callType := regexp.MustCompile(`x\[R_CALL-([0-9]+)\]`).FindAllStringSubmatch(string(enum), -1)
	if len(callType) != 1 {
		t.Fatal("selected SDK lacks one exact R_CALL enum assertion")
	}
	relocations := strings.Count(listing, " t=R_CALL ") + strings.Count(listing, " t="+callType[0][1]+" ")
	if len(data) == 0 || headers != 23 || relocations != 17 {
		t.Fatalf("incomplete original object/listing: bytes=%d TEXTs=%d static-tail relocations=%d", len(data), headers, relocations)
	}
	return data, root
}

func TestX86DirectTailWholeSourceOriginalGoAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for the complete direct-tail source class")
	}
	for _, target := range []struct{ arch, goos, triple string }{
		{"amd64", "linux", "x86_64-unknown-linux-gnu"},
		{"amd64", "darwin", "x86_64-apple-darwin"},
		{"amd64", "windows", "x86_64-pc-windows-msvc"},
		{"386", "linux", "i386-unknown-linux-gnu"},
		{"386", "windows", "i686-pc-windows-msvc"},
	} {
		t.Run(target.goos+"/"+target.arch, func(t *testing.T) {
			fixture := x86DirectTailRuntimeSources(target.arch)
			x86DirectTailOriginalObject(t, target.arch, target.goos, fixture.assembly)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, fixture.assembly, fixture.declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						dir := t.TempDir()
						input, output := filepath.Join(dir, "whole.ll"), filepath.Join(dir, "whole.o")
						if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
							t.Fatal(err)
						}
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple,
							"-filetype=obj", input, "-o", output))
						if info, err := os.Stat(output); err != nil || info.Size() == 0 {
							t.Fatalf("missing complete LLVM object: %v", err)
						}
					}
				})
			}
		})
	}
}
