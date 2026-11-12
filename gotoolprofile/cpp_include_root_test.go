package gotoolprofile

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCPPIncludeAbsenceFollowsPhysicalPackageCWD(t *testing.T) {
	base := t.TempDir()
	physical, tool := filepath.Join(base, "real/module"), filepath.Join(base, "tool")
	for name, content := range map[string]string{
		"real/module/pkg/native.s": "#include \"../../src/value.h\"\nTEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$SOURCE_VALUE\nGLOBL ·value(SB),8,$4\n",
		"real/src/value.h":         "#define SOURCE_VALUE 99\n",
		"tool/src/value.h":         "#define SOURCE_VALUE 42\n",
	} {
		file := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	// The capture factory resolves its command directory before invoking Go.
	// Windows' lexical '..' resolution through an unresolved alias is not the
	// same search: keep it as an independent control, not the factory witness.
	canonical, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	observe := func(root, want string) {
		t.Helper()
		for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
			out, stderr, err := instrumentationActualCommand(t, filepath.Join(root, "pkg"),
				instrumentationActualEnv(target, "0"), goBinary, "tool", "asm", "-S",
				"-I", filepath.Join(tool, "pkg/include"), "-o", filepath.Join(t.TempDir(), "go.o"), "native.s")
			if err != nil || len(stderr) != 0 || !strings.Contains(string(out), want) {
				t.Fatalf("actual Go include selection (%s, root %s), want %s: %v\n%s\n%s", target, root, want, err, out, stderr)
			}
		}
	}
	observe(canonical, "63 00 00 00")
	aliasValue := "63 00 00 00"
	if runtime.GOOS == "windows" {
		aliasValue = "2a 00 00 00"
	}
	observe(alias, aliasValue)
	miss := CPPPackageSearchMiss{
		Protocol: CPPPackageSearchMissProtocol, Assembly: "pkg/native.s", Source: "module/pkg/native.s",
		Include: "../../src/value.h", PackageCandidate: "../src/value.h", ToolSource: "src/value.h",
	}
	if err := VerifyCPPPackageSearchMiss(miss, alias, tool); err == nil {
		t.Fatal("lexical symlink parent hid the actual package-CWD preferred source")
	}
	if err := os.Remove(filepath.Join(base, "real/src/value.h")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCPPPackageSearchMiss(miss, alias, tool); err != nil {
		t.Fatalf("physical CWD correctly missing its original candidate: %v", err)
	}
	observe(canonical, "2a 00 00 00")
	observe(alias, "2a 00 00 00")
}
