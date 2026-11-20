//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The first-party region fixture is not called "stock". This separate root
// records the real selected SDK assembly and its actual Go-produced archive.
// Go 1.20 does not contain the returning Or32/And32 declarations.
func TestARM64ABI0ByteRegionSelectedSDKOriginalArchive(t *testing.T) {
	dir := t.TempDir()
	listed := arm64ABI0RegionCommand(t, "linux", dir, "list", "-compiled", "-export", "-json",
		"internal/runtime/atomic")
	var selected struct {
		Dir, ImportPath, Export, BuildID string
		CompiledGoFiles, SFiles          []string
	}
	if err := json.Unmarshal(listed, &selected); err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "atomic")
	physicalRoot, err := filepath.EvalSymlinks(wantRoot)
	if err != nil {
		t.Fatal(err)
	}
	actualRoot, err := filepath.EvalSymlinks(selected.Dir)
	if err != nil || actualRoot != physicalRoot || selected.ImportPath != "internal/runtime/atomic" ||
		selected.BuildID == "" || selected.Export == "" {
		t.Fatalf("actual selected SDK package identity changed: %#v: %v", selected, err)
	}
	contains := func(files []string, name string) bool {
		for _, file := range files {
			if filepath.Base(file) == name {
				return true
			}
		}
		return false
	}
	if !contains(selected.SFiles, "atomic_arm64.s") ||
		!contains(selected.CompiledGoFiles, "atomic_arm64.go") {
		t.Fatalf("actual SDK selection does not contain its ARM64 declaration/assembly: %#v", selected)
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil || len(archive) == 0 {
		t.Fatalf("actual SDK archive missing: %v", err)
	}
	originalSHA := sha256.Sum256(archive)
	members := arm64ABI0RegionCommand(t, "linux", dir, "tool", "pack", "t", selected.Export)
	if strings.Count("\n"+string(members), "\natomic_arm64.o\n") != 1 {
		t.Fatalf("actual selected archive must contain exactly one original source object:\n%s", members)
	}
	arm64ABI0RegionCommand(t, "linux", dir, "tool", "pack", "x", selected.Export, "atomic_arm64.o")
	disassembled := arm64ABI0RegionCommand(t, "linux", dir, "tool", "objdump", "-s",
		`internal/runtime/atomic\.(Or32|And32)$`, "atomic_arm64.o")
	for _, name := range []string{"Or32", "And32"} {
		pattern := `(?s)TEXT internal/runtime/atomic\.` + name +
			`\(SB\)[^\n]*atomic_arm64\.s\n(.*?)(?:\n\n|$)`
		body := regexp.MustCompile(pattern).FindSubmatch(disassembled)
		if body == nil {
			t.Fatalf("actual SDK archive has no source-bound %s native entry:\n%s", name, disassembled)
		}
		stores := regexp.MustCompile(`MOVD R[23], 24\(RSP\)`).FindAll(body[1], -1)
		if len(stores) != 2 {
			t.Fatalf("both actual %s paths must retain the complete 8-byte native store: %d\n%s", name, len(stores), body[1])
		}
	}
	for _, name := range []string{"atomic_arm64.go", "atomic_arm64.s"} {
		source, err := os.ReadFile(filepath.Join(actualRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), source, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("actual selected SDK %s bytes=%d SHA256=%x", name, len(source), sha256.Sum256(source))
	}
	for name, data := range map[string][]byte{
		"selection.json": listed, "original.a": archive, "original.objdump": disassembled, "members.txt": members,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(selected.Export)
	if err != nil || sha256.Sum256(after) != originalSHA {
		t.Fatalf("actual archive changed during source/object observation: %v", err)
	}
	arm64ABI0RegionRetain(t, dir, "actual-selected-SDK", "selection.json", "original.a",
		"original.objdump", "members.txt", "atomic_arm64.o", "atomic_arm64.go", "atomic_arm64.s")
	t.Logf("actual SDK=%s archive bytes=%d SHA256=%x; complete source-bound disassembly:\n%s",
		runtime.Version(), len(archive), originalSHA, strings.TrimSpace(string(disassembled)))
	t.Log("selected SDK source/archive identity does not prove all native callers or permit padding clipping")
}
