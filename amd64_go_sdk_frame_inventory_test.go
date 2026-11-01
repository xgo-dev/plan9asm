package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSDKAMD64PrimaryInventorySeparatesChildSourceRoles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "generator"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, bytes := range map[string][]byte{"source.go": []byte("package fixture\n"), "ignored.s": []byte("// inactive candidate\n"),
		"generator/source.go": []byte("package separate\n")} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := sourcepath.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	request := GoAMD64FrameCaptureRequest{Directory: root}
	ordinary := newGoOriginalInputGuard(request)
	if err := ordinary.snapshotDirectory(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("SDK package inventory weakened the ordinary flat role", err)
	}
	source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(request), directories: make(map[string]os.FileInfo)}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source.guard.entries, []string{"generator", "ignored.s", "source.go"}) || len(source.guard.inputs) != 2 ||
		source.directories[filepath.Join(root, "generator")] == nil {
		t.Fatal("complete direct/inactive input or separate child identity was omitted")
	}
	if err := os.Rename(filepath.Join(root, "generator"), filepath.Join(root, "original-generator")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "generator"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "generator", "source.go"), []byte("package separate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.verifyDirectories(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("replacement child directory acquired original selected-package identity", err)
	}
}

func TestSDKAMD64PrimaryInventoryRootMembershipGuard(t *testing.T) {
	root, owned := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := sourcepath.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	owned, err = sourcepath.Resolve(owned)
	if err != nil {
		t.Fatal(err)
	}
	source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: root}), directories: make(map[string]os.FileInfo)}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		t.Fatal(err)
	}
	source.guard.owned, source.guard.ownedInfo = owned, nil
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.guard.verifyInputs(); err != nil {
		t.Fatal("unchanged complete primary membership", err)
	}
	if err := os.WriteFile(filepath.Join(root, "new-inactive.s"), []byte("// new inactive input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.guard.verifyInputs(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("new unselected root member escaped the complete input guard", err)
	}
}

func TestSDKAMD64PrimaryInventoryByteBoundary(t *testing.T) {
	for _, size := range []int{16 << 20, 16<<20 + 1} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "source.go"), []byte(strings.Repeat(" ", size)), 0600); err != nil {
			t.Fatal(err)
		}
		root, err := sourcepath.Resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: root}), directories: make(map[string]os.FileInfo)}
		err = source.snapshotSDKPrimaryDirectory()
		if size == 16<<20 {
			if err != nil || len(source.guard.inputs) != 1 {
				t.Fatal("exact original primary byte bound was rejected", err)
			}
		} else if !errors.Is(err, ErrProbeNeedsContext) || len(source.guard.inputs) != 0 {
			t.Fatal("oversized primary source entered the unchanged byte inventory", err)
		}
	}
}

func TestSDKAMD64PrimaryInventoryMemberBoundary(t *testing.T) {
	for _, count := range []int{256, 257, 300, 792} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root := t.TempDir()
			for index := 0; index < count; index++ {
				name, data := fmt.Sprintf("%03d.go", index), []byte("package fixture\n")
				if index == 0 {
					name, data = "kernel_amd64.s", []byte("TEXT ·F(SB),4,$0-0\nRET\n")
				} else if index == 1 {
					data = []byte("package fixture\nfunc F()\n")
				}
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := sourcepath.Resolve(root)
			if err != nil {
				t.Fatal(err)
			}
			request := GoAMD64FrameCaptureRequest{Directory: root, AssemblyFile: "kernel_amd64.s"}
			ordinary := newGoOriginalInputGuard(request)
			err = ordinary.snapshotDirectory()
			if count == 256 {
				if err != nil {
					t.Fatal("ordinary flat boundary rejected", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) || len(ordinary.inputs) != 0 {
				t.Fatal("SDK observation widened the ordinary flat input role", err)
			}
			source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(request), directories: make(map[string]os.FileInfo)}
			if err := source.snapshotSDKPrimaryDirectory(); err != nil || len(source.guard.inputs) != count {
				t.Fatal("complete SDK input inventory was rejected or truncated", err, len(source.guard.inputs), count)
			}
			owned, err := sourcepath.Resolve(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			source.guard.owned = owned
			source.guard.ownedInfo, err = sourcepath.Lstat(owned)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.guard.verifyInputs(); err != nil {
				t.Fatal("unchanged complete SDK inventory failed verification", err)
			}
			if err := os.WriteFile(filepath.Join(root, "new-inactive.s"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := source.guard.verifyInputs(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("larger directory became a silently accepted bounded prefix", err)
			}
		})
	}
}

func TestSDKAMD64PrimaryInventoryRejectsRedirectedChildren(t *testing.T) {
	for _, directory := range []bool{false, true} {
		root, outside := t.TempDir(), t.TempDir()
		target := outside
		if !directory {
			target = filepath.Join(outside, "source.go")
			if err := os.WriteFile(target, []byte("package foreign\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, filepath.Join(root, "redirected")); err != nil {
			t.Fatal("actual redirected child control", err)
		}
		root, err := sourcepath.Resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: root}), directories: make(map[string]os.FileInfo)}
		if err := source.snapshotSDKPrimaryDirectory(); !errors.Is(err, ErrProbeNeedsContext) || len(source.guard.inputs) != 0 || len(source.directories) != 0 {
			t.Fatal("redirected file/directory acquired a selected SDK-primary input role", err)
		}
	}
}

func TestSDKAMD64PrimaryInventoryDoesNotAuthorizeChildInclude(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "generator"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.s"), []byte("#include \"generator/body.h\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "generator", "body.h"), []byte("TEXT ·F(SB),4,$0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := sourcepath.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	source := &GoX86SDKASMDataSource{request: GoX86SDKASMDataCaptureRequest{Directory: root},
		guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: root}), directories: make(map[string]os.FileInfo)}
	source.guard.env = map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1"}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.captureAssembly(context.Background(), 0, "source.s"); !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "relative/foreign include") {
		t.Fatal("observed child identity became compiler/include source authority", err)
	}
}

// This tests the same private input transfer used by the SDK frame factory.
// It supplies no ready frame or ABI permission and runs no compiler subprocess.
func TestSDKAMD64PrimaryInventoryCloneRetainsCompleteMembership(t *testing.T) {
	for _, change := range []string{"none", "add", "remove", "bytes", "replace root", "close owner", "copy inputs", "copy entries", "drop inventory"} {
		t.Run(change, func(t *testing.T) {
			root, err := sourcepath.Resolve(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 300; index++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%03d.go", index)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			request := GoAMD64FrameCaptureRequest{Directory: root}
			source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(request), directories: make(map[string]os.FileInfo)}
			if err := source.snapshotSDKPrimaryDirectory(); err != nil {
				t.Fatal(err)
			}
			cloned := newGoOriginalInputGuard(request)
			cloned.copySDKPrimaryInputInventory(source.guard)
			owned, err := sourcepath.Resolve(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, guard := range []*GoAMD64FrameSource{source.guard, cloned} {
				guard.owned = owned
				guard.ownedInfo, err = sourcepath.Lstat(owned)
				if err != nil {
					t.Fatal(err)
				}
				if err := guard.verifyInputs(); err != nil {
					t.Fatal("complete original or copied SDK inputs rejected", err)
				}
			}
			switch change {
			case "add":
				err = os.WriteFile(filepath.Join(root, "added.s"), nil, 0600)
			case "remove":
				err = os.Remove(filepath.Join(root, "299.go"))
			case "bytes":
				err = os.WriteFile(filepath.Join(root, "299.go"), []byte("// changed\n"), 0600)
			case "close owner":
				err = source.guard.Close()
			case "copy inputs":
				cloned.inputs[filepath.Join(root, "299.go")] = [32]byte{}
			case "copy entries":
				cloned.entries[0] = "foreign.go"
			case "drop inventory":
				cloned.directoryInventory = nil
			case "replace root":
				original := root + "-original"
				err = os.Rename(root, original)
				if err == nil {
					t.Cleanup(func() {
						if err := os.RemoveAll(original); err != nil {
							t.Error(err)
						}
					})
					err = os.Mkdir(root, 0700)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, guard := range []*GoAMD64FrameSource{source.guard, cloned} {
				err := guard.verifyInputs()
				copyOnly := change == "copy inputs" || change == "copy entries" || change == "drop inventory"
				changed := change != "none" && (!copyOnly || guard == cloned)
				if !changed && err != nil || changed && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original/copy complete-input invalidation differs", change, err)
				}
			}
		})
	}
}
