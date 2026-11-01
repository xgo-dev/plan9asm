package plan9asm

import (
	"crypto/sha256"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This distinct SDK-primary role retains every direct member, including all
// inactive candidates and child-directory identities. Child contents belong
// to separate packages/generators, not the selected compiler package. Any
// selected dependency retains its independent complete original source/export
// graph; selected relative CPP headers retain their own bounded input route.
// Root membership and child identities are rechecked before/after commands. The ordinary owned
// flat inventory keeps its 256-member bound. The SDK retains its 16 MiB byte
// budget and uses the shared original-source membership bound.
func (source *GoX86SDKASMDataSource) snapshotSDKPrimaryDirectory() error {
	return captureSDKPackageDirectoryInputs(source.guard, source.retainDirectory)
}

// SDK assembly, numerical reads and literal alignment share only this input
// inventory. It grants neither child-package source/include authority nor any
// frame, native entry or initialized-storage role. Each caller authenticates
// its own complete SDK selection and retains/rechecks every child identity.
func captureSDKPackageDirectoryInputs(guard *GoAMD64FrameSource, retainDirectory func(string) error) error {
	resolved, err := sourcepath.Resolve(guard.request.Directory)
	if err != nil || resolved != guard.request.Directory {
		return sdkASMDataContext("SDK-primary package directory is not canonical")
	}
	inventory := gooriginalsrc.NewSnapshot()
	if err := inventory.Directory(resolved, false); err != nil {
		return sdkASMDataContext("SDK-primary complete package inventory: %v", err)
	}
	// Snapshot.Directory closes the complete EOF and applies the existing
	// shared file/directory count budgets. Use its observed cardinality, not
	// a newly guessed per-package cap, for the same direct member list.
	entries, info, err := gooriginalsrc.ReadDirectory(resolved, len(inventory.View().Entries[resolved]))
	if err != nil || len(entries) == 0 {
		return sdkASMDataContext("SDK-primary complete package inventory changed: %v", err)
	}
	guard.directoryInfo = info
	remaining := int64(16 << 20)
	for _, entry := range entries {
		guard.entries = append(guard.entries, entry.Name())
		path := filepath.Join(resolved, entry.Name())
		if entry.IsDir() {
			if err := retainDirectory(path); err != nil {
				return err
			}
			continue
		}
		data, err := goAMD64FrameReadBound(path, remaining)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if previous, present := guard.inputs[path]; present && previous != digest {
			return sdkASMDataContext("SDK-primary original inventory changed while capturing")
		}
		remaining -= int64(len(data))
		guard.inputs[path] = digest
	}
	if err := inventory.Verify(); err != nil {
		return sdkASMDataContext("SDK-primary input membership changed during capture: %v", err)
	}
	guard.directoryInventory = inventory
	return nil
}

// The frame owner copies mutable input maps/slices, while retaining the same
// immutable directory observation through its existing live SDK source owner.
// Directory metadata does not supply frame, numerical or native-entry facts.
func (source *GoAMD64FrameSource) copySDKPrimaryInputInventory(original *GoAMD64FrameSource) {
	source.inputs = cloneSDKASMDataInputs(original.inputs)
	source.entries = append([]string(nil), original.entries...)
	source.directoryInfo = original.directoryInfo
	source.directoryInventory = original.directoryInventory
}
