package gotoolprofile

import (
	"os"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// The shared snapshot owns filesystem validation. This adapter retains only
// the existing observation views and this producer's distinct CPP records.
type amd64OriginalObservationFiles struct {
	snapshot      *gooriginalsrc.Snapshot
	hashes, paths map[string]string
	entries       map[string][]string
	directories   map[string]os.FileInfo
	cpp           map[string]amd64OriginalCPPObservation
}

type amd64OriginalCPPObservation struct {
	Expanded string
	Inputs   []string
}

func newAMD64OriginalObservationFiles() *amd64OriginalObservationFiles {
	snapshot := gooriginalsrc.NewSnapshot()
	view := snapshot.View()
	return &amd64OriginalObservationFiles{snapshot: snapshot, hashes: view.Hashes,
		paths: view.Paths, entries: view.Entries, directories: view.Directories,
		cpp: make(map[string]amd64OriginalCPPObservation)}
}

func (files *amd64OriginalObservationFiles) retain(name string) error {
	return files.snapshot.Retain(name)
}

func (files *amd64OriginalObservationFiles) retainTool(name string) error {
	return files.snapshot.RetainTool(name)
}

func (files *amd64OriginalObservationFiles) directory(name string, recursive bool) error {
	return files.snapshot.Directory(name, recursive)
}

func (files *amd64OriginalObservationFiles) verify() error {
	if files == nil {
		return (*gooriginalsrc.Snapshot)(nil).Verify()
	}
	return files.snapshot.Verify()
}
