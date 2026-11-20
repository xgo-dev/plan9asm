package gooriginalsrc

import (
	"fmt"
	"testing"
)

func TestSnapshotActualSDKGraphAndDriverExtent(t *testing.T) {
	// Measured ordinary Go 1.27.1 darwin/amd64 crypto graph, observed by
	// the Linux driver: complete sources/exports plus the original driver.
	// This is a byte-budget fixture, not a claim of external-library success.
	const sourceBytes = int64(54155434)
	const driverBytes = int64(17142188)
	root := originalToolFixtureRoot(t)
	snapshot := NewSnapshot()
	left := sourceBytes
	for index := 0; left > 0; index++ {
		extent := int64(16 << 20)
		if left < extent {
			extent = left
		}
		path := makeOriginalToolExtent(t, root, fmt.Sprintf("source-%d", index), extent)
		if err := snapshot.Retain(path); err != nil {
			t.Fatal(err)
		}
		left -= extent
	}
	driver := makeOriginalToolExtent(t, root, "go", driverBytes)
	if err := snapshot.RetainTool(driver); err != nil {
		t.Fatalf("ordinary measured SDK/driver graph was refused: %v", err)
	}
	if snapshot.bytes != sourceBytes+driverBytes {
		t.Fatal("graph silently omitted original physical bytes", snapshot.bytes)
	}
	if err := snapshot.Verify(); err != nil {
		t.Fatal(err)
	}
}
