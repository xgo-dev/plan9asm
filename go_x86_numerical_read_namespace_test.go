package plan9asm

import "testing"

func TestNumericalRawSelectionPreservesActualPackageQuery(t *testing.T) {
	logical := []byte(`{"ImportPath":"hash/crc32","Match":["hash/crc32"]}`)
	directory := []byte(`{"ImportPath":"hash/crc32","Match":["."]}`)
	if numericalSameRawSelection(logical, directory) {
		t.Fatal("different original command selectors were discarded from the raw selection")
	}
	if !numericalSameRawSelection(logical, logical) || !numericalSameRawSelection(directory, directory) {
		t.Fatal("unchanged original package selectors were rejected")
	}
}

func TestNumericalSourcePackageQueryKeepsSourceRolesDistinct(t *testing.T) {
	for _, entry := range []struct {
		role numericalSBSourceRole
		path string
		want string
	}{
		{numericalSBOwnedSource, "example.invalid/owned", "."},
		{numericalSBSDKSource, "hash/crc32", "hash/crc32"},
		{numericalSBSDKSource, "vendor/golang.org/x/crypto/chacha20poly1305", "vendor/golang.org/x/crypto/chacha20poly1305"},
	} {
		source := &GoX86NumericalReadSource{role: entry.role, request: GoX86NumericalReadCaptureRequest{PackagePath: entry.path}}
		if actual := source.packageQuery(); actual != entry.want {
			t.Errorf("role=%d path=%q: query=%q, want %q", entry.role, entry.path, actual, entry.want)
		}
	}
}
