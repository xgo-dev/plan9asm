package gooriginalsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/golegacymod"
	"golang.org/x/mod/sumdb/dirhash"
)

func originalLegacyMetadataProof(t *testing.T) *golegacymod.ProxyGoModProof {
	t.Helper()
	data, err := os.ReadFile("../../gotoolprofile/testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof golegacymod.ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	return &proof
}

// This fixture exercises only the metadata-role consumer with an independently
// signed public record. It does not claim a complete original ZIP observation,
// compile external source, or create a frame/assembly permission.
func originalLegacyMetadataFixture(t *testing.T) (*OriginSet, DownloadReceipt, *golegacymod.ProxyGoModProof) {
	t.Helper()
	proof := originalLegacyMetadataProof(t)
	root, metadata := t.TempDir(), filepath.Join(t.TempDir(), "module.mod")
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	set := &OriginSet{files: newModuleSnapshot()}
	if err := set.files.Directory(root, true); err != nil {
		t.Fatal(err)
	}
	if err := set.files.Retain(metadata); err != nil {
		t.Fatal(err)
	}
	receipt := DownloadReceipt{Path: proof.Module, Version: proof.Version,
		Dir: root, GoMod: metadata, Sum: proof.ModuleSum, GoModSum: proof.GoModSum}
	return set, receipt, proof
}

func TestOriginalLegacyMetadataSeparateAuthenticatedRole(t *testing.T) {
	set, receipt, proof := originalLegacyMetadataFixture(t)
	before, err := os.ReadFile(receipt.GoMod)
	if err != nil {
		t.Fatal(err)
	}
	data, role, err := set.moduleMetadata(receipt.Path, receipt.Version, receipt, proof)
	if err != nil || role != golegacymod.ProxyGoModProtocol || !bytes.Equal(data, before) {
		t.Fatal("signed legacy metadata lost its separate original role", role, err)
	}
	if _, err := os.Lstat(filepath.Join(receipt.Dir, "go.mod")); !os.IsNotExist(err) {
		t.Fatal("metadata observation invented an original ZIP member", err)
	}
	if err := set.files.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalLegacyMetadataRejectsUnboundOrChangedOrigins(t *testing.T) {
	for _, role := range []string{
		"missing proof", "signature", "inclusion", "path", "version", "zip sum", "metadata sum",
		"metadata bytes", "unretained copy", "original member", "original directory", "added member",
	} {
		t.Run(role, func(t *testing.T) {
			set, receipt, proof := originalLegacyMetadataFixture(t)
			path, version := receipt.Path, receipt.Version
			original := filepath.Join(receipt.Dir, "go.mod")
			switch role {
			case "missing proof":
				proof = nil
			case "signature":
				proof.SignedTree += "changed"
			case "inclusion":
				proof.Inclusion = nil
			case "path":
				path = "example.invalid/changed"
			case "version":
				version = "v1.0.0"
			case "zip sum":
				receipt.Sum = proof.GoModSum
			case "metadata sum":
				receipt.GoModSum = proof.ModuleSum
			case "metadata bytes":
				if err := os.WriteFile(receipt.GoMod, []byte(proof.Contents+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unretained copy":
				receipt.GoMod = filepath.Join(t.TempDir(), "copy.mod")
				if err := os.WriteFile(receipt.GoMod, []byte(proof.Contents), 0600); err != nil {
					t.Fatal(err)
				}
			case "original member", "added member":
				if err := os.WriteFile(original, []byte(proof.Contents), 0600); err != nil {
					t.Fatal(err)
				}
				if role == "original member" {
					if err := set.files.Retain(original); err != nil {
						t.Fatal(err)
					}
				}
			case "original directory":
				if err := os.Mkdir(original, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := set.moduleMetadata(path, version, receipt, proof); err == nil {
				t.Fatal("unclosed legacy metadata acquired an original source role")
			}
		})
	}
}

func TestOriginSetLegacyProofCannotReplaceWholeZIPIdentity(t *testing.T) {
	for _, withProof := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing authentication", true: "different authenticated ZIP"}[withProof], func(t *testing.T) {
			set, receipt, files := originalZIPConsistencyFixture(t)
			delete(files, "go.mod")
			if err := os.Remove(filepath.Join(receipt.Dir, "go.mod")); err != nil {
				t.Fatal(err)
			}
			writeOriginalZIPFixture(t, receipt.Zip, receipt.Path+"@"+receipt.Version, files, "unchanged")
			var err error
			receipt.Sum, err = dirhash.HashZip(receipt.Zip, dirhash.Hash1)
			if err != nil {
				t.Fatal(err)
			}
			var proof *golegacymod.ProxyGoModProof
			if withProof {
				proof = originalLegacyMetadataProof(t)
			}
			_, err = set.ObserveLegacy(context.Background(), receipt.Path, receipt.Version, receipt, proof)
			if err == nil || !strings.Contains(err.Error(), "legacy proxy metadata") {
				t.Fatal("missing/different authentication did not reach the independent metadata guard", err)
			}
			if err := set.Verify(); err == nil {
				t.Fatal("failed legacy origin did not permanently revoke its observation")
			}
		})
	}
}

func TestOriginSetMetadataRetainsActualCanonicalDownloadRole(t *testing.T) {
	set, receipt, _ := originalZIPConsistencyFixture(t)
	alias := filepath.Join(t.TempDir(), "cache-alias")
	if err := os.Symlink(set.cache, alias); err != nil {
		t.Fatal(err)
	}
	for _, name := range []*string{&receipt.Dir, &receipt.Zip, &receipt.GoMod} {
		relative, err := filepath.Rel(set.cache, *name)
		if err != nil {
			t.Fatal(err)
		}
		*name = filepath.Join(alias, relative)
	}
	observed, err := set.Observe(context.Background(), receipt.Path, receipt.Version, receipt)
	if err != nil || observed.GoModOrigin != OriginalZIPGoMod {
		t.Fatal("validated ancestor alias lost its canonical original metadata", err)
	}
	if !strings.HasPrefix(observed.Root, set.cache+string(filepath.Separator)) ||
		!strings.HasPrefix(observed.GoMod, set.cache+string(filepath.Separator)) {
		t.Fatal("original metadata retained an unbound alias instead of its canonical role")
	}
	if err := set.Verify(); err != nil {
		t.Fatal(err)
	}
}
