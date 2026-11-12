package golegacymod

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/mod/module"
)

func TestCachedProxyGoModKeepsAuthenticationAndContext(t *testing.T) {
	data, err := os.ReadFile("../../gotoolprofile/testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	escaped, err := module.EscapePath(proof.Module)
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(cache, "cache", "download", escaped, "@v", proof.Version+".mod")
	if err := os.MkdirAll(filepath.Dir(metadata), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	capture := func(ctx context.Context, prior *ProxyGoModProof) (*ProxyGoModProof, string, error) {
		return CaptureCachedProxyGoMod(ctx, cache, "off", proof.Module, proof.Version,
			proof.ModuleSum, proof.GoModSum, metadata, prior)
	}
	actual, name, err := capture(context.Background(), &proof)
	physical, physicalErr := filepath.EvalSymlinks(metadata)
	if err != nil || physicalErr != nil || name != physical || !reflect.DeepEqual(actual, &proof) {
		t.Fatal("complete public authentication was not retained", err, physicalErr)
	}
	actual.Inclusion[0] = "changed"
	if reflect.DeepEqual(actual, &proof) {
		t.Fatal("returned proof shares its caller's mutable audit path")
	}
	if _, _, err := capture(context.Background(), actual); err == nil {
		t.Fatal("changed inclusion bypassed independent authentication")
	}
	if _, _, err := capture(nil, &proof); err == nil {
		t.Fatal("nil context accepted cached metadata")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := capture(canceled, &proof); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled capture borrowed a prior signature", err)
	}
	if err := os.WriteFile(metadata, []byte(proof.Contents+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := capture(context.Background(), &proof); err == nil {
		t.Fatal("cached signature hid changed actual metadata")
	}
}
