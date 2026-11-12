package gotoolprofile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Captured from the public lookup and authenticated tiles, without compiling
// or running that module. The fixture proves metadata, not source execution.
func fixtureProxyGoMod(t *testing.T) *ProxyGoModProof {
	t.Helper()
	data, err := os.ReadFile("testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	return &proof
}

type forbiddenProxyTiles struct{ calls int }

func (*forbiddenProxyTiles) Height() int                     { return 8 }
func (*forbiddenProxyTiles) SaveTiles([]tlog.Tile, [][]byte) {}
func (tiles *forbiddenProxyTiles) ReadTiles([]tlog.Tile) ([][]byte, error) {
	tiles.calls++
	return nil, fmt.Errorf("untrusted record must not trigger tile reads")
}

func TestProxyGoModCaptureRejectsUnauthenticatedRecordBeforeTiles(t *testing.T) {
	proof := fixtureProxyGoMod(t)
	lookup, err := tlog.FormatRecord(proof.RecordID, []byte(proof.Record))
	if err != nil {
		t.Fatal(err)
	}
	lookup = append(lookup, []byte(proof.SignedTree)...)
	for _, test := range []struct {
		name   string
		zipSum string
		modSum string
		body   string
	}{
		{name: "missing download GoModSum", zipSum: proof.ModuleSum, body: proof.Contents},
		{name: "different download ZIP", zipSum: proof.GoModSum, modSum: proof.GoModSum, body: proof.Contents},
		{name: "changed actual metadata", zipSum: proof.ModuleSum, modSum: proof.GoModSum, body: proof.Contents + "// changed\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tiles := new(forbiddenProxyTiles)
			if _, err := CaptureProxyGoMod(proof.Module, proof.Version, test.zipSum, test.modSum, []byte(test.body), lookup, tiles); err == nil {
				t.Fatal("download metadata bypassed its independent signed identity")
			}
			if tiles.calls != 0 {
				t.Fatal("invalid identity was fetched before validation")
			}
		})
	}
}

func TestProxyGoModAuthenticatesExactPublicRecordAndMetadata(t *testing.T) {
	if err := ValidateProxyGoMod(fixtureProxyGoMod(t)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProxyGoModProof)
	}{
		{"module", func(p *ProxyGoModProof) { p.Module += "/different" }},
		{"version", func(p *ProxyGoModProof) { p.Version = "v1.0.0" }},
		{"zip identity", func(p *ProxyGoModProof) { p.ModuleSum = p.GoModSum }},
		{"metadata identity", func(p *ProxyGoModProof) { p.GoModSum = p.ModuleSum }},
		{"metadata bytes", func(p *ProxyGoModProof) { p.Contents += "// changed\n" }},
		{"file sha", func(p *ProxyGoModProof) { p.SHA256 = strings.Repeat("0", 64) }},
		{"record id", func(p *ProxyGoModProof) { p.RecordID++ }},
		{"unsigned tree", func(p *ProxyGoModProof) { p.SignedTree = strings.Split(p.SignedTree, "\n\n")[0] + "\n" }},
		{"signed extent", func(p *ProxyGoModProof) { p.SignedTree = strings.Replace(p.SignedTree, "63096671", "63096672", 1) }},
		{"missing inclusion", func(p *ProxyGoModProof) { p.Inclusion = nil }},
		{"changed inclusion", func(p *ProxyGoModProof) { p.Inclusion[0] = p.Inclusion[1] }},
		{"foreign record", func(p *ProxyGoModProof) { p.Record = strings.Replace(p.Record, p.Module, "example.invalid/fake", -1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := fixtureProxyGoMod(t)
			test.mutate(proof)
			if err := ValidateProxyGoMod(proof); err == nil {
				t.Fatal("unauthenticated legacy metadata was accepted")
			}
		})
	}
}
