// Package golegacymod authenticates Go's separately synthesized legacy module
// metadata. It grants no ZIP membership, package, frame or assembly capability.
package golegacymod

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const ProxyGoModProtocol = "sumdb_authenticated_legacy_proxy_go_mod_v1"

// This is Go's public sum.golang.org verifier, not a caller-supplied trust key.
// A signed tree alone is insufficient: the exact record needs its audit path.
const publicSumDBKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

// ProxyGoModProof authenticates metadata outside the module ZIP. Contents is
// restricted to Go's canonical synthesized module directive, not library code.
// SignedTree and Inclusion are independent of the actual module/source proof.
type ProxyGoModProof struct {
	Protocol   string   `json:"protocol"`
	Module     string   `json:"module"`
	Version    string   `json:"version"`
	ModuleSum  string   `json:"module_sum"`
	GoModSum   string   `json:"go_mod_sum"`
	Contents   string   `json:"contents"`
	SHA256     string   `json:"sha256"`
	RecordID   int64    `json:"record_id"`
	Record     string   `json:"record"`
	SignedTree string   `json:"signed_tree"`
	Inclusion  []string `json:"record_inclusion"`
}

// CaptureProxyGoMod proves membership using authenticated sumdb tiles. Reading
// the cache or fetching a tile is the caller's bounded, owned-resource policy.
func CaptureProxyGoMod(path, version, zipSum, modSum string, contents, lookup []byte, tiles tlog.TileReader) (*ProxyGoModProof, error) {
	if len(lookup) > 16<<10 || tiles == nil {
		return nil, fmt.Errorf("legacy module metadata lacks a bounded checksum lookup")
	}
	id, record, signed, err := tlog.ParseRecord(lookup)
	if err != nil {
		return nil, fmt.Errorf("parse legacy checksum record: %w", err)
	}
	proof := &ProxyGoModProof{
		Protocol: ProxyGoModProtocol, Module: path, Version: version, ModuleSum: zipSum,
		GoModSum: modSum, Contents: string(contents), SHA256: bytesSHA256(contents),
		RecordID: id, Record: string(record), SignedTree: string(signed),
	}
	tree, err := validateProxyGoModRecord(proof)
	if err != nil {
		return nil, err
	}
	audit, err := tlog.ProveRecord(tree.N, id, tlog.TileHashReader(tree, tiles))
	if err != nil {
		return nil, fmt.Errorf("prove legacy checksum record inclusion: %w", err)
	}
	for _, hash := range audit {
		proof.Inclusion = append(proof.Inclusion, hash.String())
	}
	if err := ValidateProxyGoMod(proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateProxyGoMod(proof *ProxyGoModProof) error {
	tree, err := validateProxyGoModRecord(proof)
	if err != nil {
		return err
	}
	if len(proof.Inclusion) > 64 {
		return fmt.Errorf("legacy checksum inclusion exceeds its bound")
	}
	var audit tlog.RecordProof
	for _, encoded := range proof.Inclusion {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) != tlog.HashSize || base64.StdEncoding.EncodeToString(data) != encoded {
			return fmt.Errorf("invalid legacy checksum inclusion hash")
		}
		var hash tlog.Hash
		copy(hash[:], data)
		audit = append(audit, hash)
	}
	if err := tlog.CheckRecord(audit, tree.N, tree.Hash, proof.RecordID, tlog.RecordHash([]byte(proof.Record))); err != nil {
		return fmt.Errorf("legacy checksum record is not in its signed tree: %w", err)
	}
	return nil
}

func validateProxyGoModRecord(proof *ProxyGoModProof) (tlog.Tree, error) {
	if proof == nil || proof.Protocol != ProxyGoModProtocol || module.Check(proof.Module, proof.Version) != nil ||
		len(proof.Contents) > 1024 || proof.Contents != "module "+proof.Module+"\n" ||
		proof.SHA256 != bytesSHA256([]byte(proof.Contents)) || !ValidH1(proof.ModuleSum) || !ValidH1(proof.GoModSum) ||
		len(proof.Record) > 4096 || len(proof.SignedTree) > 4096 || proof.RecordID < 0 {
		return tlog.Tree{}, fmt.Errorf("invalid independent legacy proxy-go.mod identity")
	}
	sum, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(proof.Contents)), nil
	})
	if err != nil || sum != proof.GoModSum {
		return tlog.Tree{}, fmt.Errorf("proxy go.mod bytes differ from their independent Go h1")
	}
	lines := strings.Split(strings.TrimSuffix(proof.Record, "\n"), "\n")
	if len(lines) != 2 || lines[0] != proof.Module+" "+proof.Version+" "+proof.ModuleSum ||
		lines[1] != proof.Module+" "+proof.Version+"/go.mod "+proof.GoModSum {
		return tlog.Tree{}, fmt.Errorf("checksum record differs from exact ZIP and proxy metadata identities")
	}
	verifier, err := note.NewVerifier(publicSumDBKey)
	if err != nil {
		return tlog.Tree{}, err
	}
	signed, err := note.Open([]byte(proof.SignedTree), note.VerifierList(verifier))
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("legacy checksum tree lacks the public sumdb signature: %w", err)
	}
	tree, err := tlog.ParseTree([]byte(signed.Text))
	if err != nil || tree.N <= proof.RecordID {
		return tlog.Tree{}, fmt.Errorf("invalid legacy checksum signed tree extent")
	}
	return tree, nil
}

// ValidH1 checks only the checksum spelling. It is not authentication.
func ValidH1(value string) bool {
	if !strings.HasPrefix(value, "h1:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "h1:")
	data, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(data) == 32 && base64.StdEncoding.EncodeToString(data) == encoded
}

func bytesSHA256(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
