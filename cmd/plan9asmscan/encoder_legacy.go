package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// legacyEncoderReport inventories declaration rows, not their applicability in
// a particular x86 mode or successful translation. Keep it independent of the
// historical operand-class buckets and AVX rule fingerprints.
type legacyEncoderReport struct {
	OperandRows    int                         `json:"operand_rows"`
	MoveRows       int                         `json:"move_rows"`
	SpecialEntries int                         `json:"special_entries"`
	Fingerprint    string                      `json:"table_row_fingerprint"`
	Catalog        goasmrules.X86LegacyCatalog `json:"catalog"`
}

func attachLegacyEncoderCatalog(rep *report, goroot string) error {
	if rep.Corpus != "go-asm" || (rep.Goarch != "amd64" && rep.Goarch != "386") {
		return nil
	}
	catalog, err := goasmrules.LoadX86LegacyRules(goroot)
	if err != nil {
		return err
	}
	legacy := &legacyEncoderReport{Catalog: catalog}
	for _, entry := range catalog.Optab {
		legacy.OperandRows += len(entry.Rows)
		if entry.Kind == "special" {
			legacy.SpecialEntries++
		}
	}
	for _, entry := range catalog.Movtab {
		if entry.Kind == "encoding" {
			legacy.MoveRows++
		}
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("marshal legacy table rows: %w", err)
	}
	// This hashes normalized table rows, including symbolic attributes. It is
	// not a fingerprint of constant definitions or the entire Go assembler's
	// row-selection, mode filtering and encoding semantics.
	digest := sha256.Sum256(append([]byte("go-x86-legacy-table-rows-v1\n"), data...))
	legacy.Fingerprint = hex.EncodeToString(digest[:])
	rep.LegacyEncoder = legacy
	return nil
}
