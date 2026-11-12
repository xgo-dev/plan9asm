//go:build go1.27

package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The independent SDK raw-kind/archive oracle remains
// internal/gostaticstorage.TestGoSDKFIPSTextKindOriginalArchive. Here the
// complete original source, mapped source and binary records are established
// before testing the listing consumer. No numerical owner is constructed.
func TestGoX86NumericalNativeListingOriginalFIPSProducer(t *testing.T) {
	const pkg = "crypto/internal/fips140/bigmod"
	ctx, request := sdkASMDataRequest(t, "amd64", pkg)
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("complete actual Go FIPS source/header/archive prior", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	inputs := source.observation.ObjectInputs
	if len(inputs.Sources) != 1 || inputs.Sources[0].Name != "nat_amd64.s" {
		t.Fatal("original FIPS package source selection changed")
	}
	input := inputs.Sources[0]
	original, err := os.ReadFile(filepath.Join(request.Directory, input.Name))
	if err != nil || !bytes.Equal(input.Original, original) || len(original) == 0 {
		t.Fatal("actual original assembly source was cropped or replaced", err)
	}
	archive, err := os.ReadFile(source.guard.selection.Export)
	if err != nil || !bytes.Equal(archive, inputs.Archive) || len(archive) == 0 {
		t.Fatal("actual compiler archive differs from the source observation", err)
	}
	stems := []string{"addMulVVW1024", "addMulVVW1536", "addMulVVW2048"}
	for _, stem := range stems {
		seen := make(map[uint16]bool)
		for _, member := range source.observation.Objects.Members {
			for _, text := range member.Texts {
				if text.Name != pkg+"."+stem {
					continue
				}
				if text.Kind != 2 || text.Size == 0 || text.ABI > 1 || seen[text.ABI] {
					t.Fatal("actual compiler/archive raw Kind2 ABI inventory differs", text)
				}
				seen[text.ABI] = true
			}
		}
		if len(seen) != 2 || !seen[0] || !seen[1] {
			t.Fatal("complete original archive lost its assembly and compiler wrapper entries", stem, seen)
		}
	}
	// Separate original and position-mapped invocations match the producer's
	// exact SDK arguments and do not modify its retained commands or seal.
	directory := t.TempDir()
	expanded := filepath.Join(directory, "mapped.s")
	if err := os.WriteFile(expanded, []byte(source.observation.Positions[0].Mapped), 0600); err != nil {
		t.Fatal(err)
	}
	var listings [2][]byte
	var objects [2][]byte
	for index, assembly := range []string{filepath.Join(request.Directory, input.Name), expanded} {
		object := filepath.Join(directory, fmt.Sprintf("listing-%d.o", index))
		arguments := append([]string(nil), source.asmArguments(source.guard.owned)...)
		arguments = append(arguments, "-S", "-o", object, assembly)
		stage, cancel := runtimeOracleStageContext(t)
		listings[index], err = goasmcmd.Run(stage, request.Directory, request.Environment, request.GoBinary, arguments...)
		cancel()
		if err != nil {
			t.Fatal("actual complete original/mapped Go listing prior", index, err)
		}
		objects[index], err = os.ReadFile(object)
		if err != nil {
			t.Fatal(err)
		}
		// This prior deliberately does not use numericalListingHeader.
		// It observes the actual selected writer's explicit kind token.
		headers := make(map[string]bool)
		for _, line := range strings.Split(string(listings[index]), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "STEXTFIPS" {
				if headers[fields[0]] {
					t.Fatal("actual Go repeated an original FIPS listing header", line)
				}
				headers[fields[0]] = true
			}
		}
		if len(headers) != len(stems) {
			t.Fatal("actual complete Go listing lacks three explicit STEXTFIPS producers", index, headers)
		}
		for _, stem := range stems {
			if !headers[pkg+"."+stem] {
				t.Fatal("actual listing header changed its complete native identity", stem)
			}
		}
	}
	originalText, expandedText, err := gostaticstorage.ObserveX86SDKASMDataListingObjects(inputs, 0, objects[0], objects[1])
	if err != nil || len(originalText) != len(stems) || len(expandedText) != len(stems) {
		t.Fatal("original/mapped actual listing objects differ from the complete archive", err)
	}
	for index, text := range originalText {
		other := expandedText[index]
		if text.Kind != 2 || other.Kind != 2 || text.ABI != 0 || other.ABI != 0 ||
			text.Name != other.Name || text.Size <= 0 || !bytes.Equal(text.Code, other.Code) {
			t.Fatal("actual Kind2 listing/object identity differs before consumer validation", text.Name)
		}
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete source/archive prior changed before listing consumption", err)
	}
	t.Log("actual original and mapped bigmod source/listings/Kind2 objects and full ABI0+ABI1 archive priors passed before listing consumer")
	for index, listing := range listings {
		t.Run([]string{"original", "mapped"}[index], func(t *testing.T) {
			rows, err := numericalListingRows(listing)
			if err != nil || len(rows) != len(stems) {
				t.Fatal("complete actual STEXTFIPS listing lost native instruction ownership", err)
			}
			for _, text := range originalText {
				body := rows[text.Name]
				if len(body) < 2 {
					t.Fatal("complete native body disappeared from its original listing owner", text.Name)
				}
				reads := 0
				for pc, candidates := range body {
					if pc < 0 || pc >= text.Size {
						t.Fatal("listing PC lies outside its actual original text", text.Name, pc, text.Size)
					}
					for _, row := range candidates {
						if row.ins.Op == "CMPB" && len(row.ins.Args) == 2 && strings.Contains(row.ins.Args[0].Sym, "supportADX") {
							reads++
						}
					}
				}
				if reads != 1 {
					t.Fatal("original numerical read was assigned to another native owner", text.Name, reads)
				}
			}
		})
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("listing consumer changed its independent original observation", err)
	}
}
