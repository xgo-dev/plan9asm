package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSDKCompilerMetadataPrologueKeepsOwnedHeaderBoundary(t *testing.T) {
	var directives [][]string
	for index := 0; index < 160; index++ {
		directives = append(directives, []string{"cgo_import_dynamic", "local_symbol", "remote_symbol", "native-library"})
	}
	payload, err := json.Marshal(directives)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"darwin/amd64", "windows/amd64", "windows/386"} {
		header := "go object " + strings.ReplaceAll(target, "/", " ") + " go1.27.2\n\n"
		object := []byte(header + "\n$$\n\n$$\n\n\n$$  // cgo\n" + string(payload) + "\n\n$$\n\n\n!\nbody")
		if _, err := objectBody(object, target); !errors.Is(err, ErrContext) {
			t.Fatalf("%s large SDK prologue widened the legacy owned object reader", target)
		}
		body, err := sdkObjectBody(object, target)
		if err != nil || !bytes.Equal(body, []byte("body")) {
			t.Fatalf("%s lost the complete stock compiler metadata prologue: %v", target, err)
		}
	}
}

func TestSDKCompilerMetadataPrologueCompleteRowGrammar(t *testing.T) {
	for _, name := range []string{"cgo_import_dynamic", "cgo_import_static", "cgo_export_static", "cgo_export_dynamic", "cgo_dynamic_linker", "cgo_ldflag"} {
		for _, count := range []int{0, 1, 2, 3, 4, 5} {
			row := make([]string, count)
			for index := range row {
				row[index] = "symbol"
			}
			if count > 0 {
				row[0] = name
			}
			if count == 4 {
				row[3] = "ABIInternal"
			}
			accepted := count == 2
			if name == "cgo_import_dynamic" || name == "cgo_export_static" || name == "cgo_export_dynamic" {
				accepted = count >= 2 && count <= 4
			}
			if sdkCgoMetadataDirective(row) != accepted {
				t.Fatalf("complete original linker row changed: %q", row)
			}
		}
	}
	for _, row := range [][]string{
		{"cgo_unknown", "name"},
		{"cgo_export_static", "name", "external", "ABIUnknown"},
		{"cgo_import_dynamic", "name\x00"},
		{"cgo_ldflag", "-flag\ninjected"},
		{"cgo_import_static", strings.Repeat("x", 4097)},
	} {
		if sdkCgoMetadataDirective(row) {
			t.Fatalf("malformed directive supplied a metadata row: %q", row)
		}
	}
}

func TestSDKCompilerMetadataPrologueRejectsUnboundFormat(t *testing.T) {
	const header = "go object windows amd64 go1.27.2\n\n"
	wrap := func(payload string) []byte {
		return []byte(header + sdkCgoMetadataPrefix + payload + "\n\n$$\n\n\n!\nbody")
	}
	valid := wrap(`[["cgo_import_dynamic","local","remote","library"]]`)
	for name, object := range map[string][]byte{
		"missing-array":    wrap(`{}`),
		"empty-array":      wrap(`[]`),
		"empty-directive":  wrap(`[[]]`),
		"unknown-row":      wrap(`[["unknown","symbol"]]`),
		"nonstring-field":  wrap(`[["cgo_ldflag",42]]`),
		"trailing-json":    wrap(`[["cgo_ldflag","-flag"]] []`),
		"missing-trailer":  bytes.Replace(valid, []byte("\n\n$$\n\n\n!\n"), []byte("\n!\n"), 1),
		"missing-export":   bytes.Replace(valid, []byte(sdkCgoMetadataPrefix), []byte("\n$$  // cgo\n"), 1),
		"oversized-body":   wrap(strings.Repeat(" ", 64<<10)),
		"foreign-target":   bytes.Replace(valid, []byte("windows amd64"), []byte("linux amd64"), 1),
		"foreign-version":  bytes.Replace(valid, []byte("go1.27.2"), []byte("go1.26.9"), 1),
		"ordinary-padding": []byte(header + strings.Repeat("x", 4097) + "\n!\nbody"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sdkObjectBody(object, "windows/amd64"); !errors.Is(err, ErrContext) {
				t.Fatalf("unbound metadata supplied a compiler object: %v", err)
			}
		})
	}
}
