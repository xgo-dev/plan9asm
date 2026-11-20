package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"strings"
)

const sdkCgoMetadataPrefix = "\n$$\n\n$$\n\n\n$$  // cgo\n"

// sdkObjectBody observes a compiler metadata prologue only. It cannot supply
// a dynamic import, linker flag, external call or memory capability.
func sdkObjectBody(object []byte, target string) ([]byte, error) {
	end := bytes.Index(object, []byte("\n!\n"))
	if end < 0 || end > 64<<10 {
		return nil, contextError("SDK compiler metadata prologue exceeds its byte bound")
	}
	metadata := bytes.Index(object[:end], []byte(sdkCgoMetadataPrefix))
	if metadata < 0 {
		if bytes.Contains(object[:end], []byte("$$")) || bytes.Contains(object[:end], []byte("// cgo")) {
			return nil, contextError("SDK compiler metadata has an unregistered prologue spelling")
		}
		return objectBody(object, target)
	}
	if metadata > 4096 || !bytes.HasSuffix(object[:metadata], []byte("\n\n")) ||
		!bytes.HasSuffix(object[:end], []byte("\n\n$$\n\n")) {
		return nil, contextError("SDK compiler metadata lacks its exact export/prologue delimiters")
	}
	payload := object[metadata+len(sdkCgoMetadataPrefix) : end-len("\n\n$$\n\n")]
	var directives [][]string
	if json.Unmarshal(payload, &directives) != nil || len(directives) == 0 || len(directives) > 1024 {
		return nil, contextError("SDK compiler metadata is not one bounded complete directive array")
	}
	for _, directive := range directives {
		if !sdkCgoMetadataDirective(directive) {
			return nil, contextError("SDK compiler metadata has an unknown or incomplete directive row")
		}
	}
	if _, err := objectVersion(object, target); err != nil {
		return nil, err
	}
	return object[end+3:], nil
}

// This is the complete row grammar in the pinned linker's setCgoAttr. It
// observes the original rows without applying any of their linker effects.
func sdkCgoMetadataDirective(row []string) bool {
	if len(row) < 2 || len(row) > 4 {
		return false
	}
	for _, field := range row {
		if len(field) > 4096 || strings.ContainsAny(field, "\x00\r\n") {
			return false
		}
	}
	switch row[0] {
	case "cgo_import_dynamic":
		return true
	case "cgo_import_static", "cgo_dynamic_linker", "cgo_ldflag":
		return len(row) == 2
	case "cgo_export_static", "cgo_export_dynamic":
		return len(row) < 4 || row[3] == "ABI0" || row[3] == "ABIInternal"
	}
	return false
}
