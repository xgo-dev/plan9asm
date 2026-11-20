package gotoolprofile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"strings"
)

const instrumentationOriginalSourcesProtocol = "original_instrumentation_package_sources_v1"
const instrumentationOriginalFileLimit = 2 << 20
const instrumentationOriginalInventoryLimit = 16 << 20

// InstrumentationOriginalSourceInventory retains complete original Go/ASM
// bytes once per package, not once per mode/tag scope. Full bytes are needed
// for import "C" and package-role AST replay; a package-clause header is not
// proof that a source has no cgo import. Hash agreement is source binding, not
// independent ZIP authentication: the caller still supplies that prerequisite.
type InstrumentationOriginalSourceInventory struct {
	Protocol  string            `json:"protocol"`
	Module    string            `json:"module"`
	Version   string            `json:"version"`
	Directory string            `json:"directory"`
	Contents  map[string]string `json:"contents"`
	// Present only for a version-replaced archive with a different declared
	// namespace. This is complete original go.mod, never proxy metadata.
	ModuleMetadata string `json:"original_module_metadata,omitempty"`
}

func CaptureInstrumentationOriginalSourceInventory(input *ConsumerInput, directory string) (*InstrumentationOriginalSourceInventory, error) {
	if err := recheckInstrumentationOriginalSources(input); err != nil {
		return nil, err
	}
	names, present := input.Directories[directory]
	if !present {
		return nil, fmt.Errorf("original package directory is absent")
	}
	inventory := &InstrumentationOriginalSourceInventory{
		Protocol: instrumentationOriginalSourcesProtocol, Module: input.Module, Version: input.Version,
		Directory: directory, Contents: make(map[string]string),
	}
	total := 0
	if input.SourceModule != "" && input.SourceModule != input.Module {
		physical, err := CPPRegularSource(input.SourceRoot, "go.mod")
		if err != nil {
			return nil, err
		}
		opened, err := os.Open(physical)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(opened, instrumentationOriginalFileLimit+1))
		if err := errors.Join(readErr, opened.Close()); err != nil {
			return nil, err
		}
		inventory.ModuleMetadata = string(data)
		total += len(data)
	}
	for _, name := range names {
		if path.Ext(name) != ".go" && path.Ext(name) != ".s" {
			continue
		}
		file := path.Join(directory, name)
		limit := instrumentationOriginalSourceByteLimit(file)
		physical, err := CPPRegularSource(input.SourceRoot, file)
		if err != nil {
			return nil, err
		}
		opened, err := os.Open(physical)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(opened, int64(limit)+1))
		if err := errors.Join(readErr, opened.Close()); err != nil {
			return nil, err
		}
		total += len(data)
		if len(data) > limit || total > instrumentationOriginalInventoryLimit || bytesSHA256(data) != input.Sources[file] {
			return nil, fmt.Errorf("original source changed or exceeds the bounded full-source inventory: %s", file)
		}
		inventory.Contents[file] = string(data)
	}
	if err := ValidateInstrumentationOriginalSourceInventory(input, directory, inventory); err != nil {
		return nil, err
	}
	if err := recheckInstrumentationOriginalSources(input); err != nil {
		return nil, err
	}
	return inventory, nil
}

func ValidateInstrumentationOriginalSourceInventory(input *ConsumerInput, directory string, inventory *InstrumentationOriginalSourceInventory) error {
	if input == nil || inventory == nil || inventory.Protocol != instrumentationOriginalSourcesProtocol ||
		inventory.Module != input.Module || inventory.Version != input.Version || inventory.Directory != directory ||
		directory != "." && !CPPLocalSource(directory) {
		return fmt.Errorf("missing exact original full-source inventory identity")
	}
	if err := validateInstrumentationModuleNamespace(input, inventory.ModuleMetadata); err != nil {
		return err
	}
	names, present := input.Directories[directory]
	if !present || len(names) == 0 || len(names) > 65536 {
		return fmt.Errorf("full-source inventory lacks its original complete directory")
	}
	wanted := make(map[string]string)
	total := len(inventory.ModuleMetadata)
	for _, name := range names {
		if path.Ext(name) != ".go" && path.Ext(name) != ".s" {
			continue
		}
		file := path.Join(directory, name)
		contents, found := inventory.Contents[file]
		total += len(contents)
		if !found || len(contents) > instrumentationOriginalSourceByteLimit(file) || total > instrumentationOriginalInventoryLimit ||
			!CPPLocalSource(file) || bytesSHA256([]byte(contents)) != input.Sources[file] || strings.ContainsRune(contents, '\x00') {
			return fmt.Errorf("original full-source inventory is missing, changed or over-bound: %s", file)
		}
		wanted[file] = contents
	}
	if len(wanted) == 0 || !reflect.DeepEqual(wanted, inventory.Contents) {
		return fmt.Errorf("original full-source inventory has missing or extra members")
	}
	return nil
}
