package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// The reference role covers all direct Go/s/S/h siblings, not just the target's
// build-selected inputs. Its byte bound matches the existing complete x86
// source role; its file bound is the selected Go/native bounds combined.
const continuationReferenceFiles = 256 + 512
const continuationReferenceBytes = 64 << 20
const continuationDirectoryEntries = 4096

type continuationReferenceFile struct {
	node, target     os.FileInfo
	physical, digest string
	data             []byte // Retained only until the whole-file privacy query finishes.
}

type continuationReferenceSource struct {
	self             *continuationReferenceSource
	pkg              *packages.Package
	selected         *x86CallerTypedPackage
	context          context.Context
	directory        string
	packageDirectory assemblyMemberDirectory
	directoryInfo    os.FileInfo
	files            map[string]continuationReferenceFile
	selfName         string
	revoked          atomic.Bool
}

func continuationSourceError() error {
	return fmt.Errorf("%w: private continuation reference closure changed or lacks complete actual source", plan9asm.ErrProbeNeedsContext)
}

func continuationReferenceName(name string) bool {
	switch filepath.Ext(name) {
	case ".go", ".s", ".S", ".h":
		return true
	}
	return false
}

func continuationReferenceNames(directory string) (names []string, result error) {
	reader, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, reader.Close()) }()
	total := 0
	for {
		entries, err := reader.ReadDir(128)
		total += len(entries)
		if total > continuationDirectoryEntries {
			return nil, continuationSourceError()
		}
		for _, entry := range entries {
			if !entry.IsDir() && continuationReferenceName(entry.Name()) {
				if len(names) >= continuationReferenceFiles {
					return nil, continuationSourceError()
				}
				names = append(names, entry.Name())
			}
		}
		if err == io.EOF {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func readContinuationReference(filename string, total *int64) (record continuationReferenceFile, result error) {
	if total == nil || *total < 0 || *total > continuationReferenceBytes {
		return record, continuationSourceError()
	}
	node, err := sourcepath.Lstat(filename)
	if err != nil {
		return record, err
	}
	physical, err := sourcepath.Resolve(filename)
	if err != nil {
		return record, err
	}
	info, err := sourcepath.Lstat(physical)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > continuationReferenceBytes-*total {
		return record, continuationSourceError()
	}
	reader, err := os.Open(filename)
	if err != nil {
		return record, err
	}
	defer func() { result = errors.Join(result, reader.Close()) }()
	opened, err := reader.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return record, continuationSourceError()
	}
	data, err := io.ReadAll(io.LimitReader(reader, continuationReferenceBytes-*total+1))
	if err != nil || int64(len(data)) > continuationReferenceBytes-*total {
		return record, continuationSourceError()
	}
	*total += int64(len(data))
	return continuationReferenceFile{node: node, target: info, physical: physical, digest: featureBytesSHA256(data), data: data}, nil
}

func captureContinuationReferenceSource(pkg *packages.Package, asm, target string, defines []string,
	config compileConfig,
) (*continuationReferenceSource, error) {
	selected, err := loadX86ActualSelectedAssembly(pkg, target, asm, defines, config)
	if err != nil {
		return nil, err
	}
	directory, err := sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return nil, err
	}
	parent, err := sourcepath.Resolve(filepath.Dir(selected.member.selected))
	if err != nil || parent != directory {
		return nil, continuationSourceError()
	}
	packageInfo, err := sourcepath.Lstat(pkg.Dir)
	if err != nil {
		return nil, err
	}
	directoryInfo, err := sourcepath.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() {
		return nil, continuationSourceError()
	}
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	source := &continuationReferenceSource{pkg: pkg, selected: selected, context: ctx,
		directory: directory, directoryInfo: directoryInfo,
		packageDirectory: assemblyMemberDirectory{pkg.Dir, directory, packageInfo},
		files:            make(map[string]continuationReferenceFile), selfName: filepath.Base(selected.member.selected)}
	names, err := continuationReferenceNames(directory)
	if err != nil {
		return nil, err
	}
	total := int64(0)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, err := readContinuationReference(filepath.Join(directory, name), &total)
		if err != nil {
			return nil, err
		}
		source.files[name] = record
	}
	self, present := source.files[source.selfName]
	if !present || !os.SameFile(self.node, selected.member.selectedNode) || self.digest != selected.sources[selected.member.selected] {
		return nil, continuationSourceError()
	}
	// Every selected input retains its actual compiler key and complete bytes.
	for filename, expected := range selected.sources {
		parent, err := sourcepath.Resolve(filepath.Dir(filename))
		record, present := source.files[filepath.Base(filename)]
		if err != nil || parent != directory || !present || record.digest != expected {
			return nil, continuationSourceError()
		}
	}
	source.self = source
	if err := source.verify(ctx, defines, config.Feature); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *continuationReferenceSource) verifyInventory() error {
	if source == nil || source.self != source || source.revoked.Load() || source.pkg == nil || source.selected == nil || source.selected.selection == nil || source.context == nil {
		return continuationSourceError()
	}
	selection, pkg := source.selected.selection, source.pkg
	if selection.identity != x86CallerSelectionIdentity(pkg, selection.env) || selection.types != pkg.Types ||
		!reflect.DeepEqual(selection.sizes, x86CallerSizes(pkg.TypesSizes)) || len(selection.imports) != len(pkg.Imports) {
		return continuationSourceError()
	}
	for path, dependency := range pkg.Imports {
		if dependency == nil || dependency.Types != selection.imports[path] {
			return continuationSourceError()
		}
	}
	if err := source.selected.member.verify(); err != nil {
		return err
	}
	for _, directory := range []assemblyMemberDirectory{source.packageDirectory, {source.directory, source.directory, source.directoryInfo}} {
		info, err := sourcepath.Lstat(directory.path)
		if err != nil || !os.SameFile(info, directory.info) {
			return continuationSourceError()
		}
		physical, err := sourcepath.Resolve(directory.path)
		if err != nil || physical != directory.physical {
			return continuationSourceError()
		}
	}
	names, err := continuationReferenceNames(source.directory)
	if err != nil || len(names) != len(source.files) {
		return continuationSourceError()
	}
	total := int64(0)
	for _, name := range names {
		expected, present := source.files[name]
		if !present {
			return continuationSourceError()
		}
		actual, err := readContinuationReference(filepath.Join(source.directory, name), &total)
		if err != nil || actual.physical != expected.physical || actual.digest != expected.digest ||
			!os.SameFile(actual.node, expected.node) || !os.SameFile(actual.target, expected.target) {
			return continuationSourceError()
		}
	}
	return nil
}

func (source *continuationReferenceSource) verify(ctx context.Context, defines []string, feature *featureConsumer) (result error) {
	if source == nil {
		return continuationSourceError()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := source.verifyInventory(); err != nil {
		source.revoked.Store(true)
		return err
	}
	defer func() {
		// Sample caller code before the final callback-free inventory guard.
		result = errors.Join(result, ctx.Err(), source.context.Err(), source.verifyInventory())
		if result != nil {
			source.revoked.Store(true)
		}
	}()
	return source.selected.verify(ctx, defines, feature)
}

func (source *continuationReferenceSource) releaseQueryBytes() {
	for name, record := range source.files {
		record.data = nil
		source.files[name] = record
	}
}
