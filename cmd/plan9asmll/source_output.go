package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// One attempt owns every whole-module or chunk output. Nothing reaches a
// public destination until every deferred source verification and owner Close
// has succeeded. Multiple renames are not an atomic filesystem transaction:
// a publication I/O failure rolls back already moved files, reporting every
// rollback failure. Pure post-commit temporary cleanup has a distinct error.
type compileOutputStage struct {
	directory        string
	info             os.FileInfo
	outputs          []compileOutputFile
	names            map[string]bool
	sealed           int
	inputs           map[string]bool
	inputNodes       []compileOutputInput
	inputMisses      []compileOutputSearchMiss
	inputDirectories []compileOutputInputDirectory
	inputNames       []compileOutputInputName
	inputNameKeys    map[string]bool
	inputSeenNames   map[string]bool
	inputSeenDirs    map[string]bool
	committed        bool
	rename           func(string, string) error
	removeAll        func(string) error
}

type compileOutputFile struct {
	path, destination, digest string
	info                      os.FileInfo
	parent                    assemblyMemberDirectory
	parentTarget              os.FileInfo
	previous                  os.FileInfo
	previousDigest            string
	backup                    string
	backupInfo                os.FileInfo
	published                 bool
	deletion                  bool
}

func compileOutputError() error {
	return fmt.Errorf("missing or redirected compile output transaction")
}

func outputPathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative))
}

func compileOutputParent(task asmTask, pkg *packages.Package, feature *featureConsumer) (string, error) {
	if task.OutLL == "" {
		return "", compileOutputError()
	}
	parent, err := filepath.Abs(filepath.Dir(task.OutLL))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(parent, 0755); err != nil {
		return "", err
	}
	parent, err = sourcepath.Resolve(parent)
	if err != nil {
		return "", err
	}
	// Ordinary observations retain the complete module tree, not just selected
	// sources. Put the same-filesystem stage outside every actual source root;
	// adding an ignored directory inside that tree would weaken its inventory.
	var roots []string
	add := func(path string) {
		if path == "" || err != nil {
			return
		}
		var root string
		root, err = sourcepath.Resolve(path)
		if err == nil {
			roots = append(roots, root)
		}
	}
	if pkg != nil {
		packages.Visit([]*packages.Package{pkg}, func(selected *packages.Package) bool {
			add(selected.Dir)
			if selected.Module != nil {
				add(selected.Module.Dir)
			}
			return true
		}, nil)
	}
	if feature != nil {
		add(feature.Root)
	}
	if err != nil {
		return "", err
	}
	for {
		inside := false
		for _, root := range roots {
			inside = inside || outputPathWithin(parent, root)
		}
		if !inside {
			return parent, nil
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", compileOutputError()
		}
		parent = next
	}
}

func newCompileOutputStage(task asmTask, pkg *packages.Package, feature *featureConsumer) (*compileOutputStage, error) {
	parent, err := compileOutputParent(task, pkg, feature)
	if err != nil {
		return nil, err
	}
	destinationParent, err := sourcepath.Resolve(filepath.Dir(task.OutLL))
	if err != nil {
		return nil, err
	}
	if err := sameOutputFilesystem(parent, destinationParent); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(parent, ".plan9asm-output-")
	if err != nil {
		return nil, err
	}
	info, err := sourcepath.Lstat(directory)
	if err != nil {
		_ = os.Remove(directory) // Empty, unobserved node: never recursive cleanup.
		return nil, err
	}
	return &compileOutputStage{directory: directory, info: info, names: make(map[string]bool), rename: os.Rename, removeAll: os.RemoveAll}, nil
}

func (stage *compileOutputStage) verifyDirectory() error {
	info, err := sourcepath.Lstat(stage.directory)
	if err != nil || !info.IsDir() || !os.SameFile(info, stage.info) {
		return compileOutputError()
	}
	return nil
}

func (stage *compileOutputStage) stageTask(task asmTask, config compileConfig) (asmTask, error) {
	// This is an output-namespace exclusion, not Go's source-selection grammar.
	// Reserve case variants too: they may name an existing source on a
	// case-insensitive filesystem, even when no CPP read retained that Go file.
	if task.OutLL == "" || continuationReferenceName(strings.ToLower(filepath.Base(task.OutLL))) {
		return asmTask{}, compileOutputError()
	}
	if err := stage.verifyDirectory(); err != nil {
		return asmTask{}, err
	}
	staged := task
	staged.OutLL = filepath.Join(stage.directory, filepath.Base(task.OutLL))
	files := []compileOutputFile{{path: staged.OutLL, destination: task.OutLL}}
	if config.Enabled {
		files = append(files, compileOutputFile{path: strings.TrimSuffix(staged.OutLL, filepath.Ext(staged.OutLL)) + ".o",
			destination: strings.TrimSuffix(task.OutLL, filepath.Ext(task.OutLL)) + ".o", deletion: !config.KeepObj})
	}
	for index := range files {
		output := &files[index]
		if stage.names[output.path] || index > 0 && output.path == files[0].path {
			return asmTask{}, compileOutputError()
		}
		absolute, err := filepath.Abs(output.destination)
		if err != nil {
			return asmTask{}, err
		}
		parent := filepath.Dir(absolute)
		physical, err := sourcepath.Resolve(parent)
		if err != nil {
			return asmTask{}, err
		}
		info, err := sourcepath.Lstat(parent)
		if err != nil {
			return asmTask{}, err
		}
		output.parent = assemblyMemberDirectory{path: parent, physical: physical, info: info}
		output.parentTarget, err = sourcepath.Lstat(physical)
		if err != nil || !output.parentTarget.IsDir() {
			return asmTask{}, compileOutputError()
		}
		output.destination = filepath.Join(physical, filepath.Base(absolute))
		output.previous, err = sourcepath.Lstat(output.destination)
		if err != nil && !os.IsNotExist(err) {
			return asmTask{}, err
		}
		if err := stage.verifyInputDestination(output.destination, output.previous); err != nil {
			return asmTask{}, err
		}
		if output.previous != nil {
			if !output.previous.Mode().IsRegular() {
				return asmTask{}, compileOutputError()
			}
			output.previousDigest, err = gotoolprofile.FileSHA256(output.destination)
			if err != nil {
				return asmTask{}, err
			}
		}
	}
	for _, output := range files {
		stage.names[output.path] = true
	}
	stage.outputs = append(stage.outputs, files...)
	return staged, nil
}

func verifyOutputFile(path string, info os.FileInfo, digest string) error {
	actual, err := sourcepath.Lstat(path)
	if info == nil {
		if os.IsNotExist(err) {
			return nil
		}
		return compileOutputError()
	}
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(actual, info) {
		return compileOutputError()
	}
	actualDigest, err := gotoolprofile.FileSHA256(path)
	if err != nil || actualDigest != digest {
		return compileOutputError()
	}
	return nil
}

func (output *compileOutputFile) verifyParent() error {
	info, err := sourcepath.Lstat(output.parent.path)
	if err != nil || !os.SameFile(info, output.parent.info) {
		return compileOutputError()
	}
	physical, err := sourcepath.Resolve(output.parent.path)
	if err != nil || physical != output.parent.physical {
		return compileOutputError()
	}
	info, err = sourcepath.Lstat(physical)
	if err != nil || !info.IsDir() || !os.SameFile(info, output.parentTarget) {
		return compileOutputError()
	}
	return nil
}

func (stage *compileOutputStage) seal() error {
	if err := stage.verifyDirectory(); err != nil {
		return err
	}
	for index := stage.sealed; index < len(stage.outputs); index++ {
		output := &stage.outputs[index]
		if output.deletion {
			if err := verifyOutputFile(output.path, nil, ""); err != nil {
				return err
			}
			continue
		}
		info, err := sourcepath.Lstat(output.path)
		if err != nil || !info.Mode().IsRegular() {
			return compileOutputError()
		}
		digest, err := gotoolprofile.FileSHA256(output.path)
		if err != nil {
			return err
		}
		output.info, output.digest = info, digest
	}
	stage.sealed = len(stage.outputs)
	return nil
}

func (stage *compileOutputStage) publish() error {
	if err := stage.verifyInputs(); err != nil {
		return err
	}
	if err := stage.verifyDirectory(); err != nil {
		return err
	}
	if len(stage.outputs) == 0 || stage.sealed != len(stage.outputs) || stage.committed {
		return compileOutputError()
	}
	for index := range stage.outputs {
		output := &stage.outputs[index]
		if err := errors.Join(stage.verifyInputDestination(output.destination, output.previous),
			output.verifyParent(), verifyOutputFile(output.path, output.info, output.digest),
			verifyOutputFile(output.destination, output.previous, output.previousDigest)); err != nil {
			return err
		}
	}
	for index := range stage.outputs {
		output := &stage.outputs[index]
		if err := errors.Join(stage.verifyInputs(), stage.verifyInputDestination(output.destination, output.previous),
			stage.verifyDirectory(), output.verifyParent(),
			verifyOutputFile(output.path, output.info, output.digest),
			verifyOutputFile(output.destination, output.previous, output.previousDigest)); err != nil {
			return errors.Join(err, stage.rollback())
		}
		if output.previous != nil {
			// An absent backup name in the owned same-FS stage also permits
			// Windows replacement without relying on overwrite-Rename behavior.
			output.backup = filepath.Join(stage.directory, fmt.Sprintf("previous-%06d", index))
			if err := stage.rename(output.destination, output.backup); err != nil {
				return errors.Join(fmt.Errorf("backup compile output: %w", err), stage.rollback())
			}
			output.backupInfo = output.previous
		}
		if err := errors.Join(stage.verifyInputs(), stage.verifyInputDestination(output.destination, output.previous),
			stage.verifyDirectory(), output.verifyParent(),
			verifyOutputFile(output.path, output.info, output.digest),
			verifyOutputFile(output.destination, nil, "")); err != nil {
			return errors.Join(err, stage.rollback())
		}
		if output.deletion {
			continue // Only this actual task's old object; never unrelated parts.
		}
		if err := stage.rename(output.path, output.destination); err != nil {
			return errors.Join(fmt.Errorf("publish verified compile output: %w", err), stage.rollback())
		}
		output.published = true
	}
	stage.committed = true
	return nil
}

func (stage *compileOutputStage) rollback() error {
	if err := stage.verifyDirectory(); err != nil {
		return fmt.Errorf("rollback compile output: %w", err)
	}
	var result error
	for index := len(stage.outputs) - 1; index >= 0; index-- {
		output := &stage.outputs[index]
		if !output.published && output.backupInfo == nil {
			continue
		}
		if err := output.verifyParent(); err != nil {
			result = errors.Join(result, fmt.Errorf("rollback compile output: %w", err))
			continue
		}
		if output.published {
			if err := verifyOutputFile(output.destination, output.info, output.digest); err != nil {
				result = errors.Join(result, fmt.Errorf("rollback compile output: %w", err))
				continue
			}
			if err := stage.rename(output.destination, output.path); err != nil {
				result = errors.Join(result, fmt.Errorf("rollback compile output: %w", err))
				continue
			}
			output.published = false
		}
		if output.backupInfo != nil {
			if err := errors.Join(verifyOutputFile(output.backup, output.backupInfo, output.previousDigest),
				verifyOutputFile(output.destination, nil, "")); err != nil {
				result = errors.Join(result, fmt.Errorf("restore previous compile output: %w", err))
				continue
			}
			if err := stage.rename(output.backup, output.destination); err != nil {
				result = errors.Join(result, fmt.Errorf("restore previous compile output: %w", err))
				continue
			}
			output.backupInfo = nil
		}
	}
	return result
}

func (stage *compileOutputStage) close() error {
	if err := stage.verifyDirectory(); err != nil {
		if stage.committed {
			return fmt.Errorf("compile outputs committed; temporary cleanup failed: %w", err)
		}
		return err
	}
	// Never erase the only recoverable old output after a failed rollback.
	for _, output := range stage.outputs {
		if !stage.committed && output.backupInfo != nil {
			return fmt.Errorf("unrestored compile output retained in owned stage %s", stage.directory)
		}
	}
	err := stage.removeAll(stage.directory)
	if err != nil && stage.committed {
		return fmt.Errorf("compile outputs committed; temporary cleanup failed: %w", err)
	}
	return err
}
