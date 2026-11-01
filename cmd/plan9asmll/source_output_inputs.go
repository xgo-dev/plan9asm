package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

type compileOutputInput struct {
	path, physical string
	node, target   os.FileInfo
}

type compileOutputInputDirectory struct {
	path, physical string
	node, target   os.FileInfo
}

type compileOutputInputName struct {
	path, role string
}

type compileOutputSearchMiss struct {
	path, physical, ancestor, ancestorTarget string
	node, target                             os.FileInfo
}

// Resolve an absent name through its nearest existing ancestor. A missing
// intermediate directory is not an error or an invented successfully read file.
func compileOutputMissingPath(filename string) (physical, ancestor, target string, err error) {
	filename, err = filepath.Abs(filename)
	if err != nil {
		return "", "", "", err
	}
	ancestor = filepath.Dir(filename)
	for {
		target, err = sourcepath.Resolve(ancestor)
		if err == nil {
			var relative string
			relative, err = filepath.Rel(ancestor, filename)
			return filepath.Join(target, relative), ancestor, target, err
		}
		if !os.IsNotExist(err) || filepath.Dir(ancestor) == ancestor {
			return "", "", "", err
		}
		ancestor = filepath.Dir(ancestor)
	}
}

func (stage *compileOutputStage) verifyInputs() error {
	for _, directory := range stage.inputDirectories {
		physical, err := sourcepath.Resolve(directory.path)
		if err != nil || physical != directory.physical {
			return fmt.Errorf("compile input directory path changed before publication")
		}
		node, err := sourcepath.Lstat(directory.path)
		if err != nil || !os.SameFile(node, directory.node) {
			return fmt.Errorf("compile input directory node changed before publication")
		}
		target, err := sourcepath.Lstat(physical)
		if err != nil || !os.SameFile(target, directory.target) {
			return fmt.Errorf("compile input directory target changed before publication")
		}
	}
	for _, input := range stage.inputNodes {
		physical, err := sourcepath.Resolve(input.path)
		if err != nil || physical != input.physical {
			return fmt.Errorf("compile input path changed before publication")
		}
		node, err := sourcepath.Lstat(input.path)
		if err != nil || !os.SameFile(node, input.node) {
			return fmt.Errorf("compile input node changed before publication")
		}
		target, err := sourcepath.Lstat(physical)
		if err != nil || !os.SameFile(target, input.target) {
			return fmt.Errorf("compile input target changed before publication")
		}
	}
	for _, miss := range stage.inputMisses {
		if _, err := sourcepath.Resolve(miss.path); !os.IsNotExist(err) {
			return fmt.Errorf("compile preferred include is no longer absent")
		}
		physical, _, _, err := compileOutputMissingPath(miss.path)
		if err != nil || physical != miss.physical {
			return fmt.Errorf("compile preferred include path changed before publication")
		}
		target, err := sourcepath.Resolve(miss.ancestor)
		if err != nil || target != miss.ancestorTarget {
			return fmt.Errorf("compile include search ancestor changed before publication")
		}
		node, err := sourcepath.Lstat(miss.ancestor)
		if err != nil || !os.SameFile(node, miss.node) {
			return fmt.Errorf("compile include search node changed before publication")
		}
		info, err := sourcepath.Lstat(target)
		if err != nil || !os.SameFile(info, miss.target) {
			return fmt.Errorf("compile include search target changed before publication")
		}
	}
	return nil
}

// Protect actual source and module metadata names, including alternate-extension
// files consumed by the existing plain/registered CPP producer. This is solely
// an output exclusion: package fields and input reports confer no source role.
func (stage *compileOutputStage) protectInputs(pkg *packages.Package, actual, misses []string) error {
	if stage.inputs == nil {
		stage.inputs = make(map[string]bool)
		stage.inputSeenNames = make(map[string]bool)
		stage.inputSeenDirs = make(map[string]bool)
	}
	// A whole attempt owns all chunks. Keep the first identity and deduplicate
	// repeated observations instead of refreshing a changed node or retaining
	// another copy of the same complete source graph for every part.
	seen, seenDirectories := stage.inputSeenNames, stage.inputSeenDirs
	observeDirectories := func(directory string) error {
		for ; ; directory = filepath.Dir(directory) {
			if !seenDirectories[directory] {
				physical, err := sourcepath.Resolve(directory)
				if err != nil {
					return err
				}
				node, err := sourcepath.Lstat(directory)
				if err != nil {
					return err
				}
				target, err := sourcepath.Lstat(physical)
				if err != nil || !target.IsDir() {
					return fmt.Errorf("compile input directory is missing or redirected: %v", err)
				}
				stage.inputDirectories = append(stage.inputDirectories, compileOutputInputDirectory{directory, physical, node, target})
				seenDirectories[directory] = true
			}
			if filepath.Dir(directory) == directory {
				break
			}
		}
		return nil
	}
	add := func(filename string, allowAbsent bool) error {
		if filename == "" || seen[filename] {
			return nil
		}
		seen[filename] = true
		physical, err := sourcepath.Resolve(filename)
		if os.IsNotExist(err) {
			if !allowAbsent {
				return fmt.Errorf("compile original input disappeared before publication: %w", err)
			}
			// Metadata may be absent (go.sum); its exact physical parent and
			// basename are still not an output location for this source task.
			physical, _, _, err = compileOutputMissingPath(filename)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if err := observeDirectories(filepath.Dir(filename)); err != nil {
				return err
			}
			node, err := sourcepath.Lstat(filename)
			if err != nil {
				return err
			}
			target, err := sourcepath.Lstat(physical)
			if err != nil {
				return err
			}
			stage.inputNodes = append(stage.inputNodes, compileOutputInput{filename, physical, node, target})
		}
		stage.inputs[physical] = true
		return nil
	}
	for _, filename := range actual {
		if err := add(filename, false); err != nil {
			return err
		}
	}
	for _, filename := range misses {
		if filename == "" || seen[filename] {
			continue
		}
		seen[filename] = true
		if _, err := sourcepath.Resolve(filename); !os.IsNotExist(err) {
			return fmt.Errorf("compile preferred include lacks its original search miss")
		}
		physical, ancestor, target, err := compileOutputMissingPath(filename)
		if err != nil {
			return err
		}
		if err := observeDirectories(ancestor); err != nil {
			return err
		}
		node, err := sourcepath.Lstat(ancestor)
		if err != nil {
			return err
		}
		info, err := sourcepath.Lstat(target)
		if err != nil {
			return err
		}
		stage.inputs[physical] = true
		stage.inputMisses = append(stage.inputMisses, compileOutputSearchMiss{filename, physical, ancestor, target, node, info})
		stage.reserveInputName(filename, "preferred include")
	}
	var result error
	if pkg != nil {
		packages.Visit([]*packages.Package{pkg}, func(selected *packages.Package) bool {
			if result != nil {
				return false
			}
			for _, group := range [][]string{selected.GoFiles, selected.CompiledGoFiles, selected.OtherFiles, selected.EmbedFiles} {
				for _, filename := range group {
					if continuationReferenceName(filepath.Base(filename)) {
						continue // Those source names are already unconditionally excluded.
					}
					if result = add(filename, false); result != nil {
						return false
					}
				}
			}
			if selected.Module != nil {
				metadata := []string{selected.Module.GoMod}
				if selected.Module.Dir != "" {
					metadata = append(metadata, filepath.Join(selected.Module.Dir, "go.sum"))
				}
				for _, filename := range metadata {
					if filename != "" {
						if result = observeDirectories(filepath.Dir(filename)); result != nil {
							return false
						}
						stage.reserveInputName(filename, "metadata")
					}
					if result = add(filename, filepath.Base(filename) == "go.sum"); result != nil {
						return false
					}
				}
			}
			return true
		}, nil)
	}
	return result
}

func (stage *compileOutputStage) reserveInputName(filename, role string) {
	if stage.inputNameKeys == nil {
		stage.inputNameKeys = make(map[string]bool)
	}
	key := role + "\x00" + filename
	if !stage.inputNameKeys[key] {
		stage.inputNames = append(stage.inputNames, compileOutputInputName{filename, role})
		stage.inputNameKeys[key] = true
	}
}

func (stage *compileOutputStage) verifyInputDestination(destination string, previous os.FileInfo) error {
	conflict := stage.inputs[destination]
	// Exact observed identity covers an existing filesystem alias as well as
	// its spelling. Never use case folding to guess a case-insensitive route.
	// An existing hard-linked input is conservatively not an output resource.
	if previous != nil {
		for _, input := range stage.inputNodes {
			conflict = conflict || os.SameFile(previous, input.target)
		}
	}
	if conflict {
		return fmt.Errorf("compile output would replace or remove an original input: %s", destination)
	}
	for _, name := range stage.inputNames {
		// This is a conservative output-name policy for known original
		// metadata/search roles, not a claim that case-equivalent paths are
		// equal. Only a proved same actual parent can create this conflict.
		if !strings.EqualFold(filepath.Base(destination), filepath.Base(name.path)) {
			continue
		}
		parent, err := sourcepath.Resolve(filepath.Dir(name.path))
		if os.IsNotExist(err) {
			continue // The already existing output parent cannot be this directory.
		}
		if err != nil {
			return err
		}
		inputParent, err := sourcepath.Lstat(parent)
		if err != nil {
			return err
		}
		outputParent, err := sourcepath.Lstat(filepath.Dir(destination))
		if err != nil {
			return err
		}
		if os.SameFile(inputParent, outputParent) {
			return fmt.Errorf("potential %s-name collision with original input: %s", name.role, destination)
		}
	}
	return nil
}

func compileCPPInputFiles(feature *featureConsumer, inputs map[string]string) ([]string, error) {
	var files []string
	for name := range inputs {
		role, relative, found := strings.Cut(name, "/")
		if !found || !filepath.IsLocal(filepath.FromSlash(relative)) {
			return nil, fmt.Errorf("compile CPP input has an invalid producer name")
		}
		switch role {
		case "module":
			files = append(files, filepath.Join(feature.Dir, filepath.FromSlash(relative)))
		case "tool":
			files = append(files, filepath.Join(feature.Root, filepath.FromSlash(relative)))
		case "generated":
			// The actual generated-header producer returns memory, not a
			// physical file; it cannot be replaced by an artifact rename.
		default:
			return nil, fmt.Errorf("compile CPP input has an unknown producer role")
		}
	}
	return files, nil
}
