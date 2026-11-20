package gooriginalsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const dependencyQueryModule = "example.invalid/plan9asm-original-query"

// RunDependencyQuery owns command configuration, not original source or frame
// authority. The caller still observes every selected exact original module.
// Only the actual bounded Go query may populate go.mod/go.sum in this private
// directory. It never writes to the selected archive or adopts ancestor files.
func RunDependencyQuery(ctx context.Context, temporary, path, version string, run func(string) ([]byte, error)) (_ []byte, result error) {
	if ctx == nil || run == nil || !filepath.IsAbs(temporary) ||
		module.Check(path, version) != nil || module.CanonicalVersion(version) != version || path == dependencyQueryModule {
		return nil, fmt.Errorf("invalid exact dependency query")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(temporary, "original-dependency-query-")
	if err != nil {
		return nil, err
	}
	identity, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	defer func() {
		result = errors.Join(result, closeDependencyQuery(directory, identity, path, version))
	}()
	physical, err := sourcepath.Resolve(directory)
	if err != nil {
		return nil, err
	}
	directory = physical
	name := filepath.Join(directory, "go.mod")
	data := "module " + dependencyQueryModule + "\ngo 1.20\nrequire " + path + " " + version + "\n"
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.WriteString(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return nil, err
	}
	output, err := run(directory)
	return output, errors.Join(err, ctx.Err())
}

func closeDependencyQuery(directory string, identity os.FileInfo, path, version string) error {
	info, statErr := os.Lstat(directory)
	if statErr != nil || identity == nil || !info.IsDir() || !os.SameFile(identity, info) {
		return errors.Join(fmt.Errorf("dependency query directory was redirected or replaced"), statErr)
	}
	entries, current, err := ReadDirectory(directory, 2)
	if err != nil || identity == nil || !os.SameFile(identity, current) {
		return errors.Join(fmt.Errorf("dependency query directory identity changed"), err)
	}
	if len(entries) == 0 {
		return errors.Join(fmt.Errorf("dependency query lost its metadata"), os.Remove(directory))
	}
	snapshot := NewSnapshot()
	if err := snapshot.Directory(directory, false); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "go.mod" && entry.Name() != "go.sum" {
			return fmt.Errorf("dependency query acquired foreign member %q", entry.Name())
		}
		name := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return errors.Join(fmt.Errorf("dependency query metadata is redirected or exceeds its bound"), err)
		}
		if err := snapshot.Retain(name); err != nil {
			return err
		}
	}
	data, err := snapshot.ReadRetained(filepath.Join(directory, "go.mod"))
	if err != nil {
		return err
	}
	if err := validateDependencyQueryMetadata(data, path, version); err != nil {
		return err
	}
	if err := snapshot.Verify(); err != nil {
		return err
	}
	// Never recursively remove an unexpected member or a replaced directory.
	// The bounded actual command has completed before any owned file is freed.
	for _, entry := range entries {
		if _, err := snapshot.ReadRetained(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	_, current, err = ReadDirectory(directory, 0)
	if err != nil || !os.SameFile(identity, current) {
		return errors.Join(fmt.Errorf("dependency query changed during cleanup"), err)
	}
	return os.Remove(directory)
}

func validateDependencyQueryMetadata(data []byte, path, version string) error {
	parsed, err := modfile.Parse("go.mod", data, nil)
	if err != nil || parsed.Module == nil || parsed.Module.Mod.Path != dependencyQueryModule ||
		len(parsed.Replace)+len(parsed.Exclude)+len(parsed.Retract) != 0 || len(parsed.Require) > 64 {
		return errors.Join(fmt.Errorf("dependency query lost its separate exact-module configuration"), err)
	}
	found := 0
	for _, requirement := range parsed.Require {
		if requirement.Mod.Path == path {
			if requirement.Mod.Version != version {
				return fmt.Errorf("dependency query changed its exact primary version")
			}
			found++
		}
	}
	if found != 1 {
		return fmt.Errorf("dependency query omitted or repeated its exact primary module")
	}
	return nil
}
