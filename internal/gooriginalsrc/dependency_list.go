package gooriginalsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
)

// DependencyListRunner executes an actual bounded stock-Go command. It is an
// IO seam only: output still needs independent exact source/export observation.
type DependencyListRunner func(directory string, args []string) (stdout, stderr []byte, err error)

// RunDependencyList prepares only private module metadata, then independently
// repeats the requested query read-only. Preparatory output is never evidence
// for a compiler export, assembly acceptance or a source exclusion.
func RunDependencyList(ctx context.Context, temporary, path, version string, args []string, run DependencyListRunner) ([]byte, error) {
	if len(args) < 2 || len(args) > 7 || args[0] != "list" || run == nil {
		return nil, fmt.Errorf("exact dependency query needs a bounded list command")
	}
	selected := args[len(args)-1]
	if module.CheckImportPath(selected) != nil || selected != path && !strings.HasPrefix(selected, path+"/") {
		return nil, fmt.Errorf("dependency query escaped its exact primary package namespace")
	}
	seen := make(map[string]bool)
	for _, argument := range args[1 : len(args)-1] {
		switch argument {
		case "-deps", "-compiled", "-export", "-json", "-mod=readonly":
		default:
			return nil, fmt.Errorf("unregistered dependency query argument %q", argument)
		}
		if seen[argument] {
			return nil, fmt.Errorf("repeated dependency query argument %q", argument)
		}
		seen[argument] = true
	}
	if !seen["-json"] || !seen["-mod=readonly"] {
		return nil, fmt.Errorf("dependency query omitted its complete read-only JSON role")
	}
	prepared, readonly := []string{"list", "-mod=mod"}, []string{"list", "-mod=readonly"}
	for _, argument := range args[1:] {
		if strings.HasPrefix(argument, "-mod=") {
			continue
		}
		readonly = append(readonly, argument)
		if argument != "-export" {
			prepared = append(prepared, argument)
		}
	}
	return RunDependencyQuery(ctx, temporary, path, version, func(directory string) ([]byte, error) {
		_, diagnostic, err := run(directory, prepared)
		if err != nil {
			return nil, fmt.Errorf("prepare exact dependency query: %w; %s", err, diagnostic)
		}
		if err := dependencyPreparationDiagnostics(diagnostic); err != nil {
			return nil, err
		}
		entries, _, err := ReadDirectory(directory, 2)
		if err != nil {
			return nil, err
		}
		snapshot := NewSnapshot()
		if err := snapshot.Directory(directory, false); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.Name() != "go.mod" && entry.Name() != "go.sum" {
				return nil, fmt.Errorf("dependency preparation created a foreign file")
			}
			file := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(file)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
				return nil, errors.Join(fmt.Errorf("dependency preparation metadata is redirected or over-bound"), err)
			}
			if err := snapshot.Retain(file); err != nil {
				return nil, err
			}
		}
		data, err := snapshot.ReadRetained(filepath.Join(directory, "go.mod"))
		if err != nil {
			return nil, err
		}
		if err := validateDependencyQueryMetadata(data, path, version); err != nil {
			return nil, err
		}
		output, diagnostic, err := run(directory, readonly)
		if len(diagnostic) != 0 {
			err = errors.Join(err, fmt.Errorf("read-only dependency query diagnostics: %s", diagnostic))
		}
		return output, errors.Join(err, snapshot.Verify())
	})
}

// These are cmd/go's module-resolution progress messages (modload/import.go,
// modload/load.go and modfetch/fetch.go), never assembler rejection evidence.
// Unknown diagnostics, nonzero commands and cleanup failures remain errors.
func dependencyPreparationDiagnostics(data []byte) error {
	if len(data) > 64<<10 {
		return fmt.Errorf("dependency preparation diagnostics exceed their bound")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" && len(data) == 0 {
			return nil
		}
		fields := strings.Fields(line)
		valid := false
		switch {
		case len(fields) == 4 && fields[0] == "go:" && fields[1] == "downloading":
			valid = module.Check(fields[2], fields[3]) == nil
		case len(fields) == 6 && strings.HasPrefix(line, "go: finding module for package "):
			valid = module.CheckImportPath(fields[5]) == nil
		case len(fields) == 6 && fields[0] == "go:" && fields[1] == "found" && fields[3] == "in":
			valid = module.CheckImportPath(fields[2]) == nil && module.Check(fields[4], fields[5]) == nil
		}
		if !valid {
			return fmt.Errorf("unregistered dependency preparation diagnostic: %s", line)
		}
	}
	return nil
}
