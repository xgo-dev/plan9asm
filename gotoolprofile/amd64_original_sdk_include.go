package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/xgo-dev/plan9asm"
)

// Retain an overapproximation of physical include sources, not a CPP
// expansion. Every selected SDK assembly uses cmd/asm's fixed package CWD.
// Literal includes in both conditional branches remain guarded; unclosed
// dynamic directives fail. Actual Go independently compiles the final export.
func captureAMD64SDKIncludeSources(pkg amd64OriginalListPackage, goRoot string, files *amd64OriginalObservationFiles) error {
	var pending []string
	scheduled := make(map[string]bool)
	enqueue := func(name string) error {
		if scheduled[name] {
			return nil
		}
		if len(scheduled) >= 4096 {
			return fmt.Errorf("SDK include source closure exceeds its file bound")
		}
		scheduled[name] = true
		pending = append(pending, name)
		return nil
	}
	for _, file := range pkg.SFiles {
		if err := enqueue(filepath.Join(pkg.Dir, file)); err != nil {
			return err
		}
	}
	bytes := 0
	for len(pending) != 0 {
		name := pending[0]
		pending = pending[1:]
		data, err := files.snapshot.ReadRetained(name)
		if err != nil {
			return err
		}
		bytes += len(data)
		if bytes > 16<<20 {
			return fmt.Errorf("SDK include source closure exceeds its byte bound")
		}
		inventory, err := plan9asm.InspectAssemblyCPPSource(string(data), name, nil)
		if err != nil {
			return fmt.Errorf("SDK physical CPP source cannot be closed: %w", err)
		}
		for _, record := range inventory.Records {
			tokens := record.Tokens
			for index, token := range tokens {
				if token.Text == "#" && (index != 0 || record.Kind != "directive") {
					return fmt.Errorf("SDK macro-generated directive has no closed include-source role")
				}
			}
			if len(tokens) < 2 || tokens[0].Text != "#" || tokens[1].Text != "include" {
				continue
			}
			if len(tokens) != 4 || tokens[2].Kind != "string" ||
				tokens[3].Kind != "newline" && tokens[3].Kind != "eof" {
				return fmt.Errorf("SDK nonliteral include has no closed source role")
			}
			include, err := strconv.Unquote(tokens[2].Text)
			if err != nil {
				return err
			}
			included, err := retainAMD64SDKInclude(pkg, goRoot, include, files)
			if err != nil {
				return fmt.Errorf("SDK include %q in %s: %w", include, name, err)
			}
			if included != "" {
				if err := enqueue(included); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func retainAMD64SDKInclude(pkg amd64OriginalListPackage, goRoot, include string, files *amd64OriginalObservationFiles) (string, error) {
	// cmd/asm searches from the package CWD even for nested headers. The
	// selected source supplies that directory, not the including header.
	assembly := filepath.ToSlash(filepath.Join("src", pkg.ImportPath, pkg.SFiles[0]))
	preferred, shared, err := CPPIncludeCandidates(assembly, include)
	if err != nil || !CPPLocalSource(preferred) || !CPPLocalSource(shared) {
		return "", fmt.Errorf("SDK include escapes its actual source root")
	}
	name := filepath.Join(goRoot, filepath.FromSlash(preferred))
	if err := files.directory(filepath.Dir(name), false); err != nil {
		return "", fmt.Errorf("SDK preferred include directory is not closed: %w", err)
	}
	if _, err := os.Lstat(name); os.IsNotExist(err) {
		// Only this exact compiler-generated header may lack a physical
		// SDK file. Its properties come from the complete original Go
		// sources/tools and actual export, never a fabricated CPP header.
		if include == "go_asm.h" {
			return "", nil
		}
		name, err = CPPRegularSource(goRoot, shared)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else {
		name, err = CPPRegularSource(goRoot, preferred)
		if err != nil {
			return "", err
		}
	}
	if err := files.directory(filepath.Dir(name), false); err != nil {
		return "", err
	}
	if err := files.retain(name); err != nil {
		return "", err
	}
	return name, nil
}
