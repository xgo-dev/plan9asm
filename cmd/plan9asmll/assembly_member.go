package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// actualAssemblyMember joins a request to one already selected source. It does
// not alter the compiler inventory or grant a declaration/body permission.
type actualAssemblyMember struct {
	self          *actualAssemblyMember
	requested     string
	selected      string
	physical      string
	file          os.FileInfo
	requestedNode os.FileInfo
	selectedNode  os.FileInfo
	directories   []assemblyMemberDirectory
	revoked       atomic.Bool
}

type assemblyMemberDirectory struct {
	path     string
	physical string
	info     os.FileInfo
}

func actualAssemblyMemberError() error {
	return fmt.Errorf("%w: missing, redirected, or ambiguous actual selected assembly member", plan9asm.ErrProbeNeedsContext)
}

func observeActualAssemblyMember(requested string, selected []string) (*actualAssemblyMember, error) {
	// The consuming ARM64 actual-load role already bounds OtherFiles at 512.
	if requested == "" || filepath.Ext(requested) != ".s" || len(selected) > 512 {
		return nil, actualAssemblyMemberError()
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return nil, actualAssemblyMemberError()
	}
	info, err := sourcepath.Lstat(abs)
	if err != nil {
		return nil, actualAssemblyMemberError()
	}
	physical, err := sourcepath.Resolve(abs)
	if err != nil {
		return nil, actualAssemblyMemberError()
	}
	targetInfo, err := sourcepath.Lstat(physical)
	if err != nil || !targetInfo.Mode().IsRegular() {
		return nil, actualAssemblyMemberError()
	}
	member := &actualAssemblyMember{requested: abs, physical: physical, file: targetInfo, requestedNode: info}
	for _, filename := range selected {
		if filepath.Ext(filename) != ".s" {
			continue
		}
		resolved, err := sourcepath.Resolve(filename)
		if err != nil {
			return nil, actualAssemblyMemberError()
		}
		if resolved != physical {
			continue
		}
		selectedInfo, err := sourcepath.Lstat(filename)
		if err != nil || member.selected != "" {
			return nil, actualAssemblyMemberError()
		}
		member.selected = filename // Retain the exact compiler-inventory key.
		member.selectedNode = selectedInfo
	}
	if member.selected == "" {
		return nil, actualAssemblyMemberError()
	}
	seen := make(map[string]bool)
	for _, filename := range []string{abs, member.selected} {
		for directory := filepath.Dir(filename); ; directory = filepath.Dir(directory) {
			if !seen[directory] {
				if len(member.directories) >= 512 {
					return nil, actualAssemblyMemberError()
				}
				info, err := sourcepath.Lstat(directory)
				if err != nil {
					return nil, actualAssemblyMemberError()
				}
				physical, err := sourcepath.Resolve(directory)
				if err != nil {
					return nil, actualAssemblyMemberError()
				}
				resolvedInfo, err := sourcepath.Lstat(physical)
				if err != nil || !resolvedInfo.IsDir() {
					return nil, actualAssemblyMemberError()
				}
				member.directories = append(member.directories, assemblyMemberDirectory{directory, physical, info})
				seen[directory] = true
			}
			if filepath.Dir(directory) == directory {
				break
			}
		}
	}
	member.self = member
	if err := member.verify(); err != nil {
		return nil, err
	}
	return member, nil
}

func (member *actualAssemblyMember) verify() error {
	if member == nil || member.self != member || member.revoked.Load() {
		return actualAssemblyMemberError()
	}
	fail := func() error {
		member.revoked.Store(true)
		return actualAssemblyMemberError()
	}
	for index, filename := range []string{member.requested, member.selected} {
		physical, err := sourcepath.Resolve(filename)
		if err != nil || physical != member.physical {
			return fail()
		}
		info, err := sourcepath.Lstat(filename)
		node := member.requestedNode
		if index == 1 {
			node = member.selectedNode
		}
		if err != nil || !os.SameFile(info, node) {
			return fail()
		}
		info, err = sourcepath.Lstat(physical)
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, member.file) {
			return fail()
		}
	}
	for _, directory := range member.directories {
		info, err := sourcepath.Lstat(directory.path)
		if err != nil || !os.SameFile(info, directory.info) {
			return fail()
		}
		physical, err := sourcepath.Resolve(directory.path)
		if err != nil || physical != directory.physical {
			return fail()
		}
	}
	return nil
}
