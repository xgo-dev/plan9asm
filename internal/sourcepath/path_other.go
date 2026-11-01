//go:build !windows

// Package sourcepath resolves filesystem paths used for source/tool identity.
// Resolution alone does not establish containment, ownership or a stable lease.
package sourcepath

import "path/filepath"

func Resolve(name string) (string, error) {
	return filepath.EvalSymlinks(name)
}
