package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This identity belongs only to the temporary native analyzer invocation. It
// is not a source/ABI capability and cannot be supplied through a public proof.
type instrumentationAsmdeclWorkspace struct {
	name     string
	physical string
	identity os.FileInfo
}

func (owned *instrumentationAsmdeclWorkspace) verify() error {
	if owned == nil || owned.identity == nil || !owned.identity.IsDir() {
		return fmt.Errorf("ordinary asmdecl lacks its created directory identity")
	}
	actual, err := os.Lstat(owned.name)
	if err != nil || !actual.IsDir() || actual.Mode()&os.ModeSymlink != 0 || !os.SameFile(owned.identity, actual) {
		return fmt.Errorf("ordinary asmdecl owned directory was removed or replaced: %v", err)
	}
	physical, err := sourcepath.Resolve(owned.name)
	if err != nil || physical != owned.physical {
		return fmt.Errorf("ordinary asmdecl owned directory alias changed: %v", err)
	}
	return nil
}

func (owned *instrumentationAsmdeclWorkspace) verifyConfig() error {
	if err := owned.verify(); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Join(owned.name, "ordinary.cfg"))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("ordinary asmdecl configuration is absent or redirected: %v", err)
	}
	return nil
}

func (owned *instrumentationAsmdeclWorkspace) close(remove func(string) error) error {
	if err := owned.verify(); err != nil {
		return err // never delete a replacement or an unproved alias target
	}
	if remove == nil {
		return fmt.Errorf("ordinary asmdecl lacks its owned cleanup operation")
	}
	if err := remove(owned.name); err != nil {
		return fmt.Errorf("ordinary asmdecl owned directory cleanup failed: %w", err)
	}
	if _, err := os.Lstat(owned.name); !os.IsNotExist(err) {
		return fmt.Errorf("ordinary asmdecl owned directory cleanup did not complete: %v", err)
	}
	return nil
}
