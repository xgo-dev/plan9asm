package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// VerifyTestModuleGoModMetadata binds actual Go Module.GoMod to the independent
// exact-version download. Paths are private observations, not portable proof
// fields. The source-root/ZIP verifier remains separately mandatory.
func VerifyTestModuleGoModMetadata(source TestModuleSource, root, actual, downloaded string) error {
	if err := ValidateTestModuleSource(source); err != nil {
		return err
	}
	if source.SourceModule == "" {
		return fmt.Errorf("stdlib cannot acquire proxy/module metadata")
	}
	canonical := func(filename string) (string, error) {
		info, err := os.Lstat(filename)
		if err != nil || !filepath.IsAbs(filename) || !info.Mode().IsRegular() {
			return "", fmt.Errorf("actual dependency metadata is not a regular absolute source")
		}
		resolved, err := sourcepath.Resolve(filename)
		if err != nil {
			return "", fmt.Errorf("actual dependency metadata is missing or redirected")
		}
		digest, err := FileSHA256(resolved)
		if err != nil || digest != source.GoModSHA256 {
			return "", fmt.Errorf("actual dependency metadata differs from its authenticated origin")
		}
		return resolved, nil
	}
	actualPath, err := canonical(actual)
	if err != nil {
		return err
	}
	downloadPath, err := canonical(downloaded)
	if err != nil {
		return err
	}
	if source.GoModOrigin == ProxyGoModProtocol {
		if actualPath != downloadPath {
			return fmt.Errorf("actual dependency proxy metadata uses a different exact download path")
		}
		relative, err := filepath.Rel(root, downloadPath)
		withinRoot := relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
		if err != nil || withinRoot {
			return fmt.Errorf("proxy metadata must remain outside original ZIP source root")
		}
	}
	return nil
}
