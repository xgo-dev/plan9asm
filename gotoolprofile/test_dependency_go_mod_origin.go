package gotoolprofile

import "fmt"

// The proxy role authenticates metadata outside the immutable archive. It
// never supplies a missing ZIP member or authorizes unrelated local sources.
func validateTestModuleGoModOrigin(source TestModuleSource) error {
	if source.SourceModule == "" {
		return nil // The stdlib role forbids all module fields in its caller.
	}
	switch source.GoModOrigin {
	case TestModuleOriginalGoModOrigin:
		if source.ProxyGoMod != nil || source.Sources["go.mod"] != source.GoModSHA256 {
			return fmt.Errorf("test dependency original go.mod lacks its exact ZIP source role")
		}
	case ProxyGoModProtocol:
		proof := source.ProxyGoMod
		if proof == nil || proof.Module != source.SourceModule || proof.Version != source.SourceVersion ||
			proof.ModuleSum != source.ModuleSum || proof.GoModSum != source.GoModSum || proof.SHA256 != source.GoModSHA256 {
			return fmt.Errorf("test dependency proxy metadata lacks its exact signed module/mod identity")
		}
		if _, present := source.Sources["go.mod"]; present {
			return fmt.Errorf("test dependency proxy metadata cannot impersonate original ZIP bytes")
		}
		if _, present := source.Headers["go.mod"]; present {
			return fmt.Errorf("test dependency proxy metadata cannot impersonate a source header")
		}
		for _, entry := range source.Directories["."] {
			if entry.Name == "go.mod" {
				return fmt.Errorf("test dependency proxy metadata conflicts with original directory membership")
			}
		}
		if err := ValidateProxyGoMod(proof); err != nil {
			return fmt.Errorf("authenticate test dependency proxy metadata: %w", err)
		}
	default:
		return fmt.Errorf("test dependency lacks a recognized mandatory go.mod origin")
	}
	return nil
}
