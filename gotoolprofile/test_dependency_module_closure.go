package gotoolprofile

import (
	"fmt"
	"strings"

	"golang.org/x/mod/module"
)

func testDependencySourceModules(input *ConsumerInput, dependency *TestDependencyProof) (map[string]TestModuleSource, error) {
	return sourceModuleSnapshots(input, dependency.SourceModules)
}

func sourceModuleSnapshots(input *ConsumerInput, sources []ModuleSourceSnapshot) (map[string]ModuleSourceSnapshot, error) {
	if len(sources) > 4096 {
		return nil, fmt.Errorf("test dependency source modules exceed their bounded scope")
	}
	modules := make(map[string]TestModuleSource)
	for index, source := range sources {
		if err := ValidateTestModuleSource(source); err != nil {
			return nil, err
		}
		id := source.ID()
		if index > 0 && id <= sources[index-1].ID() || source.SourceModule == "" && source.GoVersion != input.Observed.GoVersion {
			return nil, fmt.Errorf("test dependency source roots have noncanonical identities/tool versions")
		}
		modules[id] = source
	}
	return modules, nil
}

func testDependencyPackageInput(input *ConsumerInput, source TestSourcePackage, modules map[string]TestModuleSource) (*ConsumerInput, error) {
	pkg := source.Package
	builtin := source.Builtin == "go_typechecker_unsafe_v1"
	if source.Builtin != "" && (!builtin || pkg.PackagePath != "unsafe" || source.VariantID != "unsafe" ||
		pkg.SourceRole != "stdlib" || source.ExportSHA256 != "" || len(source.ImportMap) != 0 ||
		len(pkg.GoFiles) != 1 || pkg.GoFiles[0] != "unsafe/unsafe.go" || len(pkg.CompiledGoFiles) != 0 || len(pkg.SFiles) != 0) {
		return nil, fmt.Errorf("test dependency changed the actual unsafe typechecker/documentation role")
	}
	if source.SourceRootID == "" {
		if source.ExportSHA256 != "" || pkg.PackagePath != input.Module && !strings.HasPrefix(pkg.PackagePath, input.Module+"/") {
			return nil, fmt.Errorf("test dependency has a different actual original-module source role")
		}
		if err := ValidatePackageModule(input, pkg); err != nil {
			return nil, err
		}
		return input, nil
	}
	root, found := modules[source.SourceRootID]
	if !found || !builtin && !discoverySHA256Pattern.MatchString(source.ExportSHA256) || pkg.PackagePath == "unsafe" && !builtin {
		return nil, fmt.Errorf("test dependency lacks its actual foreign module/source/export boundary")
	}
	if pkg.ModulePath == input.Module {
		return nil, fmt.Errorf("foreign dependency impersonates original candidate")
	}
	if pkg.SourceRole == "stdlib" {
		if root.SourceModule != "" || pkg.ModulePath != "" || pkg.ModuleVersion != "" || pkg.SourceModule != "" || pkg.SourceVersion != "" ||
			pkg.GoModOrigin != "" || pkg.GoModSHA256 != "" || pkg.GoModSum != "" ||
			strings.Contains(strings.Split(pkg.PackagePath, "/")[0], ".") {
			return nil, fmt.Errorf("test dependency changed actual stdlib source/tool role")
		}
	} else if module.Check(pkg.ModulePath, pkg.ModuleVersion) != nil ||
		pkg.PackagePath != pkg.ModulePath && !strings.HasPrefix(pkg.PackagePath, pkg.ModulePath+"/") ||
		pkg.SourceModule != root.SourceModule || pkg.SourceVersion != root.SourceVersion ||
		pkg.GoModOrigin != root.GoModOrigin || pkg.GoModSHA256 != root.GoModSHA256 || pkg.GoModSum != root.GoModSum ||
		pkg.SourceRole != "module" && pkg.SourceRole != "version_replace" ||
		pkg.SourceRole == "module" && (pkg.SourceModule != pkg.ModulePath || pkg.SourceVersion != pkg.ModuleVersion) {
		return nil, fmt.Errorf("test dependency changed actual Module/Replace source identity")
	}
	view := *input
	view.Module, view.Version, view.SourceModule = pkg.ModulePath, pkg.ModuleVersion, pkg.SourceModule
	view.Sources, view.Headers = root.Sources, root.Headers
	view.Directories = make(map[string][]string)
	for dir, entries := range root.Directories {
		view.Directories[dir] = []string{}
		for _, entry := range entries {
			view.Directories[dir] = append(view.Directories[dir], entry.Name)
		}
	}
	return &view, nil
}
