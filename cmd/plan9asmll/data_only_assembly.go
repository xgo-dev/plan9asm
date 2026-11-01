package main

import (
	"fmt"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func proveDataOnlyAssembly(pkg *packages.Package, task asmTask, file *plan9asm.File, target string, defines []string, cfg compileConfig) (*gotoolprofile.DataOnlyAssemblyProof, error) {
	if file == nil || len(file.Funcs) != 0 || len(file.Globl) == 0 {
		return nil, fmt.Errorf("data-only source requires global declarations and no TEXT")
	}
	var symbols []gotoolprofile.DataOnlySymbol
	native, err := proveAssemblyListing(pkg, task, target, defines, cfg, func(listing []byte, version string) error {
		var err error
		symbols, err = gotoolprofile.DataOnlySymbolsFromListingForGoVersion(listing, version)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := gotoolprofile.ValidateDataOnlySourceSymbols(file, pkg.PkgPath, symbols); err != nil {
		return nil, err
	}
	native.Protocol = gotoolprofile.DataOnlyAssemblyProtocol
	return &gotoolprofile.DataOnlyAssemblyProof{Native: *native, Symbols: symbols}, nil
}

// cmd/asm qualifies local symbols with objabi.PathToPrefix, not the logical
// import path used by LLVM. Keep the original native listing spelling intact.
// This is Go's byte-level rule; URL escaping changes different characters.
func nativeGoPackagePrefix(packagePath string) string {
	return gotoolprofile.NativeGoPackagePrefix(packagePath)
}
