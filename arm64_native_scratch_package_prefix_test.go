package plan9asm

import "testing"

func TestARM64NativeScratchActualPackageSymbolNamespaces(t *testing.T) {
	llc, _, _ := findLlcAndClang(t)
	for _, packagePath := range []string{
		"example.invalid/plain",
		"example.invalid/with.dot",
		"gopkg.in/scratch.v3",
		"example.invalid/deep.with.dot/plain",
		"example.invalid/plain/deep.with.dot",
	} {
		t.Run(packagePath, func(t *testing.T) {
			_, pkg, file, options, source := arm64ScratchActualBoundSourceWithPackage(t,
				"linux", "aarch64-unknown-linux-gnu", arm64ScratchSelectedSource, packagePath)
			for _, name := range []string{"Scratch", "Value"} {
				logical := pkg.Path + "." + name
				if source.abis[logical] != "ABI0" || len(source.native[logical]) < 2 {
					t.Fatalf("actual package ABI and all original native bodies lost logical identity %q: ABI=%q bodies=%d",
						logical, source.abis[logical], len(source.native[logical]))
				}
			}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ScratchSourceAPI(t, pkg, file, options, api)
					if err != nil {
						t.Fatalf("actual stock-Go accepted package symbol identity prevented %s: %v", api, err)
					}
					compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "scratch.ll", "scratch.o", ir)
				})
			}
		})
	}
}

func TestARM64NativeScratchPackagePrefixMetadataIsNotAdmission(t *testing.T) {
	source := &GoARM64ScratchSource{
		packages: map[string]arm64ScratchPackage{
			"example.invalid/with.dot": {},
		},
	}
	for _, test := range []struct{ native, logical string }{
		{"example.invalid/with%2edot.Value", "example.invalid/with.dot.Value"},
		{"example.invalid/with%2edot.Value%2eOther", "example.invalid/with.dot.Value%2eOther"},
		{"example.invalid/with%2edot.Value<1>", "example.invalid/with.dot.Value<1>"},
		{"example.invalid/with%2Edot.Value", "example.invalid/with%2Edot.Value"},
		{"example.invalid/with%2edotish.Value", "example.invalid/with%2edotish.Value"},
		{"unknown/pkg%2edot.Value", "unknown/pkg%2edot.Value"},
		{`"".Value`, `"".Value`},
	} {
		t.Run(test.native, func(t *testing.T) {
			if actual := source.originalObjectCallTarget(test.native); actual != test.logical {
				t.Fatalf("native package projection = %q, want %q", actual, test.logical)
			}
			if len(source.closed) != 0 || len(source.abis) != 0 || len(source.native) != 0 || source.ready {
				t.Fatal("symbol metadata alone acquired a source, ABI, body or callee fact")
			}
		})
	}
}
