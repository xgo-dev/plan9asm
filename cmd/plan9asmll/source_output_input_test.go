package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestCompileOutputRejectsSourceExtensionCaseVariants(t *testing.T) {
	for _, extension := range []string{".go", ".GO", ".Go", ".s", ".S", ".h", ".H"} {
		t.Run(extension, func(t *testing.T) {
			stage, task := compileOutputFixture(t, false)
			output := filepath.Join(filepath.Dir(task.OutLL), "original"+extension)
			if _, err := stage.stageTask(asmTask{OutLL: output}, compileConfig{}); err == nil {
				t.Fatal("reserved source extension became an output resource", output)
			}
		})
	}
}

func TestCompileOneOutputCannotReplaceCaseVariantSelectedGoSource(t *testing.T) {
	pkg, input := continuationPackage(t, continuationGo, continuationAsm)
	if len(pkg.GoFiles) != 1 {
		t.Fatalf("unexpected actual selected Go source inventory: %v", pkg.GoFiles)
	}
	selected := pkg.GoFiles[0]
	original, err := os.ReadFile(selected)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(filepath.Dir(selected), strings.ToUpper(filepath.Base(selected)))
	config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
	if err == nil {
		t.Fatal("case-variant Go source name became an output resource")
	}
	if after, err := os.ReadFile(selected); err != nil || string(after) != string(original) {
		t.Fatalf("actual selected Go source was overwritten: %v", err)
	}
}

func TestCompileOneOutputCannotReplaceOriginalModuleMetadata(t *testing.T) {
	for _, name := range []string{"go.mod", "go.sum"} {
		t.Run(name, func(t *testing.T) {
			pkg, input := continuationPackage(t, continuationGo, continuationAsm)
			output := filepath.Join(pkg.Dir, name)
			if name == "go.sum" {
				if err := os.WriteFile(output, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			original, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
			if err == nil {
				t.Error("successful artifact publication overwrote original module metadata")
			}
			if after, err := os.ReadFile(output); err != nil || string(after) != string(original) {
				t.Fatalf("original module metadata was changed: %q, %v", after, err)
			}
		})
	}
}

func TestCompileOneOutputCannotCreateAbsentMetadataAlias(t *testing.T) {
	pkg, selected := continuationPackage(t, continuationGo, continuationAsm)
	module, err := os.Stat(filepath.Join(pkg.Dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	alias, aliasErr := os.Stat(filepath.Join(pkg.Dir, "GO.MOD"))
	if aliasErr != nil && !os.IsNotExist(aliasErr) {
		t.Fatal(aliasErr)
	}
	caseInsensitive := aliasErr == nil && os.SameFile(module, alias)
	t.Logf("actual existing metadata case alias observed: %v", caseInsensitive)
	missing := filepath.Join(pkg.Dir, "go.sum")
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("fixture metadata was not absent: %v", err)
	}
	output := filepath.Join(pkg.Dir, "GO.SUM")
	config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	err = compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: selected, OutLL: output}, false, config)
	// Even a case-sensitive filesystem keeps a known same-parent metadata
	// basename out of the artifact namespace. This is an explicit conservative
	// potential-collision policy, not a claim that the names are OS-equal.
	if err == nil || !strings.Contains(err.Error(), "potential metadata-name collision") {
		t.Fatalf("known missing metadata basename became an output role: %v", err)
	}
	for _, path := range []string{missing, output} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("original missing metadata/output changed: %v", err)
		}
	}
}

func TestCompileOutputMetadataNameProtectionUsesActualParent(t *testing.T) {
	for _, placement := range []string{"same-parent", "directory-alias", "distinct-parent"} {
		t.Run(placement, func(t *testing.T) {
			stage, task := compileOutputFixture(t, false)
			root := filepath.Dir(task.OutLL)
			goMod := filepath.Join(root, "go.mod")
			if err := os.WriteFile(goMod, []byte("original module metadata\n"), 0600); err != nil {
				t.Fatal(err)
			}
			pkg := &packages.Package{Module: &packages.Module{Dir: root, GoMod: goMod}}
			if err := stage.protectInputs(pkg, nil, nil); err != nil {
				t.Fatal(err)
			}
			parent := root
			if placement == "directory-alias" {
				parent = filepath.Join(t.TempDir(), "output-parent")
				ordinaryLoadDirectoryAlias(t, parent, root)
			} else if placement == "distinct-parent" {
				parent = t.TempDir()
			}
			_, err := stage.stageTask(asmTask{OutLL: filepath.Join(parent, "GO.SUM")}, compileConfig{})
			if placement == "distinct-parent" {
				if err != nil {
					t.Fatalf("independent actual parent acquired a metadata-name restriction: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "potential metadata-name collision") {
				t.Fatalf("same actual parent metadata spelling was not excluded: %v", err)
			}
		})
	}
}

func TestCompileOneOutputCannotReplaceActualSelectedEmbed(t *testing.T) {
	for _, extension := range []string{"ll", "o"} {
		t.Run(extension, func(t *testing.T) {
			const retained = "original actual Go embed contents\n"
			name := "published." + extension
			source := strings.Replace(continuationGo, "package p\n", "package p\nimport _ \"embed\"\n//go:embed "+name+"\nvar image string\n", 1)
			pkg, selected := continuationPackageWithSources(t, source, continuationAsm, map[string]string{name: retained})
			if pkg.Types.Scope().Lookup("image") == nil {
				t.Fatal("actual complete Go loader did not typecheck the embedding source")
			}
			if len(pkg.EmbedFiles) != 1 || filepath.Base(pkg.EmbedFiles[0]) != name {
				t.Fatalf("actual compiler selected embed inventory was not retained: %v", pkg.EmbedFiles)
			}
			config := compileConfig{Context: arm64PrivateCLIContext(t),
				x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			if extension == "o" {
				var err error
				config, err = resolveCompileConfig(true, "", false, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.Context = arm64PrivateCLIContext(t)
				config.x86CallerSelections = captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)
			}
			output := filepath.Join(pkg.Dir, "published.ll")
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: selected, OutLL: output}, false, config)
			if err == nil {
				t.Error("artifact publication overwrote/deleted actual Go embed input")
			}
			if data, err := os.ReadFile(filepath.Join(pkg.Dir, name)); err != nil || string(data) != retained {
				t.Fatalf("actual Go embed input changed: %q %v", data, err)
			}
		})
	}
}

func TestCompileOneLateSelectedEmbedReplacementDoesNotPublish(t *testing.T) {
	const original = "actual original embedded bytes\n"
	source := strings.Replace(continuationGo, "package p\n", "package p\nimport _ \"embed\"\n//go:embed image.bin\nvar image string\n", 1)
	pkg, selected := continuationPackageWithSources(t, source, continuationAsm, map[string]string{"image.bin": original})
	if len(pkg.EmbedFiles) != 1 || filepath.Base(pkg.EmbedFiles[0]) != "image.bin" {
		t.Fatalf("actual selected embed was not retained: %v", pkg.EmbedFiles)
	}
	output := filepath.Join(pkg.Dir, "published.ll")
	const previous = "previous verified output\n"
	if err := os.WriteFile(output, []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	ctx := &continuationOutputCallbackContext{Context: context.Background(), directory: pkg.Dir, basename: filepath.Base(output)}
	ctx.callback = func() {
		called = true
		filename := pkg.EmbedFiles[0]
		if err := os.Rename(filename, filename+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := compileConfig{Context: ctx, x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: selected, OutLL: output}, false, config)
	if !called || err == nil || !strings.Contains(err.Error(), "compile input") {
		t.Fatalf("same-byte late embedded input replacement was ignored: called=%v error=%v", called, err)
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != previous {
		t.Fatalf("late embedded input replacement published output: %q %v", data, err)
	}
}

func TestCompileOutputInputDirectoryAliasLifetime(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	owner := t.TempDir()
	actual := filepath.Join(owner, "actual.inc")
	if err := os.WriteFile(actual, []byte("original input"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "include-owner")
	ordinaryLoadDirectoryAlias(t, alias, owner)
	if err := stage.protectInputs(nil, []string{filepath.Join(alias, "actual.inc")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(alias, alias+".original"); err != nil {
		t.Fatal(err)
	}
	ordinaryLoadDirectoryAlias(t, alias, owner) // Same target and bytes, new requested node.
	if err := stage.publish(); err == nil || stage.committed {
		t.Fatal("equal-target replacement of the original input directory alias was ignored")
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputRechecksOriginalInputsDuringPublication(t *testing.T) {
	stage, task := compileOutputFixture(t, true)
	root := filepath.Dir(task.OutLL)
	actual, alias := filepath.Join(root, "actual.inc"), filepath.Join(root, "requested.inc")
	if err := os.WriteFile(actual, []byte("previous output.o"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	if err := stage.protectInputs(nil, []string{alias, actual}, nil); err != nil {
		t.Fatal(err)
	}
	first, second := &stage.outputs[0], &stage.outputs[1]
	called := false
	stage.rename = func(from, to string) error {
		if from == first.path && to == first.destination && !called {
			called = true
			if err := os.Rename(alias, alias+".original"); err != nil {
				return err
			}
			if err := os.Symlink(second.destination, alias); err != nil {
				return err
			}
		}
		return os.Rename(from, to)
	}
	if err := stage.publish(); !called || err == nil || stage.committed {
		t.Fatalf("later output overwrote a newly redirected original input: called=%v error=%v", called, err)
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputInputIdentityExcludesEquivalentExistingName(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	input := filepath.Join(filepath.Dir(task.OutLL), "actually-read.inc")
	if err := os.Link(task.OutLL, input); err != nil {
		t.Fatal(err)
	}
	if err := stage.protectInputs(nil, []string{input}, nil); err != nil {
		t.Fatal(err)
	}
	if err := stage.publish(); err == nil || stage.committed {
		t.Fatal("same actual input identity was accepted as an existing output resource")
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputInputProtectionAccumulatesAttemptMembers(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	first, second := filepath.Join(filepath.Dir(task.OutLL), "first.inc"), filepath.Join(filepath.Dir(task.OutLL), "second.inc")
	for _, filename := range []string{first, second} {
		if err := os.WriteFile(filename, []byte("actual include"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := stage.protectInputs(nil, []string{filename}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stage.stageTask(asmTask{OutLL: first}, compileConfig{}); err == nil {
		t.Fatal("a later chunk's input observation erased an earlier task's exclusion")
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputSuccessfullyReadInputCannotBecomeMissingRole(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	input := filepath.Join(filepath.Dir(task.OutLL), "original.inc")
	if err := os.WriteFile(input, []byte("actually read input"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(input); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	if err := stage.protectInputs(nil, []string{input}, nil); err == nil {
		t.Fatal("successfully read original input was reclassified as absent metadata")
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputInputAliasLifetime(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	root := filepath.Dir(task.OutLL)
	actual := filepath.Join(root, "actual.inc")
	alias := filepath.Join(root, "requested.inc")
	// Byte-identical to the unchanged, already observed public destination.
	const retained = "previous output.ll"
	if err := os.WriteFile(actual, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	if err := stage.protectInputs(nil, []string{alias, actual}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(alias, alias+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(task.OutLL, alias); err != nil {
		t.Fatal(err)
	}
	if err := stage.publish(); err == nil || stage.committed {
		t.Fatal("redirected input acquired an earlier allowed output destination")
	}
	requirePreviousCompileOutputs(t, task)
}

func TestCompileOutputSearchMissProtection(t *testing.T) {
	for _, change := range []string{"new-preferred", "nested-preferred", "redirect-parent", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixtureWithConfig(t, compileConfig{Enabled: true, KeepObj: false})
			root := filepath.Dir(task.OutLL)
			miss := filepath.Join(root, "fallback.inc")
			if change == "nested-preferred" {
				miss = filepath.Join(root, "missing", "fallback.inc")
			} else if change == "redirect-parent" {
				alias := filepath.Join(t.TempDir(), "include-root")
				ordinaryLoadDirectoryAlias(t, alias, root)
				miss = filepath.Join(alias, "fallback.inc")
			}
			if err := stage.protectInputs(nil, nil, []string{miss}); err != nil {
				t.Fatal(err)
			}
			if change == "unchanged" {
				if err := stage.publish(); err != nil || !stage.committed {
					t.Fatalf("unchanged fallback search incorrectly prevented output: %v", err)
				}
				return
			}
			if change == "new-preferred" || change == "nested-preferred" {
				if err := os.MkdirAll(filepath.Dir(miss), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(miss, []byte("same fallback bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if change == "redirect-parent" {
				alias := filepath.Dir(miss)
				if err := os.Rename(alias, alias+".original"); err != nil {
					t.Fatal(err)
				}
				ordinaryLoadDirectoryAlias(t, alias, t.TempDir())
			}
			if err := stage.publish(); err == nil || stage.committed {
				t.Fatal("changed preferred include search was ignored at publication")
			}
			requirePreviousCompileOutputs(t, task)
		})
	}
}

func TestCompileOutputSearchMissCannotBePublicDestination(t *testing.T) {
	for _, test := range []struct {
		object, alternateCase bool
		name                  string
	}{
		{name: "ir"}, {object: true, name: "nonretained-object"},
		{alternateCase: true, name: "ir-potential-case-alias"},
		{object: true, alternateCase: true, name: "object-potential-case-alias"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			task := asmTask{OutLL: filepath.Join(root, "output.ll")}
			stage, err := newCompileOutputStage(task, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := stage.close(); err != nil {
					t.Error(err)
				}
			})
			miss := task.OutLL
			if test.object {
				miss = filepath.Join(root, "output.o")
			}
			if test.alternateCase {
				miss = filepath.Join(root, strings.ToUpper(filepath.Base(miss)))
			}
			if err := stage.protectInputs(nil, nil, []string{miss}); err != nil {
				t.Fatal(err)
			}
			if _, err := stage.stageTask(task, compileConfig{Enabled: test.object, KeepObj: false}); err == nil {
				t.Fatal("publication could create/remove the preferred missing input")
			}
			if _, err := os.Lstat(miss); !os.IsNotExist(err) {
				t.Fatalf("preferred missing input was changed: %v", err)
			}
		})
	}
}

func TestCompileOneLateEqualByteIncludeRedirectDoesNotPublish(t *testing.T) {
	for _, change := range []string{"redirect-output", "same-byte-node"} {
		t.Run(change, func(t *testing.T) {
			const retained = "// byte-identical original include and prior output\n"
			pkg, selected := continuationPackageWithSources(t, continuationGo, "#include \"requested.inc\"\n"+continuationAsm,
				map[string]string{"actual.inc": retained})
			include := filepath.Join(pkg.Dir, "requested.inc")
			actual := filepath.Join(pkg.Dir, "actual.inc")
			if err := os.Symlink(actual, include); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(pkg.Dir, "published.ll")
			if err := os.WriteFile(output, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			ctx := &continuationOutputCallbackContext{Context: context.Background(), directory: pkg.Dir, basename: filepath.Base(output)}
			ctx.callback = func() {
				called = true
				if change == "redirect-output" {
					if err := os.Rename(include, include+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(output, include); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Rename(actual, actual+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(actual, []byte(retained), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			config := compileConfig{Context: ctx, x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: selected, OutLL: output}, false, config)
			if !called || err == nil || !strings.Contains(err.Error(), "compile input") {
				t.Fatalf("equal-byte final input mutation was ignored: called=%v error=%v", called, err)
			}
			if data, err := os.ReadFile(output); err != nil || string(data) != retained {
				t.Fatalf("input redirect changed old public output: %q %v", data, err)
			}
		})
	}
}

func TestCompileOneTaskBuilderOutputCannotReplaceActualInclude(t *testing.T) {
	for _, extension := range []string{"ll", "o"} {
		for _, aliasOutput := range []bool{false, true} {
			name := extension + "/physical"
			if aliasOutput {
				name = extension + "/directory-alias"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				const packagePath = "example.com/collision"
				directory := filepath.Join(root, filepath.FromSlash(packagePath))
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				include := "kernel_amd64.s." + extension
				const original = "#define BIAS 7\n"
				assembly := "#include \"" + include + "\"\n" + strings.Replace(x86CallerCLIAssembly, "ADDL $7,AX", "ADDL $BIAS,AX", 1)
				for filename, data := range map[string]string{
					"go.mod": "module " + packagePath + "\n\ngo 1.20\n", "caller.go": x86CallerCLISource,
					"kernel_amd64.s": assembly, include: original,
				} {
					if err := os.WriteFile(filepath.Join(directory, filename), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Chdir(directory)
				t.Setenv("GOENV", "off")
				t.Setenv("GOWORK", "off")
				t.Setenv("GOTOOLCHAIN", "local")
				t.Setenv("CGO_ENABLED", "0")
				t.Setenv("GOFLAGS", "")
				selected, err := loadPkgs("linux", "amd64", []string{"."}, nil, packagePath, true, false)
				if err != nil || len(selected) != 1 || len(selected[0].Errors) != 0 {
					t.Fatalf("complete actual Go source selection: %v", err)
				}
				outputRoot := root
				if aliasOutput {
					outputRoot = filepath.Join(t.TempDir(), "output-root")
					ordinaryLoadDirectoryAlias(t, outputRoot, root)
				}
				tasks, _ := collectAsmTasks(selected, outputRoot, nil)
				if len(tasks) != 1 || filepath.Base(tasks[0].OutLL) != "kernel_amd64.s.ll" {
					t.Fatalf("original public task builder did not select complete source: %+v", tasks)
				}
				config := compileConfig{Context: arm64PrivateCLIContext(t),
					x86CallerSelections: captureX86CallerSelections(selected, "linux/amd64", nil)}
				if extension == "o" {
					config, err = resolveCompileConfig(true, "", false, 0)
					if err != nil {
						t.Fatal(err)
					}
					config.Context = arm64PrivateCLIContext(t)
					config.x86CallerSelections = captureX86CallerSelections(selected, "linux/amd64", nil)
				}
				err = compileOne(selected[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu", tasks[0], false, config)
				if err == nil {
					t.Error("public task publication replaced/deleted original assembler include")
				}
				if after, err := os.ReadFile(filepath.Join(directory, include)); err != nil || string(after) != original {
					t.Fatalf("actual include was replaced/deleted: %q %v", after, err)
				}
			})
		}
	}
}
