package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func compileOutputFixture(t *testing.T, objects bool) (*compileOutputStage, asmTask) {
	t.Helper()
	return compileOutputFixtureWithConfig(t, compileConfig{Enabled: objects, KeepObj: objects})
}

func compileOutputFixtureWithConfig(t *testing.T, config compileConfig) (*compileOutputStage, asmTask) {
	t.Helper()
	owner := t.TempDir()
	task := asmTask{OutLL: filepath.Join(owner, "output.ll")}
	for _, name := range []string{"output.ll", "output.o"} {
		if err := os.WriteFile(filepath.Join(owner, name), []byte("previous "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := newCompileOutputStage(task, &packages.Package{Dir: owner, Module: &packages.Module{Dir: owner}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.close(); err != nil {
			t.Error(err)
		}
	})
	staged, err := stage.stageTask(task, config)
	if err != nil {
		t.Fatal(err)
	}
	if outputPathWithin(stage.directory, owner) {
		t.Fatal("output stage entered complete source inventory")
	}
	for _, output := range stage.outputs {
		if output.deletion {
			continue
		}
		if err := os.WriteFile(output.path, []byte("new "+filepath.Base(output.destination)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if staged.OutLL == task.OutLL {
		t.Fatal("task did not receive private stage")
	}
	if err := stage.seal(); err != nil {
		t.Fatal(err)
	}
	return stage, task
}

func requirePreviousCompileOutputs(t *testing.T, task asmTask) {
	t.Helper()
	for _, name := range []string{"output.ll", "output.o"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(task.OutLL), name))
		if err != nil || string(data) != "previous "+name {
			t.Fatalf("retained %s changed: %q, %v", name, data, err)
		}
	}
}

func TestCompileOutputTransactionSealedInputs(t *testing.T) {
	for _, change := range []string{"bytes", "same-byte-node", "destination-bytes", "destination-node"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixture(t, false)
			filename := stage.outputs[0].path
			if strings.HasPrefix(change, "destination") {
				filename = task.OutLL
			}
			bytes, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(change, "node") {
				if err := os.Rename(filename, filename+".original"); err != nil {
					t.Fatal(err)
				}
			} else {
				bytes = append(bytes, 'x')
			}
			if err := os.WriteFile(filename, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := stage.publish(); err == nil {
				t.Fatal("changed output node/bytes was published")
			}
			if !strings.HasPrefix(change, "destination") {
				requirePreviousCompileOutputs(t, task)
			}
		})
	}
}

func TestCompileOutputTransactionRollbackAndRestoreFailure(t *testing.T) {
	for _, restoreFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "restore-failure"}[restoreFailure], func(t *testing.T) {
			stage, task := compileOutputFixture(t, true)
			publishFault, restoreFault := errors.New("actual second publish failure"), errors.New("actual backup restore failure")
			first := &stage.outputs[0]
			second := &stage.outputs[1]
			stage.rename = func(from, to string) error {
				if from == second.path && to == second.destination {
					return publishFault
				}
				if restoreFailure && from == first.backup && to == first.destination {
					return restoreFault
				}
				return os.Rename(from, to)
			}
			err := stage.publish()
			if !errors.Is(err, publishFault) || stage.committed {
				t.Fatalf("partial publication did not fail: %v", err)
			}
			if restoreFailure {
				if !errors.Is(err, restoreFault) || stage.close() == nil {
					t.Fatalf("unrestored backup was lost/misreported: %v", err)
				}
				if data, err := os.ReadFile(first.backup); err != nil || string(data) != "previous output.ll" {
					t.Fatalf("recoverable old bytes lost: %q, %v", data, err)
				}
				stage.rename = os.Rename
				if err := stage.rollback(); err != nil {
					t.Fatal(err)
				}
			}
			requirePreviousCompileOutputs(t, task)
		})
	}
}

func TestCompileOutputTransactionCommittedCleanupIsExplicit(t *testing.T) {
	stage, task := compileOutputFixture(t, true)
	if err := stage.publish(); err != nil {
		t.Fatal(err)
	}
	cleanupFault := errors.New("owned stage cleanup failure")
	stage.removeAll = func(string) error { return cleanupFault }
	err := stage.close()
	if !errors.Is(err, cleanupFault) || !strings.Contains(err.Error(), "outputs committed") {
		t.Fatalf("pure committed cleanup failure mislabeled: %v", err)
	}
	for _, name := range []string{"output.ll", "output.o"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(task.OutLL), name))
		if err != nil || string(data) != "new "+name {
			t.Fatalf("committed output missing: %q %v", data, err)
		}
	}
	stage.removeAll = os.RemoveAll
}

func TestCompileOutputTransactionDirectoryIdentity(t *testing.T) {
	for _, change := range []string{"destination-parent", "stage"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixture(t, false)
			directory := filepath.Dir(task.OutLL)
			if change == "stage" {
				directory = stage.directory
			}
			original := directory + ".original"
			if err := os.Rename(directory, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := stage.publish(); err == nil {
				t.Fatal("replaced output directory acquired publication")
			}
			if change == "stage" && stage.close() == nil {
				t.Fatal("replacement stage directory recursively cleaned")
			}
			if _, err := os.Stat(directory); err != nil {
				t.Fatalf("replacement directory was removed: %v", err)
			}
			if err := os.Remove(directory); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(original, directory); err != nil {
				t.Fatal(err)
			}
			requirePreviousCompileOutputs(t, task)
		})
	}
}

func TestCompileOutputTransactionRechecksLaterMembers(t *testing.T) {
	for _, change := range []string{"later-stage", "later-destination"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixture(t, true)
			first, second := &stage.outputs[0], &stage.outputs[1]
			called := false
			stage.rename = func(from, to string) error {
				err := os.Rename(from, to)
				if err == nil && !called && from == first.path && to == first.destination {
					called = true
					filename := second.path
					if change == "later-destination" {
						filename = second.destination
					}
					data, err := os.ReadFile(filename)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(filename, filename+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filename, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				return err
			}
			if err := stage.publish(); err == nil || !called || stage.committed {
				t.Fatalf("later same-byte member replaced after initial validation: called=%v, %v", called, err)
			}
			requirePreviousCompileOutputs(t, task)
		})
	}
}

func TestCompileOutputTransactionRejectsRedirectedDestinations(t *testing.T) {
	for _, change := range []string{"directory", "file-symlink", "directory-alias"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixture(t, false)
			if change == "directory-alias" {
				alias := filepath.Join(t.TempDir(), "output-owner")
				ordinaryLoadDirectoryAlias(t, alias, filepath.Dir(task.OutLL))
				otherTask := task
				otherTask.OutLL = filepath.Join(alias, "other.ll")
				if _, err := stage.stageTask(otherTask, compileConfig{}); err != nil {
					t.Fatal(err)
				}
				other := &stage.outputs[1]
				if err := os.WriteFile(other.path, []byte("new other.ll"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := stage.seal(); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(alias, alias+".original"); err != nil {
					t.Fatal(err)
				}
				ordinaryLoadDirectoryAlias(t, alias, t.TempDir())
			} else {
				if err := os.Rename(task.OutLL, task.OutLL+".original"); err != nil {
					t.Fatal(err)
				}
				if change == "directory" {
					if err := os.Mkdir(task.OutLL, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(task.OutLL+".original", task.OutLL); err != nil {
					t.Fatal(err)
				}
			}
			if err := stage.publish(); err == nil || stage.committed {
				t.Fatal("redirected destination acquired publication")
			}
		})
	}
}

func TestCompileOutputStageOwnsWholeAndChunkTasks(t *testing.T) {
	stage, task := compileOutputFixture(t, true)
	part := task
	part.OutLL = strings.TrimSuffix(task.OutLL, ".ll") + ".part-0001.ll"
	staged, err := stage.stageTask(part, compileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(staged.OutLL) != stage.directory || len(stage.outputs) != 3 {
		t.Fatal("chunk did not borrow the whole attempt transaction")
	}
	if err := stage.publish(); err == nil {
		t.Fatal("unsealed chunk permitted even temporary public changes")
	}
	requirePreviousCompileOutputs(t, task)
	if err := os.WriteFile(staged.OutLL, []byte("new chunk"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.seal(); err != nil {
		t.Fatal(err)
	}
	if err := stage.publish(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(part.OutLL); err != nil || string(data) != "new chunk" {
		t.Fatalf("sealed whole+chunk not committed: %q %v", data, err)
	}
}

func TestCompileOutputStageOutsideCompleteModuleAndDependencyRoots(t *testing.T) {
	module := t.TempDir()
	owner := filepath.Join(module, "subpackage")
	if err := os.Mkdir(owner, 0700); err != nil {
		t.Fatal(err)
	}
	dependency := t.TempDir()
	pkg := &packages.Package{Dir: owner, Module: &packages.Module{Dir: module},
		Imports: map[string]*packages.Package{"dependency": {Dir: dependency}}}
	for _, outputDirectory := range []string{owner, dependency} {
		task := asmTask{OutLL: filepath.Join(outputDirectory, "output.ll")}
		stage, err := newCompileOutputStage(task, pkg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if outputPathWithin(stage.directory, module) || outputPathWithin(stage.directory, dependency) {
			t.Fatal("private stage entered complete source/foreign dependency tree")
		}
		if err := sameOutputFilesystem(filepath.Dir(stage.directory), outputDirectory); err != nil {
			t.Fatal("same-source filesystem was not preserved", err)
		}
		if err := stage.close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCompileOutputTransactionNonretainedObjectPolicy(t *testing.T) {
	for _, change := range []string{"success", "new-object", "rollback-deletion"} {
		t.Run(change, func(t *testing.T) {
			stage, task := compileOutputFixtureWithConfig(t, compileConfig{Enabled: true})
			future := strings.TrimSuffix(task.OutLL, ".ll") + ".part-9999.o"
			if err := os.WriteFile(future, []byte("unrelated historical part"), 0600); err != nil {
				t.Fatal(err)
			}
			if change == "new-object" {
				object := stage.outputs[1].destination
				if err := os.Rename(object, object+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(object, []byte("new external object"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := stage.publish(); err == nil {
					t.Fatal("new unobserved object was deleted")
				}
				if data, err := os.ReadFile(object); err != nil || string(data) != "new external object" {
					t.Fatalf("new object not preserved: %q, %v", data, err)
				}
			} else if change == "rollback-deletion" {
				part := task
				part.OutLL = strings.TrimSuffix(task.OutLL, ".ll") + ".part-0001.ll"
				staged, err := stage.stageTask(part, compileConfig{})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(staged.OutLL, []byte("new part"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := stage.seal(); err != nil {
					t.Fatal(err)
				}
				fault := errors.New("actual later chunk publish failure")
				stage.rename = func(from, to string) error {
					if from == staged.OutLL {
						return fault
					}
					return os.Rename(from, to)
				}
				if err := stage.publish(); !errors.Is(err, fault) {
					t.Fatalf("later failure missing: %v", err)
				}
				requirePreviousCompileOutputs(t, task)
				if _, err := os.Stat(part.OutLL); !os.IsNotExist(err) {
					t.Fatalf("failed later chunk leaked: %v", err)
				}
			} else {
				if err := stage.publish(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(stage.outputs[1].destination); !os.IsNotExist(err) {
					t.Fatalf("successful nonretained object remained: %v", err)
				}
			}
			if data, err := os.ReadFile(future); err != nil || string(data) != "unrelated historical part" {
				t.Fatalf("unrelated part changed: %q, %v", data, err)
			}
		})
	}
}

func TestCompileOutputTransactionRollbackDoesNotReplaceConcurrentOutput(t *testing.T) {
	stage, task := compileOutputFixture(t, false)
	output := &stage.outputs[0]
	stage.rename = func(from, to string) error {
		err := os.Rename(from, to)
		if err == nil && from == output.destination && to == output.backup {
			if err := os.WriteFile(output.destination, []byte("new external writer"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	if err := stage.publish(); err == nil || stage.committed || stage.close() == nil {
		t.Fatalf("concurrent destination overwritten or old backup lost: %v", err)
	}
	if data, err := os.ReadFile(task.OutLL); err != nil || string(data) != "new external writer" {
		t.Fatalf("unobserved external writer overwritten: %q, %v", data, err)
	}
	if data, err := os.ReadFile(output.backup); err != nil || string(data) != "previous output.ll" {
		t.Fatalf("recoverable original bytes missing: %q, %v", data, err)
	}
	// Only the test owner removes its own concurrent replacement, then retries
	// restoration through the original captured identities before cleanup.
	if err := os.Remove(output.destination); err != nil {
		t.Fatal(err)
	}
	stage.rename = os.Rename
	if err := stage.rollback(); err != nil {
		t.Fatal(err)
	}
	requirePreviousCompileOutputs(t, task)
}
