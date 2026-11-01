//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64WindowsPrivateLeafCompleteObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, spelling := range []string{"leaf<>", "leaf"} {
		t.Run(spelling, func(t *testing.T) {
			assembly := fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "ADDQ BX,(BP)\nMOVQ (BP),AX")
			assembly = strings.ReplaceAll(assembly, "leaf<>", spelling)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			request.Target = "windows/amd64"
			options.TargetTriple = "x86_64-pc-windows-msvc"
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, []string{pkg.Path + ".Value"})
					compileLLVMToObject(t, llc, options.TargetTriple, "private-leaf.ll", "private-leaf.o", ir)
					compileLLVMToObject(t, llc, options.TargetTriple, "private-leaf-opt.ll", "private-leaf-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}

func TestGoAMD64WindowsPrivateLeafSourceRoleBoundaries(t *testing.T) {
	for _, spelling := range []string{"leaf<>", "leaf"} {
		t.Run(spelling, func(t *testing.T) {
			assembly := strings.ReplaceAll(fixedLocalPrivateLeafSource("CALL leaf<>(SB)",
				"ADDQ BX,(BP)\nMOVQ (BP),AX"), "leaf<>", spelling)
			pkg, request, _ := fixedLocalPrivateLeafFixture(t, assembly)
			request.Target = "windows/amd64"
			source := requireGoAMD64FrameCapture(t, pkg, request)
			object, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o"))
			if err != nil {
				t.Fatal(err)
			}
			listing, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			data, err := source.frameDataObject(assembly, object)
			if err != nil {
				t.Fatal(err)
			}
			leaves, err := goAMD64WindowsPrivateLeafTexts(file, pkg, listing, data)
			if err != nil || len(leaves) != 1 {
				t.Fatal("complete source did not retain its one exact private leaf", err)
			}
			observed, err := source.observeWindowsUnwind(object, leaves)
			if err != nil || len(observed.Texts) != 2 || len(observed.Unwind) != 1 {
				t.Fatal("framed root and zero-frame leaf lost their distinct SEH roles", err)
			}
			if _, err := source.observeWindowsUnwind(object); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("default metadata observation inferred a private source role", err)
			}
			for _, change := range nativeHeaderRoleChanges() {
				t.Run("header-"+change.name, func(t *testing.T) {
					rows := strings.Split(string(listing), "\n")
					changed := false
					for index, row := range rows {
						if strings.HasPrefix(row, leaves[0].Name+" STEXT ") && strings.Contains(row, change.before) {
							rows[index] = nativeHeaderChangedRole(row, change.before, change.after)
							changed = true
						}
					}
					if !changed {
						t.Fatal("actual private header precondition changed")
					}
					mutated := []byte(strings.Join(rows, "\n"))
					copyData := *data
					copyData.Member.Texts = append([]gostaticstorage.TextRecord(nil), data.Member.Texts...)
					for index := range copyData.Member.Texts {
						text := &copyData.Member.Texts[index]
						if text.Index == leaves[0].Index {
							if change.name == "dupok" {
								text.Flags |= 0x01
							} else if change.name == "leaf" {
								text.Flags |= 0x08
							}
						}
					}
					// These edited observations are mutation controls, not new
					// Go objects. Matching metadata still grants no private role.
					if _, err := sdkAMD64FrameNativeRecordsForSource(mutated, copyData.Member.Texts, copyData.TextOrder); err != nil {
						t.Fatal("role control did not reach the private entry boundary", err)
					}
					if _, err := goAMD64WindowsPrivateLeafTexts(file, pkg, mutated, &copyData); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("special or unknown metadata acquired a Windows private leaf role", err)
					}
				})
			}
			var root gostaticstorage.TextRecord
			for _, text := range observed.Texts {
				if text.Index != leaves[0].Index {
					root = text
				}
			}
			serialized, err := json.Marshal(leaves)
			if err != nil {
				t.Fatal(err)
			}
			mutations := map[string]func([]gostaticstorage.TextRecord) []gostaticstorage.TextRecord{
				"missing leaf": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord { return nil },
				"duplicate leaf": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					return append(v, v[0])
				},
				"framed root is not leaf": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					return []gostaticstorage.TextRecord{root}
				},
				"foreign name": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Name += "Other"
					return v
				},
				"foreign ABI": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].ABI = 1
					return v
				},
				"foreign index": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Index = root.Index
					return v
				},
				"foreign namespace": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Namespace = gostaticstorage.TextSymbolHashed
					return v
				},
				"changed bytes": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Code[0] ^= 1
					return v
				},
				"changed source PC": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Positions[0].Line++
					return v
				},
				"changed relative index": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Relative++
					return v
				},
				"borrowed root auxiliary": func(v []gostaticstorage.TextRecord) []gostaticstorage.TextRecord {
					v[0].Auxiliary = root.Auxiliary
					return v
				},
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					var changed []gostaticstorage.TextRecord
					if err := json.Unmarshal(serialized, &changed); err != nil {
						t.Fatal(err)
					}
					if _, err := source.observeWindowsUnwind(object, mutate(changed)); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed source/object leaf descriptor acquired a metadata exception", err)
					}
				})
			}
			for name, change := range map[string][2]string{
				"nonzero helper frame": {"TEXT " + spelling + "(SB),4,$0", "TEXT " + spelling + "(SB),4,$8"},
				"helper SP read":       {"ADDQ BX,(BP)", "MOVQ (SP),AX"},
				"helper stack write":   {"ADDQ BX,(BP)", "PUSHQ AX"},
				"helper is not leaf":   {"ADDQ BX,(BP)", "CALL " + spelling + "(SB)"},
			} {
				t.Run(name, func(t *testing.T) {
					changed := strings.Replace(assembly, change[0], change[1], 1)
					if changed == assembly {
						t.Fatal("source role control did not alter the complete source")
					}
					parsed, err := Parse(ArchAMD64, changed)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := goAMD64WindowsPrivateLeafTexts(parsed, pkg, listing, data); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("non-leaf source acquired a zero-frame metadata role", err)
					}
				})
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if err := source.Verify(ctx); err != nil {
				t.Fatal("readonly role controls changed the original capture", err)
			}
		})
	}
}
