//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64ByteCarrierConsumersRejectUnclosedNativeEffects(t *testing.T) {
	buildCache := t.TempDir()
	for _, test := range []struct {
		name   string
		mutate func(string) string
	}{
		{"undefined-native-tail", func(source string) string {
			return strings.ReplaceAll(source, "MOVD R1,16(RSP)", "MOVW R1,16(RSP)")
		}},
		{"undefined-outgoing-input", func(source string) string {
			return strings.ReplaceAll(source, "MOVD R0,8(RSP)", "MOVD R0,R0")
		}},
		{"saved-LR-write", func(source string) string {
			return strings.ReplaceAll(source, "MOVD R0,guard+24(FP)\n    RET", "MOVD R0,guard+24(FP)\n    MOVD R0,0(RSP)\n    RET")
		}},
		{"platform-register-write", func(source string) string {
			return strings.ReplaceAll(source, "MOVD R0,guard+24(FP)\n    RET", "MOVD R0,guard+24(FP)\n    MOVD $0x123456789abcdef0,R18_PLATFORM\n    RET")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, packagePath, _ := arm64ByteCarrierFixture(t)
			declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(directory, "original_arm64.s")
			original, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			assembly := test.mutate(string(original))
			if assembly == string(original) {
				t.Fatal("actual source effect control did not change its fixture")
			}
			if err := os.WriteFile(filename, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, packagePath, string(declarations))
			request := arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, buildCache)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					lease, release := runtimeOracleStageContext(t)
					defer release()
					source, err := CaptureGoARM64ByteCarrierSource(lease, request)
					if err != nil {
						t.Fatalf("actual Go-accepted object/source was not observed: %v", err)
					}
					defer source.Close()
					ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, assembly, "aarch64-unknown-linux-gnu", nil)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("unclosed native effect returned LLVM output: %v", err)
					}
				})
			}
		})
	}
}

func TestARM64ByteCarrierConsumerSnapshotsRemainWhole(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, kind := range []string{"file", "signature", "signature-inventory", "name", "target"} {
		for _, api := range []string{"text", "module"} {
			t.Run(kind+"/"+api, func(t *testing.T) {
				lease, release := runtimeOracleStageContext(t)
				defer release()
				owner, err := CaptureGoARM64ByteCarrierSource(lease, request)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
				ir, err := arm64ByteCarrierTranslateAPI(t, api, owner, pkg, string(assembly), "aarch64-unknown-linux-gnu",
					func(file *File, options *Options, _ *GoModuleOptions) {
						if kind == "target" {
							options.TargetTriple = "aarch64-apple-darwin"
							return
						}
						resolve := options.ResolveSym
						mutated := false
						options.ResolveSym = func(symbol string) string {
							name := resolve(symbol)
							if kind == "name" {
								return packagePath + ".collision"
							}
							if !mutated {
								mutated = true
								switch kind {
								case "file":
									file.Funcs[0].Instrs[1].Args[1].Reg = "R1"
								case "signature":
									signature := options.Sigs[name]
									signature.Ret = I64
									options.Sigs[name] = signature
								case "signature-inventory":
									options.Sigs[packagePath+".foreign"] = FuncSig{Name: packagePath + ".foreign", Ret: I64}
								}
							}
							return name
						}
					})
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("changed complete source/options returned LLVM output: %v", err)
				}
				if !errors.Is(owner.Verify(lease), ErrProbeNeedsContext) {
					t.Fatal("failed whole-source join did not revoke the owner")
				}
			})
		}
	}
}
