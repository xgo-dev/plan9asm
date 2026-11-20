//go:build go1.27

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationAssemblyEmissionRolesActualObjects(t *testing.T) {
	for _, test := range []struct {
		name, source, emission string
	}{
		{"comment-only", "// Original nonzero selected source without symbols.\n", "symbol_free"},
		{"macro-only", "#define UNUSED(X) MOVD X, R0\n", "symbol_free"},
		{"inactive-TEXT", "#ifdef NEVER_DEFINED\nTEXT ·Probe(SB),$0-8\nMOVD $41,R0\nMOVD R0,ret+0(FP)\nRET\n#endif\n", "symbol_free"},
		{"zero-byte", "", "symbol_free"},
		{"DATA-only", "#include \"textflag.h\"\nDATA ·Global+0(SB)/8,$41\nGLOBL ·Global(SB),RODATA|NOPTR,$8\n", "data_only"},
		{"TEXT-and-DATA", "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-8\nMOVD $41,R0\nMOVD R0,ret+0(FP)\nRET\nDATA ·Global+0(SB)/8,$41\nGLOBL ·Global(SB),RODATA|NOPTR,$8\n", "assembly"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "1")
			input.Original.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
			const name = "probe_arm64.s"
			if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, name), []byte(test.source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Original.Sources[name] = featureBytesSHA256([]byte(test.source))
			input.Original.Headers[name] = test.source
			toolName := "pkg/include/textflag.h"
			toolBytes, err := os.ReadFile(filepath.Join(runtime.GOROOT(), toolName))
			if err != nil {
				t.Fatal(err)
			}
			input.Original.ToolSources = map[string]string{toolName: featureBytesSHA256(toolBytes)}
			replanInstrumentationMetadataFixture(t, input)
			producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
			if err != nil {
				t.Fatal(err)
			}
			// Independent original stock-Go acceptance is not LLVM proof. In
			// particular, no-TEXT parsing cannot stand in for this real object.
			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			object := filepath.Join(t.TempDir(), "original.o")
			args := []string{"tool", "asm", "-S", "-p", input.Plan.PackagePath,
				"-I", input.Original.SourceRoot, "-I", filepath.Join(producer.Source.Root, "pkg", "include"), "-o", object}
			for _, define := range producer.Metadata.Selection.Packages[0].Macros.Defines {
				args = append(args, "-D", define)
			}
			args = append(args, name)
			listing, stderr, err := gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, producer.Source.Env, binary, args...)
			if err != nil || len(stderr) != 0 {
				t.Fatalf("original same-mode assembler: %v; %s", err, stderr)
			}
			if stat, err := os.Lstat(object); err != nil || !stat.Mode().IsRegular() || stat.Size() == 0 {
				t.Fatalf("original assembler produced no regular nonempty object: %v", err)
			}
			if test.emission == "symbol_free" && len(listing) != 0 {
				t.Fatalf("symbol-free original has a native listing: %s", listing)
			}
			if test.emission == "data_only" {
				if _, err := gotoolprofile.DataOnlySymbolsFromListing(listing); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("actual original same-mode source=%s listingSHA256=%s object=%s", name, featureBytesSHA256(listing), object)
			output := instrumentationObjectFixtureOutput(t, input)
			proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), output)
			if err != nil {
				t.Fatalf("actual accepted %s role must independently compile an LLVM object: %v", test.emission, err)
			}
			if len(proof.Files) != 1 || proof.Files[0].CPP.Emission != test.emission || proof.Files[0].Output.Object == "" {
				t.Fatalf("emission role/object lost: %#v", proof)
			}
			recordInstrumentationObjectFixture(t, output, input, producer.Metadata, tools, proof)
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gotoolprofile.DecodeInstrumentationConsumption(strings.NewReader(string(data)), input, producer.Metadata, tools, ".", nil); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*gotoolprofile.InstrumentationConsumptionProof){
				"deleted protocol": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Protocol = "" },
				"old protocol": func(p *gotoolprofile.InstrumentationConsumptionProof) {
					p.Protocol = "actual_go_instrumentation_llvm_objects_v2"
				},
				"deleted object": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Output.Object = "" },
				"paired role deletion": func(p *gotoolprofile.InstrumentationConsumptionProof) {
					p.Files[0].CPP.Emission = "assembly"
					p.Files[0].CPP.EmptyAssembly = nil
					p.Files[0].CPP.DataOnlyAssembly = nil
				},
				"contradictory role": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].CPP.Emission = "unknown" },
				"paired role and protocol deletion": func(p *gotoolprofile.InstrumentationConsumptionProof) {
					p.Protocol = ""
					p.Files[0].CPP.Emission = ""
					p.Files[0].CPP.EmptyAssembly = nil
					p.Files[0].CPP.DataOnlyAssembly = nil
				},
				"changed complete CPP": func(p *gotoolprofile.InstrumentationConsumptionProof) {
					p.Files[0].TypedSource = "// forged empty\n"
					p.Files[0].CPP.TypedExpandedSHA256 = featureBytesSHA256([]byte(p.Files[0].TypedSource))
				},
				"added unconsumed declaration": func(p *gotoolprofile.InstrumentationConsumptionProof) {
					p.Files[0].Declarations = append(p.Files[0].Declarations, gotoolprofile.InstrumentationDeclarationProof{Symbol: "Unknown"})
				},
			} {
				if name == "paired role deletion" && test.emission == "assembly" {
					continue // This unchanged normal role is the legitimate control.
				}
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.InstrumentationConsumptionProof
					if err := json.Unmarshal(data, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, &changed); err == nil {
						t.Fatal("changed native emission role/object or old consumer was accepted")
					}
				})
			}
			if test.emission != "assembly" {
				for name, mutate := range map[string]func(*gotoolprofile.EmptyAssemblyProof){
					"source":                    func(p *gotoolprofile.EmptyAssemblyProof) { p.SourceSHA256 = strings.Repeat("0", 64) },
					"file":                      func(p *gotoolprofile.EmptyAssemblyProof) { p.File = "unknown.s" },
					"package":                   func(p *gotoolprofile.EmptyAssemblyProof) { p.PackagePath += "/foreign" },
					"ordinary profile":          func(p *gotoolprofile.EmptyAssemblyProof) { p.ProfileID = input.Original.ID },
					"target":                    func(p *gotoolprofile.EmptyAssemblyProof) { p.Target = "linux/amd64" },
					"Go version":                func(p *gotoolprofile.EmptyAssemblyProof) { p.GoVersion = "go1.27.999" },
					"asm tool":                  func(p *gotoolprofile.EmptyAssemblyProof) { p.AsmToolSHA256 = strings.Repeat("0", 64) },
					"missing native object":     func(p *gotoolprofile.EmptyAssemblyProof) { p.ObjectSHA256 = "" },
					"known empty native object": func(p *gotoolprofile.EmptyAssemblyProof) { p.ObjectSHA256 = featureBytesSHA256(nil) },
					"contradictory listing": func(p *gotoolprofile.EmptyAssemblyProof) {
						if test.emission == "symbol_free" {
							p.ListingSHA256 = strings.Repeat("0", 64)
						} else {
							p.ListingSHA256 = featureBytesSHA256(nil)
						}
					},
				} {
					t.Run("native "+name, func(t *testing.T) {
						var changed gotoolprofile.InstrumentationConsumptionProof
						if err := json.Unmarshal(data, &changed); err != nil {
							t.Fatal(err)
						}
						native := changed.Files[0].CPP.EmptyAssembly
						if native == nil {
							native = &changed.Files[0].CPP.DataOnlyAssembly.Native
						}
						mutate(native)
						if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, &changed); err == nil {
							t.Fatal("foreign or missing native listing/object identity was accepted")
						}
					})
				}
			}
			if test.emission == "data_only" {
				for _, name := range []string{"name", "size", "static", "kind", "missing", "duplicate"} {
					t.Run("native symbols "+name, func(t *testing.T) {
						var changed gotoolprofile.InstrumentationConsumptionProof
						if err := json.Unmarshal(data, &changed); err != nil {
							t.Fatal(err)
						}
						symbols := &changed.Files[0].CPP.DataOnlyAssembly.Symbols
						switch name {
						case "name":
							(*symbols)[0].Name += "Unknown"
						case "size":
							(*symbols)[0].Size++
						case "static":
							(*symbols)[0].Static = !(*symbols)[0].Static
						case "kind":
							(*symbols)[0].Kind = "STEXT"
						case "missing":
							*symbols = nil
						case "duplicate":
							*symbols = append(*symbols, (*symbols)[0])
						}
						if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, &changed); err == nil {
							t.Fatal("native symbol inventory no longer matches the full original DATA source")
						}
					})
				}
			}
		})
	}
}

func TestInstrumentationAssemblyEmissionRoleModeFamily(t *testing.T) {
	for _, config := range []struct {
		target string
		mode   gotoolprofile.InstrumentationMode
	}{
		{"darwin/arm64", gotoolprofile.InstrumentationRace},
		{"darwin/amd64", gotoolprofile.InstrumentationRace},
		{"linux/amd64", gotoolprofile.InstrumentationRace},
		{"linux/arm64", gotoolprofile.InstrumentationMSan},
		{"linux/arm64", gotoolprofile.InstrumentationASan},
	} {
		t.Run(config.target+"/"+string(config.mode), func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, config.target, config.mode, "1")
			input.Original.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
			assembly := input.Plan.SFiles[0]
			// One real same-mode selection consumes all four original siblings.
			// No emission may borrow another file's listing, role or LLVM object.
			files := map[string]string{
				assembly:    input.Original.Headers[assembly],
				"comment.s": "// Nonzero symbol-free sibling.\n",
				"zero.s":    "",
				"data.s":    "#include \"textflag.h\"\nDATA local<>+0(SB)/8,$41\nGLOBL local<>(SB),RODATA|NOPTR,$8\n",
			}
			input.Original.AsmFiles = nil
			for name, source := range files {
				if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				input.Original.Sources[name], input.Original.Headers[name] = featureBytesSHA256([]byte(source)), source
				input.Original.AsmFiles = append(input.Original.AsmFiles, name)
			}
			sort.Strings(input.Original.AsmFiles)
			entries, err := os.ReadDir(input.Original.SourceRoot)
			if err != nil {
				t.Fatal(err)
			}
			input.Original.Directories["."] = nil
			for _, entry := range entries {
				input.Original.Directories["."] = append(input.Original.Directories["."], entry.Name())
			}
			toolName := "pkg/include/textflag.h"
			toolBytes, err := os.ReadFile(filepath.Join(runtime.GOROOT(), toolName))
			if err != nil {
				t.Fatal(err)
			}
			input.Original.ToolSources = map[string]string{toolName: featureBytesSHA256(toolBytes)}
			replanInstrumentationMetadataFixture(t, input)
			producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
			if err != nil {
				t.Fatal(err)
			}
			output := instrumentationObjectFixtureOutput(t, input)
			proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), output)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.Files) != 4 {
				t.Fatalf("lost real selected role denominator: %d", len(proof.Files))
			}
			for _, file := range proof.Files {
				wanted := "symbol_free"
				if file.CPP.File == "data.s" {
					wanted = "data_only"
				}
				if file.CPP.File == assembly {
					wanted = "assembly"
				}
				if file.CPP.Emission != wanted || file.Output.Object == "" {
					t.Fatalf("missing original role/real object: %+v", file)
				}
			}
			recordInstrumentationObjectFixture(t, output, input, producer.Metadata, tools, proof)
			if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err != nil {
				t.Fatal(err)
			}
			proof.Files[0].CPP.EmptyAssembly = proof.Files[3].CPP.EmptyAssembly
			if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err == nil {
				t.Fatal("cross-file emission evidence acquired source/object permission")
			}
		})
	}
}

func TestInstrumentationEmissionUnacceptedSourceCannotBecomeEmpty(t *testing.T) {
	for _, source := range []string{"BOGUS unknown\n", "BYTE $300\n", "#include \"missing-original-header.h\"\n"} {
		t.Run(strings.Fields(source)[0], func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "1")
			const name = "probe_arm64.s"
			if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, name), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Original.Sources[name], input.Original.Headers[name] = featureBytesSHA256([]byte(source)), source
			replanInstrumentationMetadataFixture(t, input)
			producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
			if err == nil || producer != nil {
				t.Fatal("unaccepted original source acquired an empty/object role")
			}
			t.Logf("actual original source failure retained: %v", err)
		})
	}
}

func TestInstrumentationEmissionNativeListingRejectsLiveSourceReplacement(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "1")
	input.Original.SignatureSourceProtocol = gotoolprofile.SignatureSourceProtocol
	const name, source = "probe_arm64.s", "// actual nonzero source\n"
	path := filepath.Join(input.Original.SourceRoot, name)
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Sources[name], input.Original.Headers[name] = featureBytesSHA256([]byte(source)), source
	replanInstrumentationMetadataFixture(t, input)
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	// No source role may be relabeled as the selected zero-byte sibling after
	// its actual same-mode graph, source bytes and tools have been captured.
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if proof, _, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), t.TempDir()); err == nil || proof != nil {
		t.Fatal("source-to-empty replacement acquired native/LLVM object permission")
	}
}
