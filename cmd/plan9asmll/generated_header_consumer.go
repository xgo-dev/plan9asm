package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// Retain the actual dependency/source/export snapshots through the final
// LLVM object and marker checks, not only until -asmhdr returns. These private
// physical paths never become portable report identities.
func (consumer *featureConsumer) retainGeneratedGuard(files map[string]string) error {
	if consumer.GeneratedGuard == nil {
		consumer.GeneratedGuard = make(map[string]string)
	}
	for file, digest := range files {
		if !filepath.IsAbs(file) || digest == "" {
			return fmt.Errorf("generated-header dependency has no exact private source identity")
		}
		if previous := consumer.GeneratedGuard[file]; previous != "" && previous != digest {
			return fmt.Errorf("generated-header dependency changed between compiler snapshots")
		}
		consumer.GeneratedGuard[file] = digest
	}
	return nil
}

func (consumer *featureConsumer) captureGeneratedMetadata(pkgs []*packages.Package, tags []string, output string) error {
	dependencies, err := consumer.ordinaryDependencyProof()
	if err != nil {
		return err
	}
	actual := &gotoolprofile.MetadataProof{
		Protocol: gotoolprofile.MetadataProtocol, ProfileID: consumer.ID,
		CustomTags: append([]string(nil), tags...), Packages: consumer.Proof.Packages,
		Dependencies: dependencies,
	}
	for index, pkg := range pkgs {
		header, err := captureGeneratedHeader(consumer, pkg, actual.Packages[index], output)
		if err != nil {
			return err
		}
		actual.Headers = append(actual.Headers, header)
		if err := loadLinknameSyntax(pkg); err != nil {
			return err
		}
	}
	if err := gotoolprofile.ValidateGeneratedHeaderAgreement(consumer.Input, consumer.Input.GeneratedHeaders, actual, tags); err != nil {
		return err
	}
	consumer.Proof.GeneratedHeaders = actual
	return consumer.verifySources()
}

// preprocessCPP uses the actual Go search order from the package working
// directory, followed by the generated object directory and GOROOT includes.
// Only active source-order includes enter this consumption graph. Raw branch
// registration remains a separate producer obligation.
func (consumer *featureConsumer) preprocessCPP(asm, packagePath string, defines []string) ([]byte, map[string]string, error) {
	return consumer.preprocessCPPWithHeader(asm, packagePath, defines, func() ([]byte, error) {
		return consumer.generatedCPPHeader(packagePath)
	})
}

// Publication uses the same active include resolver's absence trace, not a
// guessed path derived from the normalized fallback names or inactive branches.
func (consumer *featureConsumer) preprocessCPPWithReadReport(asm, packagePath string, defines []string, report *plan9asm.GoAssemblySourceReadReport) ([]byte, map[string]string, error) {
	return consumer.preprocessCPPSource(asm, packagePath, defines, func() ([]byte, error) {
		return consumer.generatedCPPHeader(packagePath)
	}, false, report)
}

func (consumer *featureConsumer) generatedCPPHeader(packagePath string) ([]byte, error) {
	if consumer.Proof == nil || consumer.Proof.GeneratedHeaders == nil {
		return nil, fmt.Errorf("active generated include lacks actual compiler metadata")
	}
	for _, header := range consumer.Proof.GeneratedHeaders.Headers {
		if header.PackagePath == packagePath {
			return gotoolprofile.CanonicalGeneratedHeader(header.Definitions)
		}
	}
	return nil, fmt.Errorf("active generated include has no selected package origin")
}

// Only the actual selected caller inventory uses this source-only role. Its
// companions need exact physical/original replay, not a final object receipt
// for an assembly file outside this invocation's object request. Requested
// files retain the ordinary strict object contract. No input/proof is mutated.
func (consumer *featureConsumer) preprocessCallerCPP(asm, packagePath string, defines []string) ([]byte, map[string]string, error) {
	assembly, err := consumer.moduleSourceName(asm)
	if err != nil {
		return nil, nil, err
	}
	sourceOnly := false
	if consumer.Input.CPPOriginals != nil {
		sourceOnly = true
		for _, requested := range consumer.Input.AsmFiles {
			if requested == assembly {
				sourceOnly = false
				break
			}
		}
		if _, present := consumer.Input.CPPOriginals.Units[assembly]; !present {
			return nil, nil, fmt.Errorf("caller companion lacks its complete original CPP unit")
		}
	}
	return consumer.preprocessCPPSource(asm, packagePath, defines, func() ([]byte, error) {
		return consumer.generatedCPPHeader(packagePath)
	}, sourceOnly, nil)
}

// A mode caller supplies a separately validated native header. This shared
// source-order search/read path never assigns that header an ordinary role.
func (consumer *featureConsumer) preprocessCPPWithHeader(asm, packagePath string, defines []string, generatedHeader func() ([]byte, error)) ([]byte, map[string]string, error) {
	return consumer.preprocessCPPSource(asm, packagePath, defines, generatedHeader, false, nil)
}

func (consumer *featureConsumer) preprocessCPPSource(asm, packagePath string, defines []string, generatedHeader func() ([]byte, error), sourceOnly bool, report *plan9asm.GoAssemblySourceReadReport) ([]byte, map[string]string, error) {
	if err := gotoolprofile.ValidateCPPIncludeSearch(consumer.Input, nil); err != nil {
		return nil, nil, err
	}
	for _, miss := range consumer.Input.CPPIncludeSearchMisses {
		if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, consumer.Dir, consumer.Root); err != nil {
			return nil, nil, err
		}
	}
	inputs := make(map[string]string)
	bytesRead := 0
	read := func(file string, generated bool) (string, []byte, error) {
		if consumer.Context != nil && consumer.Context.Err() != nil {
			return "", nil, consumer.Context.Err()
		}
		if len(inputs) >= 512 {
			return "", nil, fmt.Errorf("active CPP source inventory exceeds its bound")
		}
		if generated {
			if generatedHeader == nil {
				return "", nil, fmt.Errorf("active generated include lacks actual compiler metadata")
			}
			data, err := generatedHeader()
			id := "generated/" + packagePath + "/go_asm.h"
			if err == nil {
				inputs[id] = featureBytesSHA256(data)
			}
			return id, data, err
		}
		name, sourceErr := consumer.moduleSourceName(file)
		id, wanted := "module/"+name, consumer.Input.Sources[name]
		if sourceErr != nil {
			resolved, err := sourcepath.Resolve(file)
			if err != nil {
				return "", nil, err
			}
			// Both operands need the same physical root. The driver's GOROOT
			// may retain an ancestor alias (including a cross-volume junction).
			root, err := sourcepath.Resolve(consumer.Root)
			if err != nil {
				return "", nil, err
			}
			name, err = filepath.Rel(root, resolved)
			name = filepath.ToSlash(name)
			if err != nil || !gotoolprofile.CPPLocalSource(name) {
				return "", nil, fmt.Errorf("active CPP include lacks original module/tool provenance")
			}
			if _, err := gotoolprofile.CPPRegularSource(consumer.Root, name); err != nil {
				return "", nil, err
			}
			id, wanted = "tool/"+name, consumer.Input.ToolSources[name]
		} else if _, err := gotoolprofile.CPPRegularSource(consumer.Dir, name); err != nil {
			return "", nil, err
		}
		if wanted == "" {
			return "", nil, fmt.Errorf("active CPP source has no original bound bytes: %s", id)
		}
		reader, err := os.Open(file)
		if err != nil {
			return "", nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, 64<<20+1))
		closeErr := reader.Close()
		bytesRead += len(data)
		if readErr != nil || closeErr != nil || bytesRead > 64<<20 {
			return "", nil, fmt.Errorf("active CPP source exceeds bounded read contract: %v (close: %v)", readErr, closeErr)
		}
		actual := featureBytesSHA256(data)
		if wanted == "" || wanted != actual {
			return "", nil, fmt.Errorf("active CPP source differs from exact registered bytes: %s", id)
		}
		inputs[id] = actual
		return id, data, nil
	}
	file, source, err := read(asm, false)
	if err != nil {
		return nil, nil, err
	}
	assembly := strings.TrimPrefix(file, "module/")
	var replay plan9asm.AssemblyCPPObservation
	var replayInputs map[string]string
	var required []gotoolprofile.CPPPackageSearchMiss
	if consumer.Input.CPPOriginals != nil {
		var header []byte
		if len(consumer.Input.CPPOriginals.Units[assembly].GeneratedHeaders) != 0 && generatedHeader != nil {
			header, err = generatedHeader()
			if err != nil {
				return nil, nil, err
			}
		}
		replay, replayInputs, required, err = gotoolprofile.ReplayCPPOriginal(consumer.Input, assembly, packagePath, defines, header)
		if err != nil {
			return nil, nil, err
		}
		if sourceOnly {
			for _, miss := range required {
				if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, consumer.Dir, consumer.Root); err != nil {
					return nil, nil, err
				}
			}
		} else {
			if err := gotoolprofile.ValidateCPPExpandedOperands(consumer.Input, assembly, required); err != nil {
				return nil, nil, err
			}
		}
	}
	options := plan9asm.AssemblyPreprocessOptions{
		FileName: file, Defines: defines,
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\\\x00") {
				return "", nil, fmt.Errorf("unsafe active CPP include: %s", name)
			}
			if consumer.Input.CPPOriginals == nil {
				if err := gotoolprofile.RequireCPPPackageSearchMiss(consumer.Input, assembly, parent, name); err != nil {
					return "", nil, err
				}
			}
			candidate, err := gotoolprofile.CPPPreferredPackageInclude(consumer.Dir, assembly, name)
			if err != nil {
				return "", nil, err
			}
			if _, err := os.Lstat(candidate); err == nil {
				return read(candidate, false)
			} else if !os.IsNotExist(err) {
				return "", nil, err
			}
			if report != nil {
				report.SearchMisses = append(report.SearchMisses, candidate)
			}
			if filepath.Clean(name) == "go_asm.h" {
				return read("", true)
			}
			return read(filepath.Join(consumer.Root, "pkg/include", filepath.FromSlash(name)), false)
		},
	}
	var observation plan9asm.AssemblyCPPObservation
	if consumer.Input.CPPOriginals == nil {
		// Historical inputs do not acquire the new observation budgets.
		observation.Output, err = plan9asm.PreprocessAssemblySource(string(source), options)
	} else {
		observation, err = plan9asm.ObserveAssemblyCPP(string(source), options)
	}
	if err != nil {
		return nil, nil, err
	}
	expanded := observation.Output
	if consumer.Input.CPPOriginals != nil {
		actualOperands, err := gotoolprofile.CPPExpandedOperands(consumer.Input, assembly, observation)
		if err != nil || !reflect.DeepEqual(actualOperands, required) || expanded != replay.Output || !reflect.DeepEqual(inputs, replayInputs) {
			return nil, nil, fmt.Errorf("actual physical CPP execution differs from complete original replay: %v", err)
		}
	}
	if len(expanded) > 64<<20 {
		return nil, nil, fmt.Errorf("active CPP expansion exceeds its bound")
	}
	return []byte(expanded), inputs, nil
}
