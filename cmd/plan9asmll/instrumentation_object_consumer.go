package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// This standalone bounded consumer deliberately has no ordinary CLI/report
// adapter. It cannot satisfy a candidate until the complete mode denominator
// and all external source/context protocols are integrated independently.
func consumeInstrumentationAssembly(ctx context.Context, input *gotoolprofile.InstrumentationConsumerInput, producer *gotoolprofile.InstrumentationMetadataProof, invocation string, env []string, output string) (*gotoolprofile.InstrumentationConsumptionProof, *gotoolprofile.InstrumentationLLVMTool, error) {
	if input == nil || input.Plan == nil {
		return nil, nil, fmt.Errorf("missing original instrumented source scope")
	}
	plan := input.Plan
	if err := gotoolprofile.ValidateInstrumentationMetadata(input, plan.PackageDirectory, plan.CustomTags, producer); err != nil {
		return nil, nil, err
	}
	consumer, err := captureInstrumentationMetadata(ctx, input, invocation, env, output, packages.Load)
	if err != nil {
		return nil, nil, err
	}
	if err := gotoolprofile.ValidateInstrumentationMetadataAgreement(input, producer, consumer.Metadata, plan.PackageDirectory, plan.CustomTags); err != nil {
		return nil, nil, err
	}
	cfg, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		return nil, nil, err
	}
	cfg.Context = ctx
	version, stderr, err := gotoolprofile.RunBounded(ctx, invocation, consumer.Source.Env, cfg.LLC, "--version")
	if err != nil || len(stderr) != 0 {
		return nil, nil, fmt.Errorf("actual LLVM22 tool identity: %v; %s", err, stderr)
	}
	toolSHA, err := gotoolprofile.FileSHA256(cfg.LLC)
	if err != nil {
		return nil, nil, err
	}
	goos, goarch, _ := strings.Cut(plan.Target, "/")
	triple := targetTriple(goos, goarch)
	if triple == "" {
		return nil, nil, fmt.Errorf("actual mode source has no bound LLVM target route")
	}
	tools := &gotoolprofile.InstrumentationLLVMTool{Version: string(version), SHA256: toolSHA, Triple: triple}
	proof := &gotoolprofile.InstrumentationConsumptionProof{
		Protocol: gotoolprofile.InstrumentationConsumptionProtocol, ModeProfileID: input.ID,
		InputSHA256: gotoolprofile.InstrumentationConsumerInputSHA256(input), MetadataSHA256: gotoolprofile.InstrumentationMetadataSHA256(producer),
		Metadata: consumer.Metadata, LLVM: tools, Status: "llvm_objects_only",
	}
	arch, err := toPlan9Arch(goarch)
	if err != nil {
		return nil, nil, err
	}
	pkg, selected := consumer.Packages[0], consumer.Metadata.Selection.Packages[0]
	resolve := resolveSymFunc(pkg.PkgPath)
	artifactBudget := &gotoolprofile.InstrumentationLLVMArtifactBudget{}
	consumer.ArtifactRoot = output
	cfg.nativeListingMode = consumer
	for index, name := range plan.SFiles {
		if err := consumer.verifySources(); err != nil {
			return nil, nil, err
		}
		asm := filepath.Join(consumer.Source.Dir, filepath.FromSlash(name))
		cppSource := consumer.Source
		var expandedOperands []gotoolprofile.CPPPackageSearchMiss
		if consumer.Source.Input.CPPOriginals != nil {
			header, err := gotoolprofile.CanonicalGeneratedHeader(consumer.Metadata.Headers[0].Header.Definitions)
			if err != nil {
				return nil, nil, err
			}
			actualInput, required, err := gotoolprofile.CPPOriginalExecutionInput(consumer.Source.Input, name, pkg.PkgPath, selected.Macros.Defines, header)
			if err != nil {
				return nil, nil, err
			}
			copy := *consumer.Source
			copy.Input = actualInput
			cppSource, expandedOperands = &copy, required
		}
		expanded, inputs, err := cppSource.preprocessCPPWithHeader(asm, pkg.PkgPath, selected.Macros.Defines, func() ([]byte, error) {
			return gotoolprofile.CanonicalGeneratedHeader(consumer.Metadata.Headers[0].Header.Definitions)
		})
		if err != nil {
			return nil, nil, err
		}
		imports := make(map[string]*types.Package)
		for path, dep := range pkg.Imports {
			imports[path] = dep.Types
		}
		typed := plan9asm.ExpandGoAssemblySource(plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Imports: imports}, expanded, goarch)
		if string(typed) != string(expanded) {
			return nil, nil, fmt.Errorf("mode consumer requires native full-header expansion, not an unproved typed fallback")
		}
		ll := filepath.Join(output, fmt.Sprintf("instrumented-%04d.ll", index))
		task := asmTask{AsmFile: asm, OutLL: ll}
		fileCfg := cfg
		cpp := gotoolprofile.CPPProof{File: name, Emission: "assembly", Inputs: inputs,
			ExpandedSearchMisses: expandedOperands,
			ExpandedSHA256:       featureBytesSHA256(expanded), TypedExpandedSHA256: featureBytesSHA256(typed)}
		file, err := plan9asm.ParseWithDefines(arch, string(typed), selected.Macros.Defines)
		if err != nil {
			if err.Error() != "no TEXT directive found" {
				return nil, nil, err
			}
			cpp.EmptyAssembly, err = proveEmptyAssembly(pkg, task, plan.Target, selected.Macros.Defines, fileCfg)
			if err != nil {
				return nil, nil, err
			}
			cpp.Emission = "symbol_free"
			fileCfg.emptyAssembly = cpp.EmptyAssembly
			file = &plan9asm.File{Arch: arch}
		} else if len(file.Funcs) == 0 {
			cpp.DataOnlyAssembly, err = proveDataOnlyAssembly(pkg, task, file, plan.Target, selected.Macros.Defines, fileCfg)
			if err != nil {
				return nil, nil, err
			}
			cpp.Emission = "data_only"
		}
		sigs, sizes, err := sigsForAsmFile(pkg, file, resolve, goarch)
		if err != nil {
			return nil, nil, err
		}
		decls, err := captureInstrumentationDeclarations(input, pkg, file, resolve, goarch, sigs)
		if err != nil {
			return nil, nil, err
		}
		if err := validateDeclaredTextArgSizes(file, resolve, sizes, goarch); err != nil {
			return nil, nil, err
		}
		contents, err := captureInstrumentationCPPContents(consumer, inputs)
		if err != nil {
			return nil, nil, err
		}
		if err := translateAndCompileModule(file, triple, goarch, task, false, fileCfg, resolve, sigs); err != nil {
			return nil, nil, err
		}
		artifacts, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(output, index, artifactBudget)
		if err != nil {
			return nil, nil, err
		}
		irSHA, objectSHA := artifacts.IR.SHA256, artifacts.Object.SHA256
		consumer.Artifacts = append(consumer.Artifacts, *artifacts)
		proof.Files = append(proof.Files, gotoolprofile.InstrumentationAssemblyFile{
			CPP:            cpp,
			ExpandedSource: string(expanded), TypedSource: string(typed), InputContents: contents, Declarations: decls,
			Output:    gotoolprofile.OutputProof{File: name, Part: filepath.Base(ll), IR: irSHA, Object: objectSHA},
			Artifacts: artifacts,
		})
		after, afterInputs, err := cppSource.preprocessCPPWithHeader(asm, pkg.PkgPath, selected.Macros.Defines, func() ([]byte, error) {
			return gotoolprofile.CanonicalGeneratedHeader(consumer.Metadata.Headers[0].Header.Definitions)
		})
		if err != nil || string(after) != string(expanded) || !reflect.DeepEqual(afterInputs, inputs) {
			return nil, nil, fmt.Errorf("mode CPP graph changed during LLVM consumption: %v", err)
		}
		if err := consumer.verifySources(); err != nil {
			return nil, nil, err
		}
	}
	if err := consumer.reobserve(output); err != nil {
		return nil, nil, err
	}
	actualSHA, err := gotoolprofile.FileSHA256(cfg.LLC)
	if err != nil || actualSHA != tools.SHA256 {
		return nil, nil, fmt.Errorf("LLVM22 compiler changed during mode consumption")
	}
	if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer, tools, plan.PackageDirectory, plan.CustomTags, proof); err != nil {
		return nil, nil, err
	}
	return proof, tools, nil
}

func captureInstrumentationDeclarations(input *gotoolprofile.InstrumentationConsumerInput, pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string, sigs map[string]plan9asm.FuncSig) ([]gotoolprofile.InstrumentationDeclarationProof, error) {
	result := make([]gotoolprofile.InstrumentationDeclarationProof, 0, len(file.Funcs))
	for _, function := range file.Funcs {
		symbol := resolve(function.Sym)
		derived, _, found, err := tryDeclSig(pkg.Types.Scope(), function.Sym, symbol, nil, goarch, pkg.TypesSizes, false)
		if err != nil || !found || strings.Contains(function.Sym, "<") || !reflect.DeepEqual(derived, sigs[symbol]) {
			return nil, fmt.Errorf("mode entry requires its actual ordinary typed Go declaration: %s: %v", symbol, err)
		}
		proof := gotoolprofile.InstrumentationDeclarationProof{Symbol: symbol}
		name := strings.TrimPrefix(symbol, pkg.PkgPath+".")
		object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			return nil, fmt.Errorf("mode declaration is not an actual Go function")
		}
		proof.GoType = types.TypeString(object.Type(), func(pkg *types.Package) string { return pkg.Path() })
		for _, source := range input.Plan.GoFiles {
			set := token.NewFileSet()
			parsed, err := parser.ParseFile(set, source, input.Sources.Contents[source], 0)
			if err != nil {
				return nil, err
			}
			for _, declaration := range parsed.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok || fn.Name.Name != name {
					continue
				}
				if proof.File != "" || fn.Body != nil || fn.Recv != nil {
					return nil, fmt.Errorf("mode entry has no unique original bodyless declaration")
				}
				proof.File = source
				proof.DeclarationSHA256, err = gotoolprofile.ASTSHA(set, fn)
				if err != nil {
					return nil, err
				}
			}
		}
		proof.Layout, err = json.Marshal(derived)
		if err != nil || proof.File == "" {
			return nil, fmt.Errorf("mode layout has no bound selected declaration: %v", err)
		}
		result = append(result, proof)
	}
	return result, nil
}

// These are declaration observations, not synthetic TEXT/frame source. The
// actual Go types/export load supplies every layout; parsed original assembly
// separately determines which of them the LLVM consumer needs.
func captureInstrumentationPackageDeclarations(input *gotoolprofile.InstrumentationConsumerInput, pkg *packages.Package) ([]gotoolprofile.InstrumentationDeclarationProof, error) {
	_, goarch, _ := strings.Cut(input.Plan.Target, "/")
	file := &plan9asm.File{}
	sigs := make(map[string]plan9asm.FuncSig)
	resolve := resolveSymFunc(pkg.PkgPath)
	for _, name := range input.Plan.GoFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, input.Sources.Contents[name], 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range parsed.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body != nil || fn.Recv != nil {
				continue
			}
			sym := "·" + fn.Name.Name
			derived, _, found, err := tryDeclSig(pkg.Types.Scope(), sym, resolve(sym), nil, goarch, pkg.TypesSizes, false)
			if err != nil || !found {
				return nil, fmt.Errorf("actual mode declaration has an unproved native/variadic layout: %s: %v", name, err)
			}
			file.Funcs = append(file.Funcs, plan9asm.Func{Sym: sym})
			sigs[resolve(sym)] = derived
		}
	}
	proofs, err := captureInstrumentationDeclarations(input, pkg, file, resolve, goarch, sigs)
	if err != nil {
		return nil, err
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].Symbol < proofs[j].Symbol })
	return proofs, nil
}

func captureInstrumentationCPPContents(consumer *instrumentationMetadataConsumer, inputs map[string]string) (map[string]string, error) {
	result := make(map[string]string)
	total := 0
	for id, digest := range inputs {
		origin, name, _ := strings.Cut(id, "/")
		limit := gotoolprofile.InstrumentationCPPInputByteLimit(id)
		var data []byte
		var err error
		if origin == "generated" {
			data, err = gotoolprofile.CanonicalGeneratedHeader(consumer.Metadata.Headers[0].Header.Definitions)
		} else {
			root := consumer.Source.Dir
			if origin == "tool" {
				root = consumer.Source.Root
			}
			physical, sourceErr := gotoolprofile.CPPRegularSource(root, name)
			if sourceErr != nil {
				return nil, sourceErr
			}
			opened, openErr := os.Open(physical)
			if openErr != nil {
				return nil, openErr
			}
			data, err = io.ReadAll(io.LimitReader(opened, int64(limit)+1))
			closeErr := opened.Close()
			if err == nil {
				err = closeErr
			}
		}
		total += len(data)
		if err != nil || len(data) > limit || total > 16<<20 || featureBytesSHA256(data) != digest {
			return nil, fmt.Errorf("mode active CPP bytes changed or exceeded their bounded proof: %v", err)
		}
		result[id] = string(data)
	}
	return result, consumer.verifySources()
}
