package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

const InstrumentationConsumptionProtocol = "actual_go_instrumentation_llvm_objects_v3"

// This standalone proof establishes only the original assembly's LLVM objects.
// There is no corpus/report hook, candidate PASS, sanitizer runtime or link
// claim. Ordinary and instrumented protocols cannot substitute for each other.
type InstrumentationConsumptionProof struct {
	Protocol       string                        `json:"protocol"`
	ModeProfileID  string                        `json:"mode_profile_id"`
	InputSHA256    string                        `json:"input_sha256"`
	MetadataSHA256 string                        `json:"producer_metadata_sha256"`
	Metadata       *InstrumentationMetadataProof `json:"actual_consumer_metadata"`
	LLVM           *InstrumentationLLVMTool      `json:"llvm_tool"`
	Files          []InstrumentationAssemblyFile `json:"files"`
	Status         string                        `json:"status"`
}

type InstrumentationLLVMTool struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Triple  string `json:"target_triple"`
}

type InstrumentationAssemblyFile struct {
	CPP            CPPProof                          `json:"cpp"`
	ExpandedSource string                            `json:"expanded_source"`
	TypedSource    string                            `json:"typed_expanded_source"`
	Declarations   []InstrumentationDeclarationProof `json:"actual_go_declarations"`
	InputContents  map[string]string                 `json:"active_cpp_input_contents"`
	Output         OutputProof                       `json:"output"`
	Artifacts      *InstrumentationLLVMArtifacts     `json:"generated_artifacts"`
}

type InstrumentationDeclarationProof struct {
	Symbol            string          `json:"symbol"`
	File              string          `json:"file"`
	DeclarationSHA256 string          `json:"declaration_ast_sha256"`
	GoType            string          `json:"go_type"`
	Layout            json.RawMessage `json:"layout"`
}

func InstrumentationMetadataSHA256(proof *InstrumentationMetadataProof) string {
	return instrumentationObjectSHA(proof)
}

func ValidateInstrumentationMetadataAgreement(input *InstrumentationConsumerInput, expected, actual *InstrumentationMetadataProof, directory string, tags []string) error {
	for _, proof := range []*InstrumentationMetadataProof{expected, actual} {
		if err := ValidateInstrumentationMetadata(input, directory, tags, proof); err != nil {
			return err
		}
	}
	normalize := func(proof *InstrumentationMetadataProof) (*InstrumentationMetadataProof, error) {
		copy, err := compactInstrumentationMetadataLayouts(proof)
		if err != nil {
			return nil, err
		}
		copy.Headers = append([]InstrumentationGeneratedHeader(nil), proof.Headers...)
		for index := range copy.Headers {
			copy.Headers[index].Header.HeaderSHA256 = ""
			copy.Headers[index].Header.ObjectSHA256 = ""
		}
		return copy, nil
	}
	wanted, err := normalize(expected)
	if err != nil {
		return err
	}
	observed, err := normalize(actual)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(wanted, observed) {
		return fmt.Errorf("independent same-mode metadata selected different source/exports/full definitions or routing")
	}
	return nil
}

func DecodeInstrumentationConsumption(reader io.Reader, input *InstrumentationConsumerInput, producer *InstrumentationMetadataProof, llvm *InstrumentationLLVMTool, directory string, tags []string) (*InstrumentationConsumptionProof, error) {
	var proof InstrumentationConsumptionProof
	if err := decodeInstrumentationOriginalJSON(reader, 40<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationConsumption(input, producer, llvm, directory, tags, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

var instrumentationLLVMVersion = regexp.MustCompile(`(?m)\bLLVM version 22(?:\.|$)`)

func ValidateInstrumentationConsumption(input *InstrumentationConsumerInput, producer *InstrumentationMetadataProof, llvm *InstrumentationLLVMTool, directory string, tags []string, proof *InstrumentationConsumptionProof) error {
	if err := ValidateInstrumentationMetadata(input, directory, tags, producer); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != InstrumentationConsumptionProtocol || proof.ModeProfileID != input.ID ||
		proof.InputSHA256 != InstrumentationConsumerInputSHA256(input) || proof.MetadataSHA256 != InstrumentationMetadataSHA256(producer) ||
		proof.Status != "llvm_objects_only" || llvm == nil || !instrumentationLLVMVersion.MatchString(llvm.Version) ||
		!discoverySHA256Pattern.MatchString(llvm.SHA256) || llvm.Triple == "" || llvm.Triple != instrumentationConsumptionTriple(input.Plan.Target) || !reflect.DeepEqual(proof.LLVM, llvm) {
		return fmt.Errorf("mode consumption lacks its independent context/producer/LLVM22 tool identity")
	}
	if err := ValidateInstrumentationMetadataAgreement(input, producer, proof.Metadata, directory, tags); err != nil {
		return err
	}
	if len(proof.Files) != len(input.Plan.SFiles) || len(proof.Files) == 0 {
		return fmt.Errorf("mode consumption lost its complete selected assembly denominator")
	}
	pkg := proof.Metadata.Selection.Packages[0]
	arch, err := instrumentationConsumptionArch(input.Plan.Target)
	if err != nil {
		return err
	}
	bytes := 0
	artifactBudget := &InstrumentationLLVMArtifactBudget{}
	for index, file := range proof.Files {
		cpp := file.CPP
		bytes += len(file.ExpandedSource) + len(file.TypedSource)
		if cpp.File != input.Plan.SFiles[index] || len(cpp.Signatures) != 0 ||
			len(file.ExpandedSource) > AssemblySourceByteLimit || len(file.TypedSource) > AssemblySourceByteLimit || bytes > instrumentationOriginalInventoryLimit ||
			cpp.ExpandedSHA256 != bytesSHA256([]byte(file.ExpandedSource)) || cpp.TypedExpandedSHA256 != bytesSHA256([]byte(file.TypedSource)) ||
			cpp.Inputs["module/"+cpp.File] != input.Original.Sources[cpp.File] {
			return fmt.Errorf("mode CPP differs from its original scope/actual source or has an unproved role")
		}
		if err := replayInstrumentationCPP(input, pkg, proof.Metadata, file); err != nil {
			return err
		}
		for origin, digest := range cpp.Inputs {
			kind, name, present := strings.Cut(origin, "/")
			wanted := input.Original.Sources[name]
			if kind == "tool" {
				wanted = input.Original.ToolSources[name]
			}
			if kind == "generated" && name == pkg.PackagePath+"/go_asm.h" {
				data, err := CanonicalGeneratedHeader(proof.Metadata.Headers[0].Header.Definitions)
				if err != nil {
					return err
				}
				wanted = bytesSHA256(data)
			}
			if !present || kind != "module" && kind != "tool" && kind != "generated" || wanted == "" || digest != wanted {
				return fmt.Errorf("mode CPP read an unbound original/header resource")
			}
		}
		parsed, err := validateInstrumentationAssemblyEmission(input, pkg, file, arch)
		if err != nil {
			return err
		}
		if err := replayInstrumentationDeclarationLayouts(input, pkg, file.Declarations); err != nil {
			return err
		}
		for ordinal, fn := range parsed.Funcs {
			symbol := instrumentationResolvedSymbol(pkg.PackagePath, fn.Sym)
			if err := validateInstrumentationDeclaration(input, pkg, symbol, file.Declarations[ordinal]); err != nil {
				return err
			}
			found := false
			for _, expected := range proof.Metadata.Declarations {
				if expected.Symbol == symbol {
					wanted, err := compactInstrumentationDeclarationLayout(expected)
					if err != nil {
						return err
					}
					actual, err := compactInstrumentationDeclarationLayout(file.Declarations[ordinal])
					if err != nil {
						return err
					}
					found = reflect.DeepEqual(wanted, actual)
				}
			}
			if !found {
				return fmt.Errorf("mode LLVM layout differs from the independent actual typed Go metadata")
			}
		}
		output := file.Output
		if output.File != cpp.File || path.Base(output.Part) != output.Part || !strings.HasSuffix(output.Part, ".ll") ||
			!discoverySHA256Pattern.MatchString(output.IR) || !discoverySHA256Pattern.MatchString(output.Object) {
			return fmt.Errorf("mode consumption lacks its actual same-file LLVM IR/object")
		}
		if err := ValidateInstrumentationLLVMArtifacts(index, output, file.Artifacts, artifactBudget); err != nil {
			return err
		}
	}
	return nil
}

// Callers first strictly decode the complete layout and replay the independent
// original Go declaration. Only JSON whitespace is normalized: every ABI token
// and all other declaration fields still participate in the exact comparison.
func compactInstrumentationDeclarationLayout(proof InstrumentationDeclarationProof) (InstrumentationDeclarationProof, error) {
	var layout bytes.Buffer
	if err := json.Compact(&layout, proof.Layout); err != nil {
		return InstrumentationDeclarationProof{}, err
	}
	proof.Layout = layout.Bytes()
	return proof, nil
}

func compactInstrumentationMetadataLayouts(proof *InstrumentationMetadataProof) (*InstrumentationMetadataProof, error) {
	copy := *proof
	copy.Declarations = append([]InstrumentationDeclarationProof(nil), proof.Declarations...)
	for index := range copy.Declarations {
		declaration, err := compactInstrumentationDeclarationLayout(copy.Declarations[index])
		if err != nil {
			return nil, err
		}
		copy.Declarations[index] = declaration
	}
	return &copy, nil
}

func validateInstrumentationPackageDeclarations(input *InstrumentationConsumerInput, pkg PackageProof, declarations []InstrumentationDeclarationProof) error {
	if declarations == nil || len(declarations) > 4096 || !sort.SliceIsSorted(declarations, func(i, j int) bool { return declarations[i].Symbol < declarations[j].Symbol }) {
		return fmt.Errorf("mode metadata lacks complete canonical actual Go declaration layouts")
	}
	wanted := make(map[string]bool)
	for _, name := range pkg.CompiledGoFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, input.Sources.Contents[name], 0)
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if ok && fn.Body == nil && fn.Recv == nil {
				wanted[pkg.PackagePath+"."+fn.Name.Name] = true
			}
		}
	}
	if len(declarations) != len(wanted) {
		return fmt.Errorf("mode metadata omitted an actual compiled bodyless declaration")
	}
	for _, declaration := range declarations {
		if !wanted[declaration.Symbol] {
			return fmt.Errorf("mode metadata changed or duplicated an actual declaration")
		}
		delete(wanted, declaration.Symbol)
		if err := validateInstrumentationDeclaration(input, pkg, declaration.Symbol, declaration); err != nil {
			return err
		}
	}
	return replayInstrumentationDeclarationLayouts(input, pkg, declarations)
}

func replayInstrumentationCPP(input *InstrumentationConsumerInput, pkg PackageProof, metadata *InstrumentationMetadataProof, file InstrumentationAssemblyFile) error {
	if len(file.InputContents) != len(file.CPP.Inputs) || len(file.InputContents) > 512 || file.TypedSource != file.ExpandedSource {
		return fmt.Errorf("mode CPP lacks complete actual inputs or needs an unproved typed expansion")
	}
	total := 0
	for id, text := range file.InputContents {
		total += len(text)
		if len(text) > InstrumentationCPPInputByteLimit(id) || total > instrumentationOriginalInventoryLimit || bytesSHA256([]byte(text)) != file.CPP.Inputs[id] {
			return fmt.Errorf("mode CPP contents are changed or exceed the total byte bound")
		}
	}
	read := func(id string) ([]byte, error) {
		text, found := file.InputContents[id]
		if !found || len(text) > InstrumentationCPPInputByteLimit(id) || bytesSHA256([]byte(text)) != file.CPP.Inputs[id] {
			return nil, fmt.Errorf("mode CPP input contents differ from their original byte binding")
		}
		return []byte(text), nil
	}
	original := "module/" + file.CPP.File
	source, err := read(original)
	if err != nil || string(source) != input.Sources.Contents[file.CPP.File] {
		return fmt.Errorf("mode CPP original assembly bytes differ from the complete source inventory")
	}
	if input.Original.CPPOriginals != nil {
		header, err := CanonicalGeneratedHeader(metadata.Headers[0].Header.Definitions)
		if err != nil {
			return err
		}
		observation, used, required, err := ReplayCPPOriginal(input.Original, file.CPP.File, pkg.PackagePath, pkg.Macros.Defines, header)
		if err != nil || file.CPP.ExpandedSearchMisses == nil || !reflect.DeepEqual(required, file.CPP.ExpandedSearchMisses) ||
			observation.Output != file.ExpandedSource || !reflect.DeepEqual(used, file.CPP.Inputs) {
			return fmt.Errorf("mode CPP original replay/expanded operands differ from its actual mode header and defines: %v", err)
		}
		return nil
	}
	used := map[string]bool{original: true}
	expanded, err := plan9asm.PreprocessAssemblySource(string(source), plan9asm.AssemblyPreprocessOptions{
		FileName: original, Defines: pkg.Macros.Defines,
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if err := RequireCPPPackageSearchMiss(input.Original, file.CPP.File, parent, name); err != nil {
				return "", nil, err
			}
			module, tool, err := CPPIncludeCandidates(file.CPP.File, name)
			if err != nil {
				return "", nil, err
			}
			id := "tool/" + tool
			if CPPLocalSource(module) && input.Original.Sources[module] != "" {
				id = "module/" + module
			} else if path.Clean(name) == "go_asm.h" {
				id = "generated/" + pkg.PackagePath + "/go_asm.h"
				data, err := CanonicalGeneratedHeader(metadata.Headers[0].Header.Definitions)
				if err != nil || file.InputContents[id] != string(data) {
					return "", nil, fmt.Errorf("mode generated include differs from the actual full native header")
				}
			}
			data, err := read(id)
			if err == nil {
				used[id] = true
			}
			return id, data, err
		},
	})
	if err != nil || expanded != file.ExpandedSource || len(used) != len(file.InputContents) {
		return fmt.Errorf("mode CPP source-order replay differs from the complete actual graph: %v", err)
	}
	return nil
}

func validateInstrumentationDeclaration(input *InstrumentationConsumerInput, pkg PackageProof, symbol string, proof InstrumentationDeclarationProof) error {
	if proof.Symbol != symbol || !strings.HasPrefix(symbol, pkg.PackagePath+".") ||
		proof.GoType == "" || len(proof.GoType) > 4096 || strings.ContainsAny(proof.GoType, "\r\n\x00") || len(proof.Layout) > 1<<20 {
		return fmt.Errorf("mode function lacks an exact actual Go declaration/type/layout")
	}
	selected := false
	for _, name := range pkg.CompiledGoFiles {
		selected = selected || name == proof.File
	}
	if !selected {
		return fmt.Errorf("mode declaration source was not compiled by the actual Go package")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, proof.File, input.Sources.Contents[proof.File], 0)
	if err != nil {
		return err
	}
	wanted := strings.TrimPrefix(symbol, pkg.PackagePath+".")
	found := false
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != wanted {
			continue
		}
		if found || fn.Body != nil || fn.Recv != nil {
			return fmt.Errorf("mode function has no unique original bodyless non-method declaration")
		}
		found = true
		digest, err := ASTSHA(fset, fn)
		if err != nil || digest != proof.DeclarationSHA256 {
			return fmt.Errorf("mode declaration differs from the original selected AST")
		}
	}
	var sig plan9asm.FuncSig
	if err := decodeInstrumentationOriginalJSON(strings.NewReader(string(proof.Layout)), 1<<20, &sig); err != nil {
		return err
	}
	if !found || sig.Name != symbol || sig.Ret == "" || sig.ARMEntry != nil || sig.WASMContext != "" || sig.WASMNative ||
		sig.ARM64ClosureABI != nil || sig.ARM64GoRegisterABI != nil || len(sig.ArgRegs) != 0 || sig.Attrs != "" {
		return fmt.Errorf("mode layout acquired an unproved native/hidden/register ABI")
	}
	return nil
}

func instrumentationResolvedSymbol(pkg, sym string) string {
	sym = strings.TrimSuffix(sym, "(SB)")
	if strings.HasPrefix(sym, "·") {
		return pkg + "." + strings.TrimPrefix(sym, "·")
	}
	return strings.ReplaceAll(strings.ReplaceAll(sym, "∕", "/"), "·", ".")
}

func instrumentationConsumptionArch(target string) (plan9asm.Arch, error) {
	_, arch, _ := strings.Cut(target, "/")
	switch arch {
	case "386", "amd64":
		return plan9asm.ArchAMD64, nil
	case "arm":
		return plan9asm.ArchARM, nil
	case "arm64":
		return plan9asm.ArchARM64, nil
	case "wasm":
		return plan9asm.ArchWASM, nil
	}
	return "", fmt.Errorf("unknown mode object architecture")
}

// These are concrete LLVM emission routes, not an instrumentation-support
// table. Stock Go's source rules/actual mode observation independently decide
// target eligibility; an unbound LLVM backend route remains a real failure.
func instrumentationConsumptionTriple(target string) string {
	return map[string]string{
		"linux/386": "i386-unknown-linux-gnu", "linux/amd64": "x86_64-unknown-linux-gnu",
		"linux/arm": "armv7-unknown-linux-gnueabihf", "linux/arm64": "aarch64-unknown-linux-gnu",
		"darwin/386": "i386-apple-macosx", "darwin/amd64": "x86_64-apple-macosx", "darwin/arm64": "arm64-apple-macosx",
		"windows/386": "i686-pc-windows-msvc", "windows/amd64": "x86_64-pc-windows-msvc", "windows/arm64": "aarch64-pc-windows-msvc",
		"js/wasm": "wasm32-unknown-unknown", "wasip1/wasm": "wasm32-wasi",
	}[target]
}
