package plan9asm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type numericalSBNativeProof struct {
	Archive, OriginalObject, ExpandedObject []byte
	OriginalListing, ExpandedListing        []byte
	OriginalText, ExpandedText              []gostaticstorage.TextRecord
	ArchiveMembers                          []gostaticstorage.TextMember
	Sources                                 map[string][]byte
	CompilerAliases                         map[string]numericalCompilerAliasWitness
	ArgumentRules                           map[string]string
}

func (source *GoX86NumericalReadSource) bindNative(ctx context.Context, variables map[string]numericalSBRead, environment map[string]string) error {
	if err := source.preprocess(); err != nil {
		return err
	}
	tailRoles, err := numericalDirectTailRoles(source.file)
	if err != nil {
		return err
	}
	guard := source.guard
	selected := guard.selection
	_, arch, _ := strings.Cut(source.request.Target, "/")
	builtin, err := guard.read(filepath.Join(guard.env["GOROOT"], "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		return err
	}
	proof := &source.native
	assembly := source.sdkAssemblyJoin()
	proof.Archive, err = guard.read(selected.Export)
	if err != nil {
		return err
	}
	if source.role == numericalSBSDKSource {
		if source.sdk == nil || source.sdk.origin != source || source.sdk.closed {
			return numericalSBContext("native observation lacks the live exact SDK input graph")
		}
		if assembly != nil {
			if !bytes.Equal(proof.Archive, assembly.Observation.ObjectInputs.Archive) {
				return numericalSBContext("literal native archive changed")
			}
			proof.ArchiveMembers = source.sdk.ArchiveMembers
		} else {
			proof.ArchiveMembers, err = gostaticstorage.ObserveX86SDKAssemblyArchiveReferences(proof.Archive, builtin, source.request.Target,
				selected.SFiles, source.sdk.Referenced)
		}
	} else {
		proof.ArchiveMembers, err = gostaticstorage.ObserveX86AssemblyArchive(proof.Archive, builtin, source.request.Target, selected.SFiles)
	}
	if err != nil {
		return numericalSBContext("complete actual compiler/archive role: %v", err)
	}
	found := false
	for _, name := range selected.SFiles {
		found = found || name == source.request.AssemblyFile
	}
	if !found {
		return numericalSBContext("assembly is not actually selected")
	}
	expanded := filepath.Join(guard.owned, "expanded.s")
	expandedProgram := source.cpp.Output
	var sourcePositions [][]string
	if assembly != nil {
		positioned := assembly.Observation.Positions[assembly.SourceOrdinal]
		expandedProgram = positioned.Mapped
		sourcePositions, err = numericalSDKLiteralSourcePositions(source.file, source.cpp.Output, positioned)
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(expanded, []byte(expandedProgram), 0600); err != nil {
		return err
	}
	if _, err := guard.read(expanded); err != nil {
		return err
	}
	assemble := func(input, output string) ([]byte, []byte, error) {
		arguments := []string{"tool", "asm", "-S", "-p", source.request.PackagePath, "-I", source.request.Directory, "-I", filepath.Join(guard.env["GOROOT"], "pkg", "include")}
		if assembly != nil {
			// Match the independent SDK header producer's complete source and
			// generated-header route; no user header or substituted constant.
			arguments = []string{"tool", "asm", "-S", "-p", source.request.PackagePath, "-std",
				"-I", assembly.source.guard.owned, "-I", filepath.Join(guard.env["GOROOT"], "pkg", "include")}
		}
		if source.role == numericalSBSDKSource && environment["GOOS"] == "darwin" {
			arguments = append(arguments, "-shared")
		}
		for _, define := range GoAssemblerDefinesWithEnv(environment["GOOS"], arch, environment) {
			arguments = append(arguments, "-D", define)
		}
		arguments = append(arguments, "-o", output, input)
		listing, err := source.run(ctx, arguments...)
		if err != nil {
			return nil, listing, err
		}
		object, err := guard.read(output)
		return object, listing, err
	}
	proof.OriginalObject, proof.OriginalListing, err = assemble(filepath.Join(source.request.Directory, source.request.AssemblyFile), filepath.Join(guard.owned, "original.o"))
	if err != nil {
		return err
	}
	proof.ExpandedObject, proof.ExpandedListing, err = assemble(expanded, filepath.Join(guard.owned, "expanded.o"))
	if err != nil {
		return err
	}
	if assembly != nil {
		proof.OriginalText, proof.ExpandedText, err = gostaticstorage.ObserveX86SDKASMDataListingObjects(
			assembly.Observation.ObjectInputs, assembly.SourceOrdinal, proof.OriginalObject, proof.ExpandedObject)
	} else {
		proof.OriginalText, err = gostaticstorage.ObserveX86AssemblyText(proof.OriginalObject, builtin, source.request.Target)
		if err == nil {
			proof.ExpandedText, err = gostaticstorage.ObserveX86AssemblyText(proof.ExpandedObject, builtin, source.request.Target)
		}
	}
	if err != nil || len(proof.OriginalText) != len(proof.ExpandedText) || len(proof.OriginalText) != len(source.file.Funcs) {
		return numericalSBContext("original/expanded complete TEXT differs: %v", err)
	}
	originalRows, err := numericalListingRows(proof.OriginalListing)
	if err != nil {
		return err
	}
	expandedRows, err := numericalListingRows(proof.ExpandedListing)
	if err != nil {
		return err
	}
	var textOrder []int
	if assembly != nil {
		observed := assembly.Observation.Objects.Sources[assembly.SourceOrdinal]
		textOrder, err = numericalSDKNativeTextOrder(source.cpp.Output, source.request.PackagePath,
			observed, proof.OriginalText, proof.ExpandedText)
		if err != nil {
			return err
		}
	}
	for index, fn := range source.file.Funcs {
		objectOrdinal := index
		if textOrder != nil {
			objectOrdinal = textOrder[index]
		}
		text, expandedText := proof.OriginalText[objectOrdinal], proof.ExpandedText[objectOrdinal]
		name, abi, valid := source.numericalSourceTextIdentity(index, fn, arch)
		if !valid || text.Name != name || text.ABI != abi || expandedText.Name != name || expandedText.ABI != abi ||
			!bytes.Equal(text.Code, expandedText.Code) || text.Size != expandedText.Size || !numericalRelocationEqual(text.Relocations, expandedText.Relocations) {
			return numericalSBContext("whole original/expanded TEXT/ABI/code/relocations differ")
		}
		memberMatches := 0
		memberOrdinal := -1
		for ordinal, name := range selected.SFiles {
			if name == source.request.AssemblyFile {
				if memberOrdinal >= 0 {
					return numericalSBContext("selected assembly repeats its native member identity")
				}
				memberOrdinal = ordinal + 2 // Actual work/gc.go compiler then selected ASM order.
			}
		}
		if memberOrdinal < 2 || memberOrdinal >= len(proof.ArchiveMembers) {
			return numericalSBContext("selected source has no original archive member ordinal")
		}
		for ordinal, member := range proof.ArchiveMembers {
			if ordinal != memberOrdinal {
				continue
			}
			for _, record := range member.Texts {
				if record.Name == text.Name && record.ABI == text.ABI && record.Size == text.Size && bytes.Equal(record.Code, text.Code) && numericalRelocationEqual(record.Relocations, text.Relocations) {
					memberMatches++
				}
			}
		}
		if memberMatches != 1 {
			return numericalSBContext("original assembler TEXT does not match its actual selected archive member")
		}
		lines := strings.Split(source.cpp.Output, "\n")
		textLine := 0
		for line, physical := range lines {
			if strings.TrimSpace(physical) == fn.Instrs[0].Raw {
				if textLine != 0 {
					return numericalSBContext("ambiguous expanded physical TEXT identity")
				}
				textLine = line + 1
			}
		}
		if textLine == 0 {
			return numericalSBContext("missing expanded physical TEXT identity")
		}
		textEnd := len(lines) + 1
		for line, physical := range lines[textLine:] {
			for _, other := range source.file.Funcs {
				if strings.TrimSpace(physical) == other.Instrs[0].Raw {
					textEnd = textLine + line + 1
					break
				}
			}
			if textEnd != len(lines)+1 {
				break
			}
		}
		mode := 64
		if arch == "386" {
			mode = 32
		}
		// The full native stream must have trusted instruction boundaries,
		// including vector instructions and unreachable bytes. Only the
		// independent scalar decoder map can supply a numerical read below.
		decoded, err := numericalNativeReads(text.Code, mode)
		if err != nil {
			return err
		}
		for ordinal, ins := range fn.Instrs {
			if _, terminal := tailRoles[x86DirectTailPoint{index, ordinal}]; terminal {
				continue // Exact source control role; no data/entry/state authority.
			}
			containsSymbol := false
			for operandIndex, operand := range ins.Args {
				local, err := source.sdkLiteralRead(ins, operandIndex, arch)
				if err != nil {
					return err
				}
				containsSymbol = containsSymbol || operand.Kind == OpSym && !local
				if operand.Kind == OpMem && operand.Mem.Sym != "" && !local {
					return numericalSBContext("indexed/alternate SB memory role needs separate binding")
				}
			}
			if !containsSymbol {
				continue
			}
			operandIndex, width, valid := x86NumericalSBReadShape(ins, arch)
			if !valid {
				return numericalSBContext("symbol address/write/unregistered numerical read form")
			}
			base, offset, valid := parseSBRef(ins.Args[operandIndex].Sym)
			if !valid || strings.Contains(base, "<") {
				return numericalSBContext("unknown source SB storage identity")
			}
			owner, exists := variables[numericalNativeName(base, source.request.PackagePath)]
			if !exists || !numericalOwnerContains(owner.variable, offset, width) {
				return numericalSBContext("read bytes lack exact numerical owner span")
			}
			matches := 0
			for pc, native := range decoded {
				for _, row := range expandedRows[name][pc] {
					if !numericalSameInstruction(ins, row.ins, source.request.PackagePath, arch) {
						continue
					}
					if assembly != nil {
						if !numericalSDKLiteralReadOrdinal(fn, ordinal, sourcePositions[index], pc, row,
							expandedRows[name], source.request.PackagePath, arch) {
							continue
						}
					} else {
						// The expanded physical line must select this exact ordinal;
						// repeated identical instructions cannot borrow another row.
						separator := strings.LastIndexByte(row.position, ':')
						if separator < 0 || row.position[:separator] != expanded {
							return numericalSBContext("expanded listing source role differs")
						}
						line, err := strconv.Atoi(row.position[separator+1:])
						if err != nil || line <= textLine || line >= textEnd || strings.TrimSpace(lines[line-1]) != ins.Raw {
							return numericalSBContext("expanded source ordinal/physical line differs")
						}
						priorCount := 0
						for _, prior := range fn.Instrs[:ordinal] {
							if prior.Raw == ins.Raw {
								priorCount++
							}
						}
						physicalCount := 0
						for _, physical := range lines[textLine : line-1] {
							if strings.TrimSpace(physical) == ins.Raw {
								physicalCount++
							}
						}
						if priorCount != physicalCount {
							continue
						}
					}
					originalMatches := 0
					for _, original := range originalRows[name][pc] {
						if numericalSameInstruction(ins, original.ins, source.request.PackagePath, arch) {
							for _, position := range text.Positions {
								path := original.position
								objectFile := position.File
								if assembly != nil {
									var valid bool
									path, valid = numericalSDKListingLogicalPosition(path)
									if !valid {
										return numericalSBContext("unknown SDK original source-position display")
									}
									objectFile, valid = source.sdkLiteralObjectSource(objectFile)
									if !valid {
										continue
									}
								} else {
									// Go's object writer uses forward slashes on Windows.
									// Decode spelling only; the exact CPP input join below
									// still establishes source identity and PC ownership.
									var valid bool
									objectFile, valid = originalGoObjectSourcePath(objectFile, "")
									if !valid {
										continue
									}
								}
								colon := strings.LastIndexByte(path, ':')
								line, err := strconv.Atoi(path[colon+1:])
								if colon >= 0 && err == nil && position.Start <= pc && pc < position.End && objectFile == path[:colon] && int32(line) == position.Line {
									for _, input := range source.cpp.Sources {
										if input.File == objectFile {
											originalMatches++
										}
									}
								}
							}
						}
					}
					if originalMatches != 1 || native.width != int(width) || native.addressBits != mode {
						var locations []string
						for _, position := range text.Positions {
							if position.Start <= pc && pc < position.End {
								locations = append(locations, fmt.Sprintf("%s:%d", position.File, position.Line))
							}
						}
						return numericalSBContext("native read width/source-PC role differs: source matches=%d width=%d/%d address=%d/%d listing=%s binary=%v", originalMatches, native.width, width, native.addressBits, mode, row.position, locations)
					}
					if !native.matchesSource(ins, operandIndex, arch) {
						return numericalSBContext("read has unbound native opcode/segment/index/base role")
					}
					relocation, physicalOffset, err := native.relocation(text, pc, arch)
					if err != nil || physicalOffset != offset || relocation.Target.Name != owner.variable.NativeName {
						return numericalSBContext("whole native address/addend/owner differs: source=%s code=%x field=%d offset=%d/%d: %v", ins.Raw,
							text.Code[pc:pc+int64(native.length)], native.addressField, physicalOffset, offset, err)
					}
					matches++
					read := owner
					function := name
					if strings.HasSuffix(fn.Sym, "<>") {
						function = numericalNativeName(fn.Sym, source.request.PackagePath)
					}
					read.function, read.instruction, read.original = function, ordinal, ins
					read.operand = operandIndex
					read.pc, read.offset, read.width, read.relocation = pc, offset, width, relocation
					read.code = append([]byte(nil), text.Code[pc:pc+int64(native.length)]...)
					source.reads = append(source.reads, read)
				}
			}
			if matches != 1 {
				if assembly != nil {
					var positions []string
					for pc, rows := range expandedRows[name] {
						for _, row := range rows {
							if numericalSameInstruction(ins, row.ins, source.request.PackagePath, arch) {
								positions = append(positions, fmt.Sprintf("%d@%s", pc, row.position))
							}
						}
					}
					return numericalSBContext("missing/ambiguous mapped source/native read: %s; expected %s, observed %v", ins.Raw, sourcePositions[index][ordinal], positions)
				}
				return numericalSBContext("missing/ambiguous whole source instruction/native read join: %s", ins.Raw)
			}
		}
	}
	if len(source.reads) == 0 {
		return numericalSBContext("source has no certified numerical SB reads")
	}
	if err := source.captureCompilerAliases(); err != nil {
		return err
	}
	if err := source.captureAMD64GoArgumentRules(); err != nil {
		return err
	}
	proof.Sources = make(map[string][]byte)
	for name := range guard.inputs {
		if goAssemblyPathWithinRoot(source.request.Directory, name) || strings.HasPrefix(name, filepath.Join(guard.env["GOROOT"], "pkg", "include")+string(filepath.Separator)) {
			proof.Sources[name], err = guard.read(name)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// A source ordinal and a physical goobj ordinal are separate identities. This
// consumes the already authenticated complete SDK member, retaining every native
// code/PC/relocation record in its original order. It supplies no entry, helper,
// closure, declaration or numerical read authority.
func numericalSDKNativeTextOrder(program, packagePath string, observed gostaticstorage.ASMDataSourceObservation,
	original, expanded []gostaticstorage.TextRecord,
) ([]int, error) {
	if len(original) == 0 || !reflect.DeepEqual(original, observed.Original.Texts) ||
		!reflect.DeepEqual(expanded, observed.Expanded.Texts) {
		return nil, numericalSBContext("native TEXT records differ from the complete original SDK member")
	}
	first, second := observed.Original, observed.Expanded
	first.Texts, second.Texts = original, expanded
	actual, err := gostaticstorage.ASMSourceTextOrder([]byte(program), packagePath, first)
	if err != nil {
		return nil, numericalSBContext("original native source TEXT association differs: %v", err)
	}
	replayed, err := gostaticstorage.ASMSourceTextOrder([]byte(program), packagePath, second)
	if err != nil || !reflect.DeepEqual(actual, replayed) || !reflect.DeepEqual(actual, observed.TextOrder) {
		return nil, numericalSBContext("complete source/original/expanded TEXT association differs: %v", err)
	}
	order := make([]int, len(original))
	for ordinal, association := range actual {
		order[ordinal] = association.ObjectOrdinal
	}
	return order, nil
}

// This binds an explicit source ABI selector to the original native object.
// It creates no entry, frame or initialization permission. AMD64 scalar
// register transport must independently pass its complete source/result proof.
func numericalFunctionSourceIdentity(symbol, pkg, arch string, role numericalSBSourceRole) (string, uint16, bool) {
	abi := uint16(0)
	if strings.HasSuffix(symbol, "<ABIInternal>") {
		if role != numericalSBSDKSource || arch != "amd64" {
			return "", 0, false
		}
		abi = 1
		symbol = strings.TrimSuffix(symbol, "<ABIInternal>")
	} else if strings.HasSuffix(symbol, "<ABI0>") {
		symbol = strings.TrimSuffix(symbol, "<ABI0>")
	}
	if strings.ContainsAny(symbol, "<>") {
		return "", 0, false
	}
	return numericalNativeName(symbol, pkg), abi, true
}
