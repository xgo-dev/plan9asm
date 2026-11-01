package plan9asm

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type sdkLiteralLinkedSymbol struct {
	name                                        string
	value, size, sectionStart, sectionAlignment uint64
	data                                        []byte
	readonly, sized                             bool
}

// The observed address is used only to reject mismatches in this actual image.
// It is never exported as a number or used to infer additional address bits.
func sdkLiteralLinkedMinima(image []byte, target, pkg string, initializers []gostaticstorage.ReadonlyLiteralDataImage,
	inventory []gostaticstorage.SDKArchiveDefinitionIdentity) ([]sdkLiteralMinimumAlignment, error) {
	symbols, err := sdkLiteralImageSymbols(image, target)
	if err != nil {
		return nil, err
	}
	var result []sdkLiteralMinimumAlignment
	for _, literal := range initializers {
		definition := literal.Definition
		if definition.Name == "" || definition.Namespace != gostaticstorage.TextSymbolSelf || definition.ABI != 65535 ||
			definition.Kind != 3 || definition.Flags != 0 || definition.Flags2 != 0 || definition.Align != 0 ||
			len(definition.Hash) != 0 || len(definition.Relocations) != 0 || definition.Size == 0 || len(literal.Initial) != int(definition.Size) {
			return nil, sdkASMDataContext("minimum alignment requires exact private readonly unset-alignment object storage")
		}
		count, exact := 0, false
		for _, item := range inventory {
			if item.Name != definition.Name {
				continue
			}
			count++
			if item.PackagePath == pkg && item.MemberOrdinal == literal.MemberOrdinal && item.MemberName == literal.MemberName &&
				item.Namespace == definition.Namespace && item.Index == definition.Index && item.ABI == definition.ABI &&
				item.Kind == definition.Kind && item.Flags == definition.Flags && item.Flags2 == definition.Flags2 &&
				item.Size == definition.Size && item.Align == definition.Align {
				exact = true
			}
		}
		if !exact {
			return nil, sdkASMDataContext("minimum alignment lost original complete archive definition identity")
		}
		if count != 1 {
			continue
		} // No byte-identical/name-identical winner selection.
		var linked *sdkLiteralLinkedSymbol
		matches := 0
		for index := range symbols {
			if symbols[index].name == definition.Name {
				linked = &symbols[index]
				matches++
			}
		}
		if matches != 1 {
			continue
		} // Linker-native dead stripping/ambiguity is not permission.
		_, arch, _ := strings.Cut(target, "/")
		minimum := uint64(goAssemblyDataAlignment(Arch(arch), int64(definition.Size)))
		if !linked.readonly || linked.sized && linked.size != uint64(definition.Size) || linked.value < linked.sectionStart ||
			linked.value%minimum != 0 || linked.sectionAlignment < minimum || linked.sectionAlignment%minimum != 0 {
			return nil, sdkASMDataContext("original linked literal violates its registered section/symbol minimum alignment")
		}
		offset := linked.value - linked.sectionStart
		if offset > uint64(len(linked.data)) || uint64(definition.Size) > uint64(len(linked.data))-offset ||
			!bytes.Equal(linked.data[offset:offset+uint64(definition.Size)], literal.Initial) {
			return nil, sdkASMDataContext("original linked literal bytes/extent differ from its exact source/object initializer")
		}
		result = append(result, sdkLiteralMinimumAlignment{SourceOrdinal: literal.SourceOrdinal, MemberOrdinal: literal.MemberOrdinal,
			Namespace: definition.Namespace, Index: definition.Index, Name: definition.Name,
			Size: definition.Size, MinimumAlignment: uint32(minimum)})
	}
	return result, nil
}

func sdkLiteralImageSymbols(image []byte, target string) ([]sdkLiteralLinkedSymbol, error) {
	if len(image) == 0 || len(image) > 64<<20 || !gostaticstorage.X86SDKTarget(target) {
		return nil, sdkASMDataContext("minimum alignment linked image is unavailable or outside its exact target/byte bound")
	}
	_, arch, _ := strings.Cut(target, "/")
	var result []sdkLiteralLinkedSymbol
	switch {
	case strings.HasPrefix(target, "linux/"):
		file, err := elf.NewFile(bytes.NewReader(image))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if file.Type != elf.ET_EXEC || file.Data != elf.ELFDATA2LSB ||
			arch == "amd64" && (file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64) ||
			arch == "386" && (file.Class != elf.ELFCLASS32 || file.Machine != elf.EM_386) {
			return nil, sdkASMDataContext("minimum alignment ELF target/default executable profile differs")
		}
		symbols, err := file.Symbols()
		if err != nil {
			return nil, err
		}
		sections := make(map[*elf.Section][]byte)
		for _, symbol := range symbols {
			if symbol.Name == "" || symbol.Section == elf.SHN_UNDEF || int(symbol.Section) >= len(file.Sections) {
				continue
			}
			section := file.Sections[symbol.Section]
			readonly := section.Type == elf.SHT_PROGBITS && section.Flags == elf.SHF_ALLOC && elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT
			data := sections[section]
			if readonly && data == nil {
				if section.Size > 64<<20 {
					return nil, sdkASMDataContext("literal linker ELF section exceeds its byte bound")
				}
				data, err = section.Data()
				if err != nil {
					return nil, err
				}
				sections[section] = data
			}
			result = append(result, sdkLiteralLinkedSymbol{name: symbol.Name, value: symbol.Value, size: symbol.Size,
				sectionStart: section.Addr, sectionAlignment: section.Addralign, data: data, sized: true,
				readonly: readonly})
		}
	case target == "darwin/amd64":
		file, err := macho.NewFile(bytes.NewReader(image))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if file.Cpu != macho.CpuAmd64 || file.Type != macho.TypeExec || file.Flags&macho.FlagPIE == 0 || file.Symtab == nil {
			return nil, sdkASMDataContext("minimum alignment Mach-O target/default PIE profile differs")
		}
		sections := make(map[*macho.Section][]byte)
		for _, symbol := range file.Symtab.Syms {
			if symbol.Name == "" || symbol.Sect == 0 || int(symbol.Sect) > len(file.Sections) {
				continue
			}
			section := file.Sections[int(symbol.Sect)-1]
			readonly := symbol.Type&0x0e == 0x0e && section.Seg == "__TEXT" && section.Name == "__rodata"
			data := sections[section]
			if readonly && data == nil {
				if section.Size > 64<<20 {
					return nil, sdkASMDataContext("literal linker Mach-O section exceeds its byte bound")
				}
				data, err = section.Data()
				if err != nil {
					return nil, err
				}
				sections[section] = data
			}
			if section.Align > 31 {
				return nil, sdkASMDataContext("minimum alignment Mach-O section bound differs")
			}
			result = append(result, sdkLiteralLinkedSymbol{name: strings.TrimPrefix(symbol.Name, "_"), value: symbol.Value,
				sectionStart: section.Addr, sectionAlignment: uint64(1) << section.Align, data: data,
				readonly: readonly})
		}
	case strings.HasPrefix(target, "windows/"):
		file, err := pe.NewFile(bytes.NewReader(image))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if arch == "amd64" && file.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || arch == "386" && file.Machine != pe.IMAGE_FILE_MACHINE_I386 || file.Characteristics&0x2002 != 2 {
			return nil, sdkASMDataContext("minimum alignment PE target/executable profile differs")
		}
		var base, alignment uint64
		switch header := file.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			if arch != "amd64" || header.DllCharacteristics&0x40 == 0 {
				return nil, sdkASMDataContext("minimum alignment PE64 default PIE profile differs")
			}
			base, alignment = header.ImageBase, uint64(header.SectionAlignment)
		case *pe.OptionalHeader32:
			if arch != "386" || header.DllCharacteristics&0x40 == 0 {
				return nil, sdkASMDataContext("minimum alignment PE32 default PIE profile differs")
			}
			base, alignment = uint64(header.ImageBase), uint64(header.SectionAlignment)
		default:
			return nil, sdkASMDataContext("minimum alignment PE optional header is absent")
		}
		if alignment < 32 || alignment&(alignment-1) != 0 || base%alignment != 0 {
			return nil, sdkASMDataContext("minimum alignment PE image base/section placement differs")
		}
		sections := make(map[*pe.Section][]byte)
		for _, symbol := range file.Symbols {
			if symbol.SectionNumber <= 0 || int(symbol.SectionNumber) > len(file.Sections) || symbol.Name == "" {
				continue
			}
			section := file.Sections[int(symbol.SectionNumber)-1]
			readonly := section.Characteristics&0x20 == 0 && section.Characteristics&0x40 != 0 && section.Characteristics&0xc0000000 == 0x40000000
			data := sections[section]
			if readonly && data == nil {
				if section.Size > 64<<20 {
					return nil, sdkASMDataContext("literal linker PE section exceeds its byte bound")
				}
				data, err = section.Data()
				if err != nil {
					return nil, err
				}
				sections[section] = data
			}
			start := base + uint64(section.VirtualAddress)
			result = append(result, sdkLiteralLinkedSymbol{name: symbol.Name, value: start + uint64(symbol.Value),
				sectionStart: start, sectionAlignment: alignment, data: data,
				readonly: readonly})
		}
	}
	return result, nil
}
