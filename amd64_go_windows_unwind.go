package plan9asm

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

func (source *GoAMD64FrameSource) observeWindowsUnwind(object []byte, privateLeaves ...[]gostaticstorage.TextRecord) (gostaticstorage.WindowsAMD64AssemblyUnwind, error) {
	var empty gostaticstorage.WindowsAMD64AssemblyUnwind
	for _, declaration := range source.declarations {
		if !fixedLocalTransportRole(declaration.transport) {
			return empty, goAMD64FrameContext("Windows unwind join requires the closed typed ABI0 transport scope")
		}
	}
	builtin, err := gostaticstorage.WindowsAMD64UnwindSources(source.env["GOVERSION"], func(name string) ([]byte, error) {
		return source.read(filepath.Join(source.env["GOROOT"], filepath.FromSlash(name)))
	})
	if err != nil {
		return empty, goAMD64FrameContext("Windows unwind actual SDK sources: %v", err)
	}
	observed, err := gostaticstorage.ObserveWindowsAMD64AssemblyUnwind(object, builtin, privateLeaves...)
	if err != nil {
		return empty, goAMD64FrameContext("Windows unwind complete object metadata: %v", err)
	}
	if observed.Version != source.env["GOVERSION"] {
		return empty, goAMD64FrameContext("Windows unwind object differs from its actual producer")
	}
	return observed, nil
}

// Only the complete original source classification can select leaf records.
// Keep their full raw object identity, including namespace, ABI, bytes and PCs;
// neither a static ABI number nor absent SEH metadata establishes this role.
func goAMD64WindowsPrivateLeafTexts(file *File, pkg GoPackage, listing []byte,
	data *gostaticstorage.AMD64AssemblyData) ([]gostaticstorage.TextRecord, error) {
	leaves, err := goAMD64FramePrivateLeaves(file, pkg)
	if err != nil || len(leaves) == 0 {
		return nil, err
	}
	if data == nil {
		return nil, goAMD64FrameContext("Windows private leaf requires its original source/object association")
	}
	records, err := sdkAMD64FrameNativeRecordsForSource(listing, data.Member.Texts, data.TextOrder)
	if err != nil || len(records) != len(file.Funcs) {
		return nil, goAMD64FrameContext("Windows private leaf lacks a complete source/object TEXT association: %v", err)
	}
	var result []gostaticstorage.TextRecord
	for index, fn := range file.Funcs {
		if !leaves[fn.Sym] {
			continue
		}
		text := data.Member.Texts[data.TextOrder[index].ObjectOrdinal]
		abi, namespace := uint16(0), gostaticstorage.TextSymbolNonpkgDefinition
		if strings.HasSuffix(fn.Sym, "<>") {
			abi, namespace = 65535, gostaticstorage.TextSymbolSelf
		}
		if text.Name != strings.TrimSuffix(fn.Sym, "<>") || text.ABI != abi || text.Namespace != namespace ||
			!records[index].ordinaryFrameRole() || records[index].Locals != uint64(goAMD64FrameNativeLocals(fn.FrameSize)) {
			return nil, goAMD64FrameContext("Windows private leaf changed its exact source symbol/ABI/namespace")
		}
		result = append(result, text)
	}
	return result, nil
}

func goAMD64WindowsUnwindByteRow(line string, offset int, expected []byte) ([]byte, error) {
	pc, actual, err := goAssemblyListingByteRow(line)
	if err != nil || len(expected) != 12 || offset != 0 || pc != 0 || !bytes.Equal(actual, expected) {
		return nil, goAMD64FrameContext("Windows unwind listing differs from complete original binary bytes")
	}
	return actual, nil
}

// This private join consumes the factory's independently read whole object.
// A public offline observation is never itself an authorization input.
func goAMD64FrameWindowsUnwindListing(listing []byte, file *File, pkg GoPackage, origins map[string]int, directory string, observed gostaticstorage.WindowsAMD64AssemblyUnwind) (map[string]goAMD64FrameFunction, error) {
	functions, err := goAMD64FrameListingWithSplitObject(listing, file, pkg, origins, observed.Texts, &observed, "windows/amd64", directory, "")
	if err != nil {
		return nil, err
	}
	if err := goAMD64FrameWindowsUnwindFunctions(functions, origins, directory, observed); err != nil {
		return nil, err
	}
	return functions, nil
}

func goAMD64FrameWindowsUnwindFunctions(functions map[string]goAMD64FrameFunction, origins map[string]int, directory string, observed gostaticstorage.WindowsAMD64AssemblyUnwind) error {
	if len(observed.Texts) != len(functions) {
		return goAMD64FrameContext("Windows object/listing complete TEXT inventories differ")
	}
	unwind := make(map[string]gostaticstorage.WindowsAMD64UnwindRecord)
	for _, record := range observed.Unwind {
		unwind[record.Name] = record
	}
	seen := make(map[string]bool)
	for _, text := range observed.Texts {
		fn, exists := functions[text.Name]
		abi := uint16(0)
		if fn.privateLeaf {
			abi = fn.nativeABI
		}
		if !exists || seen[text.Name] || text.ABI != abi || text.Kind != 1 || text.Flags != fn.nativeFlags() || text.Flags2 != observed.TextFlags2 ||
			!bytes.Equal(text.Code, fn.code) || fn.prologue < 0 || fn.prologue >= len(fn.code) {
			return goAMD64FrameContext("Windows object/listing TEXT name/ABI/code role differs")
		}
		seen[text.Name] = true
		var metadata gostaticstorage.WindowsAMD64UnwindRecord
		for _, aux := range text.Auxiliary {
			if aux.Type == observed.AuxType {
				metadata = unwind[aux.Target.Name]
			}
		}
		if fn.privateLeaf && fn.locals == 0 {
			if metadata.Name != "" || fn.prologue != 0 || fn.split {
				return goAMD64FrameContext("Windows private leaf acquired an automatic frame or SEH prologue")
			}
			if err := goAMD64FrameMachineShapeWithCalls(fn, 0, nil); err != nil {
				return err
			}
			if err := goAMD64FrameSourcePCs(text, fn, directory, origins, ""); err != nil {
				return err
			}
			continue
		}
		first, err := x86asm.Decode(fn.code[fn.prologue:], 64)
		if err != nil || first.Op != x86asm.PUSH || first.Args[0] != x86asm.RBP || fn.prologue+first.Len != int(metadata.PushEnd) {
			return goAMD64FrameContext("Windows unwind push end differs from actual automatic prologue")
		}
		second, err := x86asm.Decode(fn.code[fn.prologue+first.Len:], 64)
		if err != nil || second.Op != x86asm.MOV || second.Args[0] != x86asm.RBP || second.Args[1] != x86asm.RSP ||
			fn.prologue+first.Len+second.Len != int(metadata.PrologueEnd) {
			return goAMD64FrameContext("Windows unwind frame end differs from actual automatic prologue")
		}
		if err := goAMD64FrameSourcePCs(text, fn, directory, origins, ""); err != nil {
			return err
		}
	}
	return nil
}

func goAMD64FrameSourcePath(name, directory, root string) string {
	if strings.HasPrefix(name, "$GOROOT/") {
		if root == "" {
			return ""
		}
		actual, valid := originalGoObjectSourcePath(name, root)
		if !valid {
			return ""
		}
		return actual
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(directory, filepath.FromSlash(name))
	}
	return filepath.Clean(name)
}

func goAMD64FrameSourcePCs(text gostaticstorage.TextRecord, fn goAMD64FrameFunction, directory string, origins map[string]int, root string) error {
	normalize := func(name string) string { return goAMD64FrameSourcePath(name, directory, root) }
	// Go object file tables use slash paths on Windows, while captured
	// origins retain host paths and the command's relative source spelling.
	// Compare their already-bound paths consistently with the listing join;
	// aliases must still agree on the complete original source extent. SDK
	// metadata additionally uses only the captured root's strict path spelling;
	// resolving it never adds an input to this complete original inventory.
	linesByPath := make(map[string]int, len(origins))
	for name, lines := range origins {
		path := normalize(name)
		if path == "" {
			return goAMD64FrameContext("source origin has an unbound SDK path")
		}
		if previous, found := linesByPath[path]; found && previous != lines {
			return goAMD64FrameContext("source origin aliases disagree on their original extent")
		}
		linesByPath[path] = lines
	}
	var previous int64
	for _, span := range text.Positions {
		if span.File == "" || span.Line <= 0 || int(span.Line) > linesByPath[normalize(span.File)] || span.Start < 0 ||
			span.Start != previous || span.End <= span.Start || span.End > int64(len(fn.code)) {
			return goAMD64FrameContext("object source-PC interval lacks its original file/line/extent: %s %s:%d [%d,%d)",
				text.Name, span.File, span.Line, span.Start, span.End)
		}
		previous = span.End
	}
	if previous != int64(len(fn.code)) {
		return goAMD64FrameContext("source-PC intervals do not cover the complete physical TEXT")
	}
	for pc, positions := range fn.sourcePositions {
		matched := false
		for _, span := range text.Positions {
			if span.Start > int64(pc) || span.End <= int64(pc) {
				continue
			}
			for _, position := range positions {
				if normalize(position.file) == normalize(span.File) && position.line == int(span.Line) {
					matched = true
				}
			}
		}
		if !matched {
			return goAMD64FrameContext("object/listing source-PC file/line witness differs")
		}
	}
	return nil
}
