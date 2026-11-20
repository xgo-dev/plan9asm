package plan9asm

import (
	"fmt"
	"go/types"
	"sort"
	"strconv"
	"strings"
)

func dataAddress(d DataStmt) (string, int64, error) {
	if !strings.HasSuffix(d.Addr, "(SB)") {
		return "", 0, fmt.Errorf("DATA %s: address must name an SB symbol: %q", d.Sym, d.Addr)
	}
	base, offset, ok := parseSBRef(d.Addr)
	if !ok || base == "" || strings.ContainsAny(base, "+- \t\r\n()\"'`") {
		return "", 0, fmt.Errorf("DATA %s: unresolved or malformed address %q", d.Sym, d.Addr)
	}
	return base, offset, nil
}

func validateDataRelocations(file *File, goarch string) error {
	hasAddress := false
	for _, d := range file.Data {
		hasAddress = hasAddress || d.Addr != ""
	}
	if !hasAddress {
		return nil
	}
	if goarch == "" {
		goarch = string(file.Arch)
	}
	sizes := types.SizesFor("gc", goarch)
	if sizes == nil {
		return fmt.Errorf("DATA relocation has no Go pointer-size contract for %q", goarch)
	}
	pointerSize := sizes.Sizeof(types.Typ[types.Uintptr])
	last := make(map[string]int64)
	for _, d := range file.Data {
		end, err := dataStmtEnd(d)
		if err != nil {
			return err
		}
		if previous, exists := last[d.Sym]; exists && d.Off < previous {
			return fmt.Errorf("overlapping DATA entry for %s", d.Sym)
		}
		last[d.Sym] = end
		if d.Addr == "" {
			continue
		}
		if d.Width != pointerSize || d.Payload != nil || d.Value != 0 {
			return fmt.Errorf("DATA %s: address needs an exclusive %d-byte pointer initializer, got width=%d", d.Sym, pointerSize, d.Width)
		}
		if _, _, err := dataAddress(d); err != nil {
			return err
		}
	}
	return nil
}

func resolveDataSymbol(symbol string, resolve func(string) string) string {
	if strings.ContainsAny(symbol, "·/.") {
		return resolve(symbol)
	}
	return resolve("·" + symbol)
}

func resolveDataAddressSymbol(file *File, symbol string, resolve func(string) string, sigs map[string]FuncSig) string {
	// A plain TEXT name need not use the data-symbol heuristic, especially
	// with the standalone API's identity resolver. Bind known code addresses
	// to the actual LLVM definition, including a caller-supplied symbol alias.
	for _, fn := range file.Funcs {
		if fn.Sym == symbol {
			name := resolve(fn.Sym)
			return funcSigSymbol(name, sigs[name])
		}
	}
	if sig, known := sigs[resolve(symbol)]; known {
		return funcSigSymbol(resolve(symbol), sig)
	}
	name := resolveDataSymbol(symbol, resolve)
	if sig, known := sigs[name]; known {
		return funcSigSymbol(name, sig)
	}
	return name
}

func dataAddressIsFunction(file *File, symbol string, resolve func(string) string, sigs map[string]FuncSig) bool {
	for _, fn := range file.Funcs {
		if fn.Sym == symbol {
			return true
		}
	}
	if _, known := sigs[resolve(symbol)]; known {
		return true
	}
	_, known := sigs[resolveDataSymbol(symbol, resolve)]
	return known
}

// Go wasm stores addresses in eight-byte DATA slots, but LLVM wasm32 has
// four-byte pointers. A widened static ptrtoint is not a legal LLVM constant.
// The wasm MC assembler can instead emit real MEMORY_ADDR_I64/TABLE_INDEX_I64
// relocations. Keep the slot opaque to LLVM, preserving all bytes and addends.
func emitWASMDataRelocations(b *strings.Builder, file *File, name string, buffer []byte, relocations map[int64]DataStmt, resolve func(string) string, sigs map[string]FuncSig, abi WASMABI, readOnly, local bool, align int64) error {
	emit := func(line string) {
		b.WriteString("module asm \"")
		for _, ch := range []byte(line) {
			if ch < 32 || ch > 126 || ch == '"' || ch == '\\' {
				fmt.Fprintf(b, "\\%02X", ch)
			} else {
				b.WriteByte(ch)
			}
		}
		b.WriteString("\"\n")
	}
	symbol := strconv.Quote(name)
	section := ".data."
	kind := "global"
	if readOnly {
		section, kind = ".rodata.", "constant"
	}
	emit(".section " + strconv.Quote(section+name) + ",\"\",@")
	logAlign := 0
	for (int64(1) << logAlign) < align {
		logAlign++
	}
	emit(fmt.Sprintf(".p2align %d", logAlign))
	visibility := ""
	if local {
		emit(".hidden " + symbol)
		visibility = "hidden "
	} else {
		emit(".globl " + symbol)
	}
	// The real LLVM external-global declaration supplies DATA type. Wasm's
	// .type directive rejects quoted package/path symbols even though labels
	// and relocation expressions accept them.
	emit(symbol + ":")
	for offset := int64(0); offset < int64(len(buffer)); {
		if relocation, ok := relocations[offset]; ok {
			base, addend, err := dataAddress(relocation)
			if err != nil {
				return err
			}
			name, function, packed, err := wasmFunctionAddress(file, base, addend, resolve, sigs, abi)
			if err != nil {
				return err
			}
			if packed {
				// The wasm32 table index occupies PC bits 16..47. Place its
				// real I32 relocation at byte 2 of the eight-byte Go slot.
				// This is fully initialized by the linker, even before any
				// host/function entry, and needs no runtime constructor.
				emit(fmt.Sprintf(".int16 %d", addend))
				emit(".int32 " + strconv.Quote(name))
				emit(".int16 0")
				offset += relocation.Width
				continue
			}
			if function && addend != 0 {
				// TABLE_INDEX_I64 has no addend. LLVM MC accepts f+1 but
				// silently drops +1; accepting that would change the source.
				return fmt.Errorf("%w: wasm DATA function address %s has an unrepresentable table-index addend %d", ErrProbeNeedsContext, base, addend)
			}
			value := strconv.Quote(name)
			if addend != 0 {
				value += fmt.Sprintf("%+d", addend)
			}
			emit(".int64 " + value)
			offset += relocation.Width
			continue
		}
		if buffer[offset] == 0 {
			end := offset + 1
			for end < int64(len(buffer)) && buffer[end] == 0 {
				if _, address := relocations[end]; address {
					break
				}
				end++
			}
			emit(fmt.Sprintf(".zero %d", end-offset))
			offset = end
			continue
		}
		bytes := make([]string, 0, 32)
		for offset < int64(len(buffer)) && buffer[offset] != 0 && len(bytes) < 32 {
			if _, address := relocations[offset]; address {
				break
			}
			bytes = append(bytes, strconv.Itoa(int(buffer[offset])))
			offset++
		}
		emit(".byte " + strings.Join(bytes, ","))
	}
	emit(fmt.Sprintf(".size %s,%d", symbol, len(buffer)))
	fmt.Fprintf(b, "%s = external %s%s [%d x i8], align %d\n", llvmGlobal(name), visibility, kind, len(buffer), align)
	return nil
}

// Module assembly references are invisible to the LLVM optimizer. Retain
// every referenced symbol (and holder) explicitly, including private targets.
func emitWASMDataRelocationRoots(b *strings.Builder, file *File, resolve func(string) string, sigs map[string]FuncSig) error {
	roots := make(map[string]bool)
	for _, data := range file.Data {
		if data.Addr == "" {
			continue
		}
		base, _, err := dataAddress(data)
		if err != nil {
			return err
		}
		roots[resolveDataSymbol(data.Sym, resolve)] = true
		roots[resolveDataAddressSymbol(file, base, resolve, sigs)] = true
	}
	if len(roots) == 0 {
		return nil
	}
	names := make([]string, 0, len(roots))
	for name := range roots {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]string, len(names))
	for index, name := range names {
		values[index] = "ptr " + llvmGlobal(name)
	}
	fmt.Fprintf(b, "@llvm.used = appending global [%d x ptr] [%s], section \"llvm.metadata\"\n", len(values), strings.Join(values, ", "))
	return nil
}

// LLVM cannot express a relocation inside a byte-array constant. A packed
// aggregate preserves every byte offset while retaining pointer relocations.
// Integer transport uses Go's pointer width on native targets. GEP is
// deliberately not inbounds: Go accepts signed
// symbol addends without asserting an object extent.
func dataRelocationInitializer(file *File, buffer []byte, relocations map[int64]DataStmt, resolve func(string) string, sigs map[string]FuncSig) (string, string, error) {
	offsets := make([]int64, 0, len(relocations))
	for offset := range relocations {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	var fields, values []string
	appendBytes := func(bytes []byte) {
		if len(bytes) != 0 {
			typ := fmt.Sprintf("[%d x i8]", len(bytes))
			fields = append(fields, typ)
			values = append(values, typ+" "+llvmI8ArrayInit(bytes))
		}
	}
	cursor := int64(0)
	for _, offset := range offsets {
		d := relocations[offset]
		base, addend, err := dataAddress(d)
		if err != nil {
			return "", "", err
		}
		end, err := dataStmtEnd(d)
		if err != nil || offset < cursor || end > int64(len(buffer)) {
			return "", "", fmt.Errorf("DATA %s: overlapping or out-of-bounds relocation", d.Sym)
		}
		appendBytes(buffer[cursor:offset])
		typ := fmt.Sprintf("i%d", d.Width*8)
		pointer := llvmGlobal(resolveDataAddressSymbol(file, base, resolve, sigs))
		if addend != 0 {
			pointer = fmt.Sprintf("getelementptr (i8, ptr %s, i64 %d)", pointer, addend)
		}
		fields = append(fields, typ)
		values = append(values, fmt.Sprintf("%s ptrtoint (ptr %s to %s)", typ, pointer, typ))
		cursor = end
	}
	appendBytes(buffer[cursor:])
	return "<{ " + strings.Join(fields, ", ") + " }>", "<{ " + strings.Join(values, ", ") + " }>", nil
}
