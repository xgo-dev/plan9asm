package plan9asm

// This map describes actual same-module numeric storage, not external Go
// variables or a reusable source/return certificate. All typed read consumers
// still request their complete native width, independently of a selected lane.
func x86LoweredScalarDataReads(file *File, resolve func(string) string, sigs map[string]FuncSig, arch string) map[x86StaticSBAddress]int64 {
	if file == nil || file.Arch != ArchAMD64 || resolve == nil {
		return nil
	}
	// No local object can supply a read extent. Avoid allocating a directory
	// or observing unrelated function/external symbols through a user resolver.
	if len(file.Data) == 0 && len(file.Globl) == 0 {
		return nil
	}
	type object struct {
		size    int64
		invalid bool
	}
	objects := make(map[string]object)
	for _, global := range file.Globl {
		name := resolveAssemblyDataSymbol(global.Sym, resolve)
		current := objects[name]
		if global.SizeRaw != "" || global.Size < 0 || global.Size > maxDataGlobalSize {
			current.invalid = true
		}
		if global.Size > current.size {
			current.size = global.Size
		}
		objects[name] = current
	}
	for _, datum := range file.Data {
		name := resolveAssemblyDataSymbol(datum.Sym, resolve)
		current := objects[name]
		end, err := dataStmtEnd(datum)
		if err != nil || datum.Addr != "" {
			// Reject relocations in the entire resolved object, not merely
			// the selected raw name or currently read range.
			current.invalid = true
		}
		if end > current.size {
			current.size = end
		}
		objects[name] = current
	}
	for _, function := range file.Funcs {
		name := resolve(function.Sym)
		current := objects[name]
		current.invalid = true
		objects[name] = current
	}
	for name, signature := range sigs {
		for _, symbol := range []string{name, funcSigSymbol(name, signature)} {
			current := objects[symbol]
			current.invalid = true
			objects[symbol] = current
		}
	}
	reads := make(map[x86StaticSBAddress]int64)
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			for _, operand := range ins.Args {
				address, valid := x86StaticSBReadAddress(operand, arch)
				if !valid {
					continue
				}
				if graph := file.x86ContinuationGraph; graph != nil {
					if _, codeTable := graph.tables[address.symbol]; codeTable {
						continue // Mutable code carriers are not numerical BSS/literal bytes.
					}
				}
				current := objects[resolveAssemblyDataSymbol(address.symbol, resolve)]
				if !current.invalid && current.size > 0 && current.size <= maxDataGlobalSize && address.offset < current.size {
					reads[address] = current.size - address.offset
				}
			}
		}
	}
	return reads
}
