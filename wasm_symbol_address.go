package plan9asm

import "fmt"

// wasmFunctionAddress separates a source Go logical PC from LLVM's physical
// function-table index. WASMNative changes the physical signature, not Go's
// source address: Go's linker assigns packed PCs to every TEXT symbol.
func wasmFunctionAddress(file *File, symbol string, addend int64, resolve func(string) string, sigs map[string]FuncSig, abi WASMABI) (name string, function, packed bool, err error) {
	name = resolveDataAddressSymbol(file, symbol, resolve, sigs)
	function = dataAddressIsFunction(file, symbol, resolve, sigs)
	if !function || abi != WASMABIGo {
		return name, function, false, nil
	}
	for _, fn := range file.Funcs {
		resolved := resolve(fn.Sym)
		if funcSigSymbol(resolved, sigs[resolved]) != name {
			continue
		}
		if addend < 0 || addend >= 1<<16 {
			return "", true, false, fmt.Errorf("%w: wasm Go function address %s has an unrepresentable packed-PC addend %d", ErrProbeNeedsContext, symbol, addend)
		}
		return name, true, true, nil
	}
	return "", true, false, fmt.Errorf("%w: wasm Go function address %s requires a source-bound logical-PC contract", ErrProbeNeedsContext, symbol)
}
