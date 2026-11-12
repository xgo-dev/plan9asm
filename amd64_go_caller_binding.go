package plan9asm

import "fmt"

// GoX86RawReturnCallerBindingNeeded is only a loader cost predicate. A true
// result proves neither a caller region nor a valid source continuation.
func GoX86RawReturnCallerBindingNeeded(file *File, goarch string, resolve func(string) string, sigs map[string]FuncSig) bool {
	if file == nil || goarch != "amd64" || resolve == nil {
		return false
	}
	for _, fn := range file.Funcs {
		if x86GoCallerRegionCandidate(fn, sigs[resolve(goTextSymbolForResolution(fn.Sym))]) {
			return true
		}
	}
	return false
}

// BindGoX86RawReturnCallerRegions consumes the compiler's complete actual
// typed package selection. It returns new signatures with private source
// evidence; the whole-source normalizer must still prove every stack, memory
// effect and return. Pointer/noescape types or JSON hashes are insufficient.
func BindGoX86RawReturnCallerRegions(pkg GoPackage, file *File, goarch string, resolve func(string) string, sigs map[string]FuncSig) (map[string]FuncSig, error) {
	if !GoX86RawReturnCallerBindingNeeded(file, goarch, resolve, sigs) {
		return sigs, nil
	}
	if pkg.SourceSelection == nil {
		return nil, fmt.Errorf("%w: bounded raw-return caller binding requires actual selected source", ErrProbeNeedsContext)
	}
	bound := make(map[string]FuncSig, len(sigs))
	for name, sig := range sigs {
		bound[name] = sig
	}
	for _, fn := range file.Funcs {
		name := resolve(goTextSymbolForResolution(fn.Sym))
		sig := bound[name]
		if !x86GoCallerRegionCandidate(fn, sig) {
			continue
		}
		proof, err := deriveX86GoCallerRegions(pkg, *pkg.SourceSelection, fn, sig, goarch)
		if err != nil {
			return nil, err
		}
		sig.x86CallerRegions = proof
		bound[name] = sig
	}
	return bound, nil
}
