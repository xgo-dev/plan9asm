package plan9asm

// Predicate selection is not canonicality, source, frame or entry permission.
// AMD64 keeps its independent explicit register-result role. The 386 role is
// an ordinary zero-frame/no-argument ABI0 function with one declared bool byte;
// its complete typed result initialization/canonicality is checked separately.
func x86SDKLiteralBoolPredicateRole(fn Func, sig FuncSig, arch string) bool {
	if arch == "amd64" {
		return sig.Ret == I1 && x86RegisterBoolResultNeedsProof(fn, sig, arch)
	}
	return x86ABI0SingleByteBoolResultRole(fn, sig, arch)
}
