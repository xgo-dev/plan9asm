package plan9asm

import (
	"bytes"
	"errors"
	"reflect"
	"strings"

	"github.com/xgo-dev/llvm"
)

type arm64ByteCarrierBinding struct {
	source     *GoARM64ByteCarrierSource
	file       *File
	options    Options
	symbols    map[string]string
	signatures map[string][]byte
	functions  map[string]*arm64ByteCarrierFunction
}

func (source *GoARM64ByteCarrierSource) revokeCarrier() {
	if source == nil {
		return
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.identity == source {
		source.ready = false
	}
}

// This checks the existing observation's identity/lifetime only. It neither
// creates a binding nor substitutes for the complete physical Verify checks.
func (source *GoARM64ByteCarrierSource) liveCarrier() error {
	if source == nil {
		return arm64ByteCarrierContext("missing original source owner")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.identity != source {
		return arm64ByteCarrierContext("copied or uninitialized original source")
	}
	err := arm64ByteCarrierLive(source.lease)
	if !source.ready || err != nil {
		source.ready = false
		return errors.Join(arm64ByteCarrierContext("original owner closed or expired"), err)
	}
	return nil
}

func bindARM64ByteCarrier(file *File, options Options) (_ *arm64ByteCarrierBinding, failure error) {
	if err := rejectMixedNativeAuthorities(options.NumericalReads, options.ARM64ByteCarrierSource); err != nil {
		return nil, err
	}
	source := options.ARM64ByteCarrierSource
	if source == nil {
		return nil, arm64ByteCarrierContext("missing original source owner")
	}
	defer func() {
		if failure != nil {
			source.revokeCarrier()
		}
	}()
	if err := source.Verify(source.lease); err != nil {
		return nil, err
	}
	targets := map[string]string{
		"aarch64-apple-darwin": "darwin/arm64", "arm64-apple-darwin": "darwin/arm64",
		"aarch64-unknown-linux-gnu": "linux/arm64", "aarch64-pc-windows-msvc": "windows/arm64",
		"aarch64-unknown-freebsd": "freebsd/arm64", "aarch64-unknown-openbsd": "openbsd/arm64",
	}
	if file == nil || file.Arch != ArchARM64 || options.Goarch != "arm64" || options.ResolveSym == nil ||
		targets[options.TargetTriple] != source.request.Target || source.guard.selection.Name == "main" ||
		options.WASMABI != WASMABIDirect || options.X87Mode != X87Auto || len(options.X86TailGroups) != 0 ||
		len(file.Funcs) == 0 || len(file.Funcs) > 256 || len(options.Sigs) != len(source.declarations) ||
		!reflect.DeepEqual(arm64ScratchFileSnapshot(file), arm64ScratchFileSnapshot(source.file)) {
		return nil, arm64ByteCarrierContext("complete private library source/target/options differ")
	}
	binding := &arm64ByteCarrierBinding{
		source: source, file: arm64ScratchFileSnapshot(file), options: options,
		symbols: make(map[string]string), signatures: make(map[string][]byte), functions: make(map[string]*arm64ByteCarrierFunction),
	}
	// Snapshot every signature before calling arbitrary user resolution code.
	for name, signature := range options.Sigs {
		binding.signatures[name] = append([]byte(nil), arm64ScratchPublicSignature(signature)...)
	}
	for _, function := range binding.file.Funcs {
		if err := source.liveCarrier(); err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(function.Sym, "·")
		expected, present := source.declarations[name]
		resolved := options.ResolveSym(function.Sym)
		if err := source.liveCarrier(); err != nil {
			return nil, err
		}
		if !present || resolved != expected.Name || !bytes.Equal(binding.signatures[resolved], arm64ScratchPublicSignature(expected)) ||
			binding.symbols[function.Sym] != "" || binding.functions[resolved] != nil {
			return nil, arm64ByteCarrierContext("actual declaration/LLVM identity differs or collides")
		}
		binding.symbols[function.Sym] = resolved
		binding.functions[resolved] = &arm64ByteCarrierFunction{source: function, signature: expected,
			privateName: resolved + ".plan9asm.bytecarrier"}
	}
	if err := binding.verifyFileAndOptions(file, options); err != nil {
		return nil, err
	}
	if err := binding.prepareNative(); err != nil {
		return nil, err
	}
	if err := binding.verify(); err != nil {
		return nil, err
	}
	return binding, nil
}

func (binding *arm64ByteCarrierBinding) verifyFileAndOptions(file *File, options Options) error {
	if !reflect.DeepEqual(binding.file, arm64ScratchFileSnapshot(file)) || len(options.Sigs) != len(binding.signatures) ||
		options.ARM64ByteCarrierSource != binding.source || options.TargetTriple != binding.options.TargetTriple ||
		options.Goarch != binding.options.Goarch || options.WASMABI != binding.options.WASMABI ||
		options.X87Mode != binding.options.X87Mode || options.AnnotateSource != binding.options.AnnotateSource ||
		len(options.X86TailGroups) != 0 || options.NumericalReads != nil {
		return arm64ByteCarrierContext("source/options changed during callbacks or lowering")
	}
	for name, prior := range binding.signatures {
		current, exists := options.Sigs[name]
		if !exists || !bytes.Equal(prior, arm64ScratchPublicSignature(current)) {
			return arm64ByteCarrierContext("complete signature inventory changed")
		}
	}
	return nil
}

func (binding *arm64ByteCarrierBinding) verify() error {
	if err := binding.source.Verify(binding.source.lease); err != nil {
		return err
	}
	for _, function := range binding.file.Funcs {
		if err := binding.source.liveCarrier(); err != nil {
			return err
		}
		name := binding.options.ResolveSym(function.Sym)
		if err := binding.source.liveCarrier(); err != nil {
			return err
		}
		if name != binding.symbols[function.Sym] {
			return arm64ByteCarrierContext("resolution changed after the original declaration join")
		}
	}
	if err := binding.verifyFileAndOptions(binding.file, binding.options); err != nil {
		return err
	}
	return binding.source.Verify(binding.source.lease)
}

func translateARM64ByteCarrierModule(ctx llvm.Context, file *File, options Options) (result llvm.Module, failure error) {
	binding, err := bindARM64ByteCarrier(file, options)
	if err != nil {
		return llvm.Module{}, err
	}
	defer func() {
		final := errors.Join(binding.verifyFileAndOptions(file, options), binding.verify())
		if failure != nil || final != nil {
			binding.source.revokeCarrier()
			if !result.IsNil() {
				result.Dispose()
			}
			result = llvm.Module{}
			failure = errors.Join(failure, final)
		}
	}()
	ir, err := binding.emitIR()
	if err != nil {
		return llvm.Module{}, err
	}
	return parseIRModuleInContext(ctx, ir)
}
