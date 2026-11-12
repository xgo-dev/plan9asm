package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
)

// GoX86TLSMoveBinding consumes a live source-encoder observation. Its sole
// permission is substituting the independently observed zero-width NOPs.
// In particular it cannot define the original destination GP bytes.
type GoX86TLSMoveBinding struct {
	identity        *GoX86TLSMoveBinding
	source          *GoX86TLSMoveSource
	originalSource  *GoX86TLSMoveSource
	context         context.Context
	originalContext context.Context
	file            [32]byte
	arch            string
	triple          string
	seal            [32]byte
}

func (source *GoX86TLSMoveSource) BindTLSMoves(ctx context.Context, file *File, options Options) (Options, error) {
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	_, arch, _ := strings.Cut(source.request.Target, "/")
	if options.Goarch != arch || options.TargetTriple != x86TLSExpectedTriple(source.request.Target) || options.TargetTriple == "" ||
		options.X86TLSMoves != nil || options.NumericalReads != nil || options.ARM64ByteCarrierSource != nil || len(options.X86TailGroups) != 0 {
		return Options{}, x86TLSMoveContext("binding source/profile or independent native authority differs")
	}
	actual, err := x86CallerSourceFingerprint(source.file)
	provided, sourceErr := x86CallerSourceFingerprint(file)
	if err != nil || sourceErr != nil || file == nil || provided != actual || len(source.noops) == 0 {
		return Options{}, x86TLSMoveContext("binding needs the complete original file and an actual NOP effect")
	}
	binding := &GoX86TLSMoveBinding{source: source, originalSource: source, context: ctx, originalContext: ctx,
		file: actual, arch: arch, triple: options.TargetTriple}
	binding.identity = binding
	binding.seal = binding.digest()
	options.X86TLSMoves = binding
	return options, nil
}

// Target equality is an explicit code-generation contract. This mapping does
// not choose a TLS rewrite; only the actual source/object/listing producer does.
func x86TLSExpectedTriple(target string) string {
	return map[string]string{
		"linux/amd64": "x86_64-unknown-linux-gnu", "linux/386": "i386-unknown-linux-gnu",
		"darwin/amd64": "x86_64-apple-darwin", "windows/amd64": "x86_64-pc-windows-msvc",
		"windows/386": "i686-pc-windows-msvc", "freebsd/386": "i386-unknown-freebsd",
		"freebsd/amd64": "x86_64-unknown-freebsd",
	}[target]
}

func (binding *GoX86TLSMoveBinding) digest() [32]byte {
	return sha256.Sum256([]byte(string(binding.file[:]) + "\x00" + binding.arch + "\x00" + binding.triple))
}

func (binding *GoX86TLSMoveBinding) verify(file *File, options Options) (result error) {
	defer func() {
		if result != nil && binding != nil {
			binding.originalSource.revoke()
		}
	}()
	if binding == nil || binding.identity != binding || binding.source == nil || binding.context == nil ||
		binding.source != binding.originalSource || binding.context != binding.originalContext ||
		binding.seal != binding.digest() || binding.context.Err() != nil ||
		options.Goarch != binding.arch || options.TargetTriple != binding.triple || options.X86TLSMoves != binding ||
		options.NumericalReads != nil || options.ARM64ByteCarrierSource != nil || len(options.X86TailGroups) != 0 {
		return x86TLSMoveContext("binding identity, source, context or target differs")
	}
	actual, err := x86CallerSourceFingerprint(file)
	if err != nil || file == nil || actual != binding.file {
		return x86TLSMoveContext("complete original file changed during consumption")
	}
	return binding.source.Verify(binding.context)
}

func freezeTLSMoveInputs(file *File, options Options) (*File, Options, error) {
	binding := options.X86TLSMoves
	if binding == nil {
		return file, options, nil
	}
	if err := binding.verify(file, options); err != nil {
		return nil, Options{}, err
	}
	// Reparse the independently guarded source, so caller-owned slices and
	// decoder certificates cannot change or supplement the native NOP fact.
	normalized, err := Parse(ArchAMD64, binding.source.expanded)
	if err != nil {
		return nil, Options{}, err
	}
	changed := make(map[int]bool)
	for _, site := range binding.source.noops {
		original := normalized.Funcs[site.Function].Instrs[site.Instruction]
		form, known, err := x86TLSMoveProperties(original, binding.arch)
		if err != nil || !known || form.memory >= 0 {
			return nil, Options{}, x86TLSMoveContext("observed NOP source role changed")
		}
		normalized.Funcs[site.Function].Instrs[site.Instruction] = Instr{Op: "NOP", Raw: original.Raw}
		changed[site.Function] = true
	}
	options.Sigs, err = numericalCloneSignatures(options.Sigs)
	if err != nil {
		return nil, Options{}, err
	}
	resolve := options.ResolveSym
	if resolve == nil {
		resolve = func(symbol string) string { return symbol }
	}
	for index := range changed {
		function := normalized.Funcs[index]
		name := resolve(function.Sym)
		if err := binding.verify(file, options); err != nil {
			return nil, Options{}, err
		}
		signature, present := options.Sigs[name]
		if !present {
			return nil, Options{}, x86TLSMoveContext("NOP consumer lacks its independent signature")
		}
		// The observed NOP preserves unknown as well as initialized GP state.
		// Consume the existing complete lowering result/effect proof before
		// generic register allocas can choose implementation representatives.
		consumer := &amd64Ctx{sig: signature, fpScalarSource: function, goarch: binding.arch}
		if err := consumer.checkLoweredScalarFPResultInitialization(); err != nil {
			return nil, Options{}, err
		}
	}
	return normalized, options, nil
}

func finishTLSMoves(file *File, options Options) error {
	if options.X86TLSMoves == nil {
		return nil
	}
	return options.X86TLSMoves.verify(file, options)
}

func tlsGoAssemblyInput(binding *GoX86TLSMoveBinding, pkg GoPackage, source []byte, options GoModuleOptions) (_ []byte, result error) {
	defer func() {
		if result != nil && binding != nil {
			binding.originalSource.revoke()
		}
	}()
	if binding == nil || binding.identity != binding || binding.source == nil {
		return nil, x86TLSMoveContext("missing Go source binding")
	}
	owner := binding.source
	goos, arch, _ := strings.Cut(owner.request.Target, "/")
	if pkg.Path != owner.request.PackagePath || pkg.Types == nil || pkg.Types.Path() != pkg.Path ||
		options.GOOS != goos || options.GOARCH != arch || options.TargetTriple != binding.triple ||
		options.NumericalReads != nil || options.ARM64ByteCarrierSource != nil || options.KeepFunc != nil {
		return nil, x86TLSMoveContext("Go source/package/profile or complete-file role differs")
	}
	if !bytes.Equal(source, owner.original) && !bytes.Equal(source, []byte(owner.expanded)) {
		return nil, x86TLSMoveContext("Go wrapper needs the exact captured original or expanded source")
	}
	if err := owner.Verify(binding.context); err != nil {
		return nil, err
	}
	return []byte(owner.expanded), nil
}

func finishTLSGoInput(binding *GoX86TLSMoveBinding, pkg GoPackage, source []byte, originalDigest [32]byte, options GoModuleOptions) error {
	_, err := tlsGoAssemblyInput(binding, pkg, source, options)
	if sha256.Sum256(source) != originalDigest {
		err = errors.Join(err, x86TLSMoveContext("original Go wrapper source changed during consumption"))
	}
	return err
}
