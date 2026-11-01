package plan9asm

import (
	"fmt"
	"strings"

	llvm "github.com/xgo-dev/llvm"
)

// TranslateNativeModule represents each raw native entry as an address-only
// naked LLVM function. The void() carrier is NOT a Go/C signature: all inputs,
// results, calls and returns live in physical registers inside inline assembly.
// Call sites retain their own ABI. No typed IR call is generated for a carrier.
// DATA contains real LLVM references, as do inline-asm symbol operands, so module
// linking, renaming and dead-code elimination can track their dependencies.
// The caller owns the returned module; errors never return a partial module.
func TranslateNativeModule(ctx llvm.Context, src []byte, opts NativeOptions) (mod llvm.Module, err error) {
	f, e, _, err := prepareNativeSource(src, opts)
	if err != nil {
		return llvm.Module{}, err
	}
	mod = ctx.NewModule("native-" + opts.PackagePath)
	defer func() {
		if err != nil {
			mod.Dispose()
			mod = llvm.Module{}
		}
	}()
	arch := "aarch64"
	if opts.GOARCH == "amd64" {
		arch = "x86_64"
	}
	triple := arch + "-unknown-linux-gnu"
	if opts.GOOS == "darwin" {
		triple = arch + "-apple-darwin"
	}
	mod.SetTarget(triple)
	// LLVM 22 InstCombineCalls explicitly preserves mismatched prototypes for
	// naked functions: their asm can consume arguments absent from the carrier.
	// Keep this separate from typed lowering, which must never invent void calls.
	carrierTy := llvm.FunctionType(ctx.VoidType(), nil, false)
	funcs := map[string]llvm.Value{}
	globals := map[string]llvm.Value{}
	imports := map[string]llvm.Value{}
	for i, fn := range f.Funcs {
		name, linkage := fmt.Sprintf("__plan9_native_%d", i), llvm.InternalLinkage
		if object, bound := opts.CodeEntries[fn.Sym]; bound {
			name, linkage = object, llvm.ExternalLinkage
		}
		v := llvm.AddFunction(mod, name, carrierTy)
		v.SetLinkage(linkage)
		for _, attr := range []string{"naked", "noinline"} {
			v.AddFunctionAttr(ctx.CreateEnumAttribute(llvm.AttributeKindID(attr), 0))
		}
		funcs[fn.Sym] = v
	}
	// Reserve all globals first, allowing forward DATA references. A packed
	// structure gives byte-exact layout while retaining pointer-typed relocations.
	for _, g := range f.Globl {
		values, _ := e.dataValues(f, g)
		var fields []llvm.Type
		pos := int64(0)
		for _, d := range values {
			if d.Off > pos {
				fields = append(fields, llvm.ArrayType(ctx.Int8Type(), int(d.Off-pos)))
			}
			ty := ctx.IntType(int(d.Width * 8))
			if d.Addr != "" {
				ty = llvm.PointerType(ctx.Int8Type(), 0)
			}
			fields = append(fields, ty)
			pos = d.Off + d.Width
		}
		if pos < g.Size {
			fields = append(fields, llvm.ArrayType(ctx.Int8Type(), int(g.Size-pos)))
		}
		v := llvm.AddGlobal(mod, ctx.StructType(fields, true), opts.PackagePath+"."+strings.TrimPrefix(g.Sym, "·"))
		v.SetAlignment(8)
		flags, _ := nativeFlags(g.Flags, "RODATA", "NOPTR")
		v.SetGlobalConstant(flags["RODATA"])
		globals[g.Sym] = v
	}
	resolve := func(s string, data bool) (llvm.Value, error) {
		if !strings.HasSuffix(s, "(SB)") {
			return llvm.Value{}, fmt.Errorf("unsupported native symbol %s", s)
		}
		name := strings.TrimSuffix(s, "(SB)")
		if v, ok := funcs[name]; ok {
			return v, nil
		}
		if data {
			if v, ok := globals[name]; ok {
				return v, nil
			}
		}
		if alias, ok := opts.Imports[name]; ok {
			if v, ok := imports[alias]; ok {
				return v, nil
			}
			// An untyped external address, not a guessed foreign function prototype.
			v := llvm.AddGlobal(mod, ctx.Int8Type(), alias)
			imports[alias] = v
			return v, nil
		}
		return llvm.Value{}, fmt.Errorf("undeclared foreign symbol or unsupported native reference %s", s)
	}
	for _, g := range f.Globl {
		values, _ := e.dataValues(f, g)
		var fields []llvm.Value
		pos := int64(0)
		for _, d := range values {
			if d.Off > pos {
				fields = append(fields, llvm.ConstNull(llvm.ArrayType(ctx.Int8Type(), int(d.Off-pos))))
			}
			var value llvm.Value
			if d.Addr != "" {
				value, err = resolve(d.Addr, true)
				if err != nil {
					return mod, err
				}
			} else {
				value = llvm.ConstInt(ctx.IntType(int(d.Width*8)), d.Value, false)
			}
			fields = append(fields, value)
			pos = d.Off + d.Width
		}
		if pos < g.Size {
			fields = append(fields, llvm.ConstNull(llvm.ArrayType(ctx.Int8Type(), int(g.Size-pos))))
		}
		globals[g.Sym].SetInitializer(ctx.ConstStruct(fields, true))
	}
	builder := ctx.NewBuilder()
	defer builder.Dispose()
	for i, fn := range f.Funcs {
		if err = e.functionLabels(fn, i); err != nil {
			return mod, err
		}
		for label, value := range e.labels {
			e.labels[label] = value + "___native_uid__"
		}
		var refs []llvm.Value
		e.symbolOperand = func(s string, data bool) (string, error) {
			v, err := resolve(s, data)
			if err != nil {
				return "", err
			}
			for n, ref := range refs {
				if ref == v {
					return fmt.Sprintf("__native_operand_%d__", n), nil
				}
			}
			n := len(refs)
			refs = append(refs, v)
			return fmt.Sprintf("__native_operand_%d__", n), nil
		}
		var body strings.Builder
		if err = e.functionBody(&body, fn); err != nil {
			return mod, err
		}
		last := string(fn.Instrs[len(fn.Instrs)-1].Op)
		if last != "RET" && last != "JMP" && last != "B" {
			return mod, fmt.Errorf("native naked TEXT must end with RET or an unconditional branch: %s", fn.Sym)
		}
		// Escape literal x86 '$' immediates before adding LLVM template operands.
		assembly := strings.ReplaceAll(body.String(), "$", "$$")
		assembly = strings.ReplaceAll(assembly, "__native_uid__", "${:uid}")
		var types []llvm.Type
		var constraints []string
		for n, v := range refs {
			assembly = strings.ReplaceAll(assembly, fmt.Sprintf("__native_operand_%d__", n), fmt.Sprintf("${%d:c}", n))
			types = append(types, v.Type())
			constraint := "i"
			if opts.GOARCH == "amd64" {
				constraint = "s"
			}
			constraints = append(constraints, constraint)
		}
		constraints = append(constraints, "~{memory}")
		ty := llvm.FunctionType(ctx.VoidType(), types, false)
		inline := llvm.InlineAsm(ty, assembly, strings.Join(constraints, ","), true, false, llvm.InlineAsmDialectATT, false)
		block := ctx.AddBasicBlock(funcs[fn.Sym], "entry")
		builder.SetInsertPointAtEnd(block)
		builder.CreateCall(ty, inline, refs, "")
		// Machine RET/tail JMP exits the carrier. This is not a noreturn function.
		builder.CreateUnreachable()
	}
	if err = llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
		return mod, err
	}
	return mod, nil
}
