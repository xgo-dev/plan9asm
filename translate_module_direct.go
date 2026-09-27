package plan9asm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xgo-dev/llvm"
)

var errDirectModuleUnsupported = errors.New("direct module lowering unsupported")

func directUnsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDirectModuleUnsupported, fmt.Sprintf(format, args...))
}

type directValue struct {
	typ LLVMType
	val llvm.Value
}

func translateModuleDirect(file *File, opt Options) (llvm.Module, error) {
	return translateModuleDirectInContext(llvm.GlobalContext(), file, opt)
}

func translateModuleDirectInContext(ctx llvm.Context, file *File, opt Options) (llvm.Module, error) {
	if file == nil {
		return llvm.Module{}, fmt.Errorf("nil file")
	}
	if len(file.x86Continuations) != 0 {
		return llvm.Module{}, directUnsupportedf("x86 continuations require shared CFG lowering")
	}
	if len(file.Funcs) == 0 && len(file.Data) == 0 && len(file.Globl) == 0 {
		return llvm.Module{}, fmt.Errorf("empty file")
	}
	if opt.AnnotateSource {
		return llvm.Module{}, directUnsupportedf("source annotation requires textual lowering")
	}

	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}

	mod := ctx.NewModule("plan9asm")
	if opt.TargetTriple != "" {
		mod.SetTarget(opt.TargetTriple)
	}
	if err := emitDataGlobalsModule(mod, file, resolve); err != nil {
		mod.Dispose()
		if errors.Is(err, errDirectModuleUnsupported) {
			return llvm.Module{}, err
		}
		return llvm.Module{}, err
	}

	for i := range file.Funcs {
		fn := &file.Funcs[i]
		if fn.X86RawText != nil {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("address-sensitive x86 raw TEXT requires textual lowering for %s", fn.Sym)
		}
		name := resolve(fn.Sym)
		sig, ok := opt.Sigs[name]
		if !ok {
			mod.Dispose()
			return llvm.Module{}, fmt.Errorf("missing signature for %q", name)
		}
		if sig.Name == "" {
			sig.Name = name
		}
		if sig.Name != name {
			mod.Dispose()
			return llvm.Module{}, fmt.Errorf("signature name mismatch: %q vs %q", sig.Name, name)
		}
		if sig.Ret == "" {
			mod.Dispose()
			return llvm.Module{}, fmt.Errorf("missing return type for %q", name)
		}
		if err := validateResolvedImmediates(file.Arch, *fn); err != nil {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("%s: %v", name, err)
		}
		if file.Arch == ArchAMD64 {
			if err := validateAMD64ScalarAddSubFunction(opt.Goarch, *fn); err != nil {
				mod.Dispose()
				return llvm.Module{}, fmt.Errorf("%s: %w", name, err)
			}
		}
		if file.Arch == ArchARM {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("arm CFG lowering required for %s", name)
		}
		if file.Arch == ArchARM64 && funcNeedsARM64CFG(*fn) {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("arm64 CFG lowering required for %s", name)
		}
		if file.Arch == ArchAMD64 && (opt.Goarch == "386" || (opt.Goarch == "amd64" && funcNeedsAMD64CFG(*fn))) {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("x86 CFG lowering required for %s", name)
		}
		if file.Arch == ArchWASM {
			mod.Dispose()
			return llvm.Module{}, directUnsupportedf("wasm stack lowering required for %s", name)
		}
		if err := translateFuncLinearModule(mod, file.Arch, *fn, sig); err != nil {
			mod.Dispose()
			if errors.Is(err, errDirectModuleUnsupported) {
				return llvm.Module{}, err
			}
			return llvm.Module{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
		mod.Dispose()
		return llvm.Module{}, directUnsupportedf("module verification failed in direct path: %v", err)
	}
	return mod, nil
}

func translateFuncLinearModule(mod llvm.Module, arch Arch, fn Func, sig FuncSig) error {
	ctx := mod.Context()
	retTy, err := llvmTypeFromLLVMType(ctx, sig.Ret)
	if err != nil {
		return err
	}
	argLLTys := make([]llvm.Type, 0, len(sig.Args))
	for _, t := range sig.Args {
		llty, err := llvmTypeFromLLVMType(ctx, t)
		if err != nil {
			return err
		}
		argLLTys = append(argLLTys, llty)
	}
	ft := llvm.FunctionType(retTy, argLLTys, false)
	fv := llvm.AddFunction(mod, sig.Name, ft)

	entry := ctx.AddBasicBlock(fv, "entry")
	b := ctx.NewBuilder()
	defer b.Dispose()
	b.SetInsertPointAtEnd(entry)

	args := fv.Params()

	fpParams := map[int64]FrameSlot{}
	for _, s := range sig.Frame.Params {
		fpParams[s.Offset] = s
	}
	fpResults := map[int64]FrameSlot{}
	for _, s := range sig.Frame.Results {
		fpResults[s.Offset] = s
	}

	reg := map[Reg]directValue{}
	results := make([]directValue, len(sig.Frame.Results))
	haveResult := make([]bool, len(sig.Frame.Results))

	setArgReg := func(r Reg, i int) {
		if i < 0 || i >= len(args) {
			return
		}
		reg[r] = directValue{typ: sig.Args[i], val: args[i]}
	}

	switch arch {
	case ArchARM:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				setArgReg(sig.ArgRegs[i], i)
			}
		} else {
			for i := 0; i < len(sig.Args) && i < 4; i++ {
				setArgReg(Reg(fmt.Sprintf("R%d", i)), i)
			}
		}
	case ArchARM64:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				setArgReg(sig.ArgRegs[i], i)
			}
		} else {
			for i := 0; i < len(sig.Args) && i < 8; i++ {
				setArgReg(Reg(fmt.Sprintf("R%d", i)), i)
			}
		}
	case ArchAMD64:
		if len(sig.ArgRegs) > 0 {
			for i := 0; i < len(sig.Args) && i < len(sig.ArgRegs); i++ {
				setArgReg(sig.ArgRegs[i], i)
			}
		} else {
			x86 := []Reg{DI, SI, DX, CX, Reg("R8"), Reg("R9")}
			for i := 0; i < len(sig.Args) && i < len(x86); i++ {
				setArgReg(x86[i], i)
			}
		}
	}

	zero := func(ty LLVMType) (directValue, error) {
		llty, err := llvmTypeFromLLVMType(ctx, ty)
		if err != nil {
			return directValue{}, err
		}
		switch ty {
		case Ptr:
			return directValue{typ: ty, val: llvm.ConstPointerNull(llty)}, nil
		case I1, I8, I16, I32, I64:
			return directValue{typ: ty, val: llvm.ConstInt(llty, 0, false)}, nil
		default:
			return directValue{typ: ty, val: llvm.ConstNull(llty)}, nil
		}
	}

	cast := func(v directValue, to LLVMType) (directValue, error) {
		if v.typ == to {
			return v, nil
		}
		if fb, ok := llvmIntBits(v.typ); ok {
			if tb, ok := llvmIntBits(to); ok {
				toTy, err := llvmTypeFromLLVMType(ctx, to)
				if err != nil {
					return directValue{}, err
				}
				switch {
				case fb > tb:
					return directValue{typ: to, val: b.CreateTrunc(v.val, toTy, "")}, nil
				case fb < tb:
					return directValue{typ: to, val: b.CreateZExt(v.val, toTy, "")}, nil
				default:
					return directValue{typ: to, val: v.val}, nil
				}
			}
		}
		if v.typ == Ptr {
			if _, ok := llvmIntBits(to); ok {
				toTy, err := llvmTypeFromLLVMType(ctx, to)
				if err != nil {
					return directValue{}, err
				}
				return directValue{typ: to, val: b.CreatePtrToInt(v.val, toTy, "")}, nil
			}
		}
		if to == Ptr {
			if _, ok := llvmIntBits(v.typ); ok {
				toTy, err := llvmTypeFromLLVMType(ctx, to)
				if err != nil {
					return directValue{}, err
				}
				return directValue{typ: to, val: b.CreateIntToPtr(v.val, toTy, "")}, nil
			}
		}
		return directValue{}, directUnsupportedf("unsupported cast %s -> %s", v.typ, to)
	}

	setResult := func(off int64, v directValue) error {
		slot, ok := fpResults[off]
		if !ok {
			return directUnsupportedf("unsupported FP write slot +%d(FP)", off)
		}
		if v.typ != slot.Type {
			var err error
			v, err = cast(v, slot.Type)
			if err != nil {
				return err
			}
		}
		if slot.Index < 0 || slot.Index >= len(results) {
			return directUnsupportedf("invalid result index %d", slot.Index)
		}
		results[slot.Index] = v
		haveResult[slot.Index] = true
		return nil
	}

	valueOf := func(op Operand) (directValue, error) {
		switch op.Kind {
		case OpImm:
			if op.ImmRaw != "" {
				return directValue{}, directUnsupportedf("unresolved symbolic immediate %q", op.ImmRaw)
			}
			llty, _ := llvmTypeFromLLVMType(ctx, I64)
			return directValue{typ: I64, val: llvm.ConstInt(llty, uint64(op.Imm), true)}, nil
		case OpReg:
			if v, ok := reg[op.Reg]; ok {
				return v, nil
			}
			return zero(I64)
		case OpFP:
			slot, ok := fpParams[op.FPOffset]
			if !ok {
				return directValue{}, directUnsupportedf("unsupported FP read slot %s", op.String())
			}
			if slot.Index < 0 || slot.Index >= len(args) {
				return directValue{}, directUnsupportedf("FP slot %s invalid arg index %d", op.String(), slot.Index)
			}
			arg := args[slot.Index]
			if fields := frameSlotFields(slot); len(fields) != 0 {
				ev := arg
				for _, field := range fields {
					ev = b.CreateExtractValue(ev, field, "")
				}
				return directValue{typ: slot.Type, val: ev}, nil
			}
			return directValue{typ: slot.Type, val: arg}, nil
		default:
			return directValue{}, directUnsupportedf("invalid operand kind %v", op.Kind)
		}
	}

	retTyFn := sig.Ret
	terminated := false
	for _, ins := range fn.Instrs {
		if terminated {
			switch ins.Op {
			case OpTEXT, OpBYTE, OpWORD:
				continue
			default:
				return directUnsupportedf("instruction after RET: %s", ins.Op)
			}
		}
		switch ins.Op {
		case OpTEXT:
			continue
		case OpBYTE, OpWORD:
			continue
		case OpMRS:
			if len(ins.Args) != 2 {
				return directUnsupportedf("MRS expects 2 args")
			}
			src, dst := ins.Args[0], ins.Args[1]
			if src.Kind != OpIdent || dst.Kind != OpReg {
				return directUnsupportedf("MRS expects ident, reg: %q", ins.Raw)
			}
			i64Ty, _ := llvmTypeFromLLVMType(ctx, I64)
			sysreg := arm64CanonicalSysReg(src.Ident)
			if v, ok := arm64CompileSafeMRSValue(sysreg); ok {
				if v != "0" {
					return directUnsupportedf("unexpected compile-safe MRS value %q", v)
				}
				reg[dst.Reg] = directValue{typ: I64, val: llvm.ConstInt(i64Ty, 0, false)}
				continue
			}
			asmTy := llvm.FunctionType(i64Ty, nil, false)
			asmv := llvm.InlineAsm(asmTy, "mrs $0, "+sysreg, "=r", false, false, llvm.InlineAsmDialectATT, false)
			callv := b.CreateCall(asmTy, asmv, nil, "")
			reg[dst.Reg] = directValue{typ: I64, val: callv}
		case OpMOVD, OpMOVQ:
			if len(ins.Args) != 2 {
				return directUnsupportedf("%s expects 2 args", ins.Op)
			}
			src, dst := ins.Args[0], ins.Args[1]
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = cast(v, I64)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				reg[dst.Reg] = v
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				return directUnsupportedf("%s dst unsupported: %s", ins.Op, dst.String())
			}
		case OpMOVL:
			if len(ins.Args) != 2 {
				return directUnsupportedf("MOVL expects 2 args")
			}
			src, dst := ins.Args[0], ins.Args[1]
			if dst.Kind == OpFP && (src.Kind == OpFP || src.Kind == OpMem || src.Kind == OpSym) {
				return fmt.Errorf("x86 MOVL does not allow memory-to-result-memory: %q", ins.Raw)
			}
			v, err := valueOf(src)
			if err != nil {
				return err
			}
			v, err = cast(v, I32)
			if err != nil {
				return err
			}
			switch dst.Kind {
			case OpReg:
				reg[dst.Reg] = v
			case OpFP:
				if err := setResult(dst.FPOffset, v); err != nil {
					return err
				}
			default:
				return directUnsupportedf("MOVL dst unsupported: %s", dst.String())
			}
		case OpADDQ, OpSUBQ, OpXORQ:
			if len(ins.Args) != 2 {
				return directUnsupportedf("%s expects 2 args", ins.Op)
			}
			src, dst := ins.Args[0], ins.Args[1]
			if dst.Kind != OpReg {
				return directUnsupportedf("%s dst must be register in linear lowering", ins.Op)
			}
			lhs, err := valueOf(dst)
			if err != nil {
				return err
			}
			var rhs directValue
			if (ins.Op == OpADDQ || ins.Op == OpSUBQ) && src.Kind == OpImm {
				i64Ty, typeErr := llvmTypeFromLLVMType(ctx, I64)
				if typeErr != nil {
					return typeErr
				}
				normalized := amd64ScalarAddSubImmediateInt64(src.Imm, 64)
				rhs = directValue{typ: I64, val: llvm.ConstInt(i64Ty, uint64(normalized), true)}
			} else {
				rhs, err = valueOf(src)
				if err != nil {
					return err
				}
			}
			lhs, err = cast(lhs, I64)
			if err != nil {
				return err
			}
			rhs, err = cast(rhs, I64)
			if err != nil {
				return err
			}
			var out llvm.Value
			switch ins.Op {
			case OpADDQ:
				out = b.CreateAdd(lhs.val, rhs.val, "")
			case OpSUBQ:
				out = b.CreateSub(lhs.val, rhs.val, "")
			case OpXORQ:
				out = b.CreateXor(lhs.val, rhs.val, "")
			}
			reg[dst.Reg] = directValue{typ: I64, val: out}
		case OpCPUID:
			eax, ok := reg[AX]
			if !ok {
				var zerr error
				eax, zerr = zero(I32)
				if zerr != nil {
					return zerr
				}
			} else {
				var cerr error
				eax, cerr = cast(eax, I32)
				if cerr != nil {
					return cerr
				}
			}
			ecx, ok := reg[CX]
			if !ok {
				var zerr error
				ecx, zerr = zero(I32)
				if zerr != nil {
					return zerr
				}
			} else {
				var cerr error
				ecx, cerr = cast(ecx, I32)
				if cerr != nil {
					return cerr
				}
			}
			i32Ty, _ := llvmTypeFromLLVMType(ctx, I32)
			retTy := ctx.StructType([]llvm.Type{i32Ty, i32Ty, i32Ty, i32Ty}, false)
			asmTy := llvm.FunctionType(retTy, []llvm.Type{i32Ty, i32Ty}, false)
			asmv := llvm.InlineAsm(
				asmTy,
				"cpuid",
				"={ax},={bx},={cx},={dx},{ax},{cx},~{dirflag},~{fpsr},~{flags}",
				true,
				false,
				llvm.InlineAsmDialectATT,
				false,
			)
			callv := b.CreateCall(asmTy, asmv, []llvm.Value{eax.val, ecx.val}, "")
			reg[AX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 0, "")}
			reg[BX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 1, "")}
			reg[CX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 2, "")}
			reg[DX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 3, "")}
		case OpXGETBV:
			ecx, ok := reg[CX]
			if !ok {
				var zerr error
				ecx, zerr = zero(I32)
				if zerr != nil {
					return zerr
				}
			} else {
				var cerr error
				ecx, cerr = cast(ecx, I32)
				if cerr != nil {
					return cerr
				}
			}
			i32Ty, _ := llvmTypeFromLLVMType(ctx, I32)
			retTy := ctx.StructType([]llvm.Type{i32Ty, i32Ty}, false)
			asmTy := llvm.FunctionType(retTy, []llvm.Type{i32Ty}, false)
			asmv := llvm.InlineAsm(
				asmTy,
				"xgetbv",
				"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}",
				true,
				false,
				llvm.InlineAsmDialectATT,
				false,
			)
			callv := b.CreateCall(asmTy, asmv, []llvm.Value{ecx.val}, "")
			reg[AX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 0, "")}
			reg[DX] = directValue{typ: I32, val: b.CreateExtractValue(callv, 1, "")}
		case OpRET:
			switch {
			case retTyFn == Void:
				b.CreateRetVoid()
				terminated = true
			case len(sig.Frame.Results) > 1:
				aggTy, err := llvmTypeFromLLVMType(ctx, retTyFn)
				if err != nil {
					return err
				}
				cur := llvm.Undef(aggTy)
				for _, slot := range sig.Frame.Results {
					i := slot.Index
					var v directValue
					if i >= 0 && i < len(haveResult) && haveResult[i] {
						v = results[i]
					} else {
						zv, zerr := zero(slot.Type)
						if zerr != nil {
							return zerr
						}
						v = zv
					}
					if v.typ != slot.Type {
						var cerr error
						v, cerr = cast(v, slot.Type)
						if cerr != nil {
							return cerr
						}
					}
					cur = b.CreateInsertValue(cur, v.val, slot.Index, "")
				}
				b.CreateRet(cur)
				terminated = true
			default:
				var v directValue
				if len(sig.Frame.Results) == 1 && haveResult[0] {
					v = results[0]
				} else if rv, ok := reg[archReturnReg(arch)]; ok {
					v = rv
				} else {
					zv, zerr := zero(retTyFn)
					if zerr != nil {
						return zerr
					}
					v = zv
				}
				if v.typ != retTyFn {
					var cerr error
					v, cerr = cast(v, retTyFn)
					if cerr != nil {
						return cerr
					}
				}
				b.CreateRet(v.val)
				terminated = true
			}
		default:
			return directUnsupportedf("unsupported instruction: %s", ins.Op)
		}
	}
	if !terminated {
		return directUnsupportedf("function %s has no RET", sig.Name)
	}
	return nil
}

func emitDataGlobalsModule(mod llvm.Module, file *File, resolve func(string) string) error {
	type symData struct {
		size     int64
		bytes    map[int64][]byte
		readOnly bool
		local    bool
	}
	syms := map[string]*symData{}
	resolveData := func(sym string) string {
		if strings.Contains(sym, "·") || strings.Contains(sym, "/") || strings.Contains(sym, ".") {
			return resolve(sym)
		}
		return resolve("·" + sym)
	}
	for _, g := range file.Globl {
		readOnly, err := globlReadOnly(g.Flags)
		if err != nil {
			return err
		}
		name := resolveData(g.Sym)
		sd := syms[name]
		if sd == nil {
			sd = &symData{bytes: map[int64][]byte{}}
			syms[name] = sd
		}
		if g.Size > sd.size {
			sd.size = g.Size
		}
		sd.readOnly = readOnly
		sd.local = strings.HasSuffix(g.Sym, "<>")
	}
	for _, d := range file.Data {
		name := resolveData(d.Sym)
		sd := syms[name]
		if sd == nil {
			sd = &symData{bytes: map[int64][]byte{}}
			syms[name] = sd
		}
		sd.local = strings.HasSuffix(d.Sym, "<>")
		end, err := dataStmtEnd(d)
		if err != nil {
			return err
		}
		payload, err := dataStmtPayload(d)
		if err != nil {
			return err
		}
		sd.bytes[d.Off] = payload
		if end > sd.size {
			sd.size = end
		}
	}
	if len(syms) == 0 {
		return nil
	}

	ctx := mod.Context()
	i8Ty := ctx.Int8Type()

	for name, sd := range syms {
		if sd.size <= 0 {
			continue
		}
		buf, err := makeDataGlobal(name, sd.size)
		if err != nil {
			return err
		}
		for off, p := range sd.bytes {
			if off < 0 || off+int64(len(p)) > int64(len(buf)) {
				return fmt.Errorf("DATA %s: out of bounds off=%d len=%d size=%d", name, off, len(p), len(buf))
			}
			copy(buf[off:], p)
		}
		arrTy := llvm.ArrayType(i8Ty, len(buf))
		elems := make([]llvm.Value, len(buf))
		for i, b := range buf {
			elems[i] = llvm.ConstInt(i8Ty, uint64(b), false)
		}
		init := llvm.ConstArray(i8Ty, elems)
		g := llvm.AddGlobal(mod, arrTy, name)
		g.SetInitializer(init)
		g.SetGlobalConstant(sd.readOnly)
		if sd.local {
			g.SetLinkage(llvm.InternalLinkage)
		}
		g.SetAlignment(int(bestAlign(int64(len(buf)))))
	}
	return nil
}

func llvmTypeFromLLVMType(ctx llvm.Context, ty LLVMType) (llvm.Type, error) {
	switch strings.TrimSpace(string(ty)) {
	case string(Void):
		return ctx.VoidType(), nil
	case string(I1):
		return ctx.Int1Type(), nil
	case string(I8):
		return ctx.Int8Type(), nil
	case string(I16):
		return ctx.Int16Type(), nil
	case string(I32):
		return ctx.Int32Type(), nil
	case string(I64):
		return ctx.Int64Type(), nil
	case string(Ptr):
		return llvm.PointerType(ctx.Int8Type(), 0), nil
	case "float":
		return ctx.FloatType(), nil
	case "double":
		return ctx.DoubleType(), nil
	default:
		fields, ok := parseLiteralStructFields(ty)
		if !ok {
			return llvm.Type{}, directUnsupportedf("unsupported LLVM type %q", ty)
		}
		elems := make([]llvm.Type, 0, len(fields))
		for _, f := range fields {
			t, err := llvmTypeFromLLVMType(ctx, f)
			if err != nil {
				return llvm.Type{}, err
			}
			elems = append(elems, t)
		}
		return ctx.StructType(elems, false), nil
	}
}

func llvmIntBits(ty LLVMType) (int, bool) {
	switch ty {
	case I1:
		return 1, true
	case I8:
		return 8, true
	case I16:
		return 16, true
	case I32:
		return 32, true
	case I64:
		return 64, true
	default:
		return 0, false
	}
}
