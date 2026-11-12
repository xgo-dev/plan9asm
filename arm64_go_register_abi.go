package plan9asm

import (
	"fmt"
	"go/types"
	"reflect"
	"strconv"
	"strings"
)

// ARM64GoRegisterValue identifies a scalar leaf of an LLVM argument or result.
// Result values have Index zero and Path relative to the complete LLVM return.
type ARM64GoRegisterValue struct {
	Index    int
	Path     []int
	Type     LLVMType
	Register Reg
}

// ARM64GoRegisterABI describes an entirely register-assigned Go ABIInternal
// boundary. Its non-nil presence is significant for a zero-argument function.
// Integer/pointer and floating leaves use independent R0-R15/F0-F15 banks;
// result assignment restarts both banks. It is not a memory/ownership contract.
type ARM64GoRegisterABI struct {
	Params  []ARM64GoRegisterValue
	Results []ARM64GoRegisterValue
}

func arm64GoABIContext(format string, args ...any) error {
	return fmt.Errorf("%w: ARM64 Go ABIInternal %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

// This is the recursive scalar assignment in Go's abiutils.go, restricted to
// values that are wholly register assigned. Arrays longer than one and a bank
// overflow require stack-ABI context; do not flatten them into guessed registers.
func arm64GoABILeaves(typ LLVMType, path []int, visit func(LLVMType, []int) error) error {
	return goLLVMScalarLeaves(typ, path, 1, visit)
}

// ABI consumers share the aggregate grammar, but supply their own array bound
// and leaf callback. A larger bound does not assign registers or frame roles.
func goLLVMScalarLeaves(typ LLVMType, path []int, arrayLimit uint64, visit func(LLVMType, []int) error) error {
	if len(path) > 64 {
		return arm64GoABIContext("aggregate nesting exceeds the bounded contract")
	}
	if isARM64ABIIntegerType(typ) || isARM64ABIFloatingType(typ) {
		return visit(typ, path)
	}
	s := strings.TrimSpace(string(typ))
	var children []LLVMType
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		depth, start := 0, 0
		for i, ch := range inner {
			switch ch {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			case ',':
				if depth == 0 {
					children = append(children, LLVMType(strings.TrimSpace(inner[start:i])))
					start = i + 1
				}
			}
			if depth < 0 {
				return arm64GoABIContext("malformed aggregate %s", typ)
			}
		}
		if depth != 0 || inner == "" {
			return arm64GoABIContext("malformed or zero-sized aggregate %s", typ)
		}
		children = append(children, LLVMType(strings.TrimSpace(inner[start:])))
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		count, elem, found := strings.Cut(strings.TrimSpace(s[1:len(s)-1]), " x ")
		n, err := strconv.ParseUint(count, 10, 64)
		if !found || err != nil || n == 0 || n > arrayLimit {
			return arm64GoABIContext("array %s needs a stack/zero-size contract", typ)
		}
		for index := uint64(0); index < n; index++ {
			next := append(append([]int(nil), path...), int(index))
			if err := goLLVMScalarLeaves(LLVMType(strings.TrimSpace(elem)), next, arrayLimit, visit); err != nil {
				return err
			}
		}
		return nil
	} else {
		return arm64GoABIContext("unrecognized scalar/aggregate type %s", typ)
	}
	for i, child := range children {
		next := append(append([]int(nil), path...), i)
		if err := goLLVMScalarLeaves(child, next, arrayLimit, visit); err != nil {
			return err
		}
	}
	return nil
}

func arm64GoRegisterABIForSig(sig FuncSig) (*ARM64GoRegisterABI, error) {
	contract := new(ARM64GoRegisterABI)
	assign := func(index int, typ LLVMType, cursor *arm64ABIRegisterCursor, out *[]ARM64GoRegisterValue) error {
		return arm64GoABILeaves(typ, nil, func(leaf LLVMType, path []int) error {
			reg, err := cursor.next(leaf)
			if err != nil {
				return arm64GoABIContext("%s: %v; stack assignment is not modeled", sig.Name, err)
			}
			*out = append(*out, ARM64GoRegisterValue{Index: index, Path: path, Type: leaf, Register: reg})
			return nil
		})
	}
	cursor := arm64ABIRegisterCursor{}
	for i, typ := range sig.Args {
		if err := assign(i, typ, &cursor, &contract.Params); err != nil {
			return nil, err
		}
	}
	if sig.Ret != Void {
		cursor = arm64ABIRegisterCursor{}
		if err := assign(0, sig.Ret, &cursor, &contract.Results); err != nil {
			return nil, err
		}
	}
	return contract, nil
}

func arm64ValidateGoRegisterABI(sig FuncSig) error {
	if sig.ARM64GoRegisterABI == nil {
		return arm64GoABIContext("%q needs an explicit complete register contract", sig.Name)
	}
	if len(sig.ArgRegs) != 0 {
		return arm64GoABIContext("%q mixes standard and custom register contracts", sig.Name)
	}
	want, err := arm64GoRegisterABIForSig(sig)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(want, sig.ARM64GoRegisterABI) {
		return arm64GoABIContext("%q has incomplete, mismatched or noncanonical register bindings", sig.Name)
	}
	return nil
}

func arm64GoTypeRegisterAssignable(typ types.Type) bool {
	switch u := typ.Underlying().(type) {
	case *types.Array:
		return u.Len() == 1 && arm64GoTypeRegisterAssignable(u.Elem())
	case *types.Struct:
		if u.NumFields() == 0 {
			return false
		}
		for i := 0; i < u.NumFields(); i++ {
			if !arm64GoTypeRegisterAssignable(u.Field(i).Type()) {
				return false
			}
		}
		return true
	case *types.Basic:
		return u.Info()&(types.IsBoolean|types.IsInteger|types.IsFloat|types.IsComplex|types.IsString) != 0 || u.Kind() == types.UnsafePointer
	case *types.Pointer, *types.Slice, *types.Interface, *types.Signature, *types.Map, *types.Chan:
		return true
	default:
		return false
	}
}

// DeriveARM64GoRegisterABI derives the register-only layout from a real Go
// function declaration and its corresponding LLVM signature. Callers must
// separately establish the explicit source ABIInternal selector. An ordinary
// ABI0 declaration or this layout alone does not select a register entry.
func DeriveARM64GoRegisterABI(fn *types.Func, sig FuncSig) (*ARM64GoRegisterABI, error) {
	if fn == nil {
		return nil, arm64GoABIContext("%q has no Go declaration", sig.Name)
	}
	decl, ok := fn.Type().(*types.Signature)
	if !ok || decl.Variadic() || decl.Recv() != nil {
		return nil, arm64GoABIContext("%q has no supported fixed function declaration", sig.Name)
	}
	for _, tuple := range []*types.Tuple{decl.Params(), decl.Results()} {
		for i := 0; i < tuple.Len(); i++ {
			if !arm64GoTypeRegisterAssignable(tuple.At(i).Type()) {
				return nil, arm64GoABIContext("%q type %s is stack assigned or unrecognized", sig.Name, tuple.At(i).Type())
			}
		}
	}
	// Require the declaration's actual LLVM transport types, rather than
	// letting a manual scalar signature impersonate a Go aggregate boundary.
	sizes := types.SizesFor("gc", "arm64")
	want, err := goFuncSigForDeclaredFunc(sig.Name, fn, "arm64", sizes, sizes, true)
	match := err == nil && len(want.Args) == len(sig.Args) && want.Ret == sig.Ret
	for i := range want.Args {
		if !match || want.Args[i] != sig.Args[i] {
			match = false
			break
		}
	}
	if !match {
		return nil, arm64GoABIContext("%q LLVM signature does not match its declaration", sig.Name)
	}
	return arm64GoRegisterABIForSig(sig)
}

func arm64GoABIPath(path []int) string {
	var b strings.Builder
	for i, index := range path {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", index)
	}
	return b.String()
}

func (c *arm64Ctx) extractGoABIValue(typ LLVMType, value string, slot ARM64GoRegisterValue) string {
	if len(slot.Path) == 0 {
		return value
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %s\n", t, typ, value, arm64GoABIPath(slot.Path))
	return "%" + t
}

func (c *arm64Ctx) collectGoABIValue(typ LLVMType, slots []ARM64GoRegisterValue) (string, error) {
	value := "undef"
	for _, slot := range slots {
		leaf, err := c.loadABIRegisterValue(slot.Register, slot.Type)
		if err != nil {
			return "", err
		}
		if len(slot.Path) == 0 {
			value = leaf
			continue
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %s\n", t, typ, value, slot.Type, leaf, arm64GoABIPath(slot.Path))
		value = "%" + t
	}
	return value, nil
}

func (c *arm64Ctx) goABIRegisterCallArgs(sig FuncSig) ([]string, error) {
	if err := arm64ValidateGoRegisterABI(sig); err != nil {
		return nil, err
	}
	args := make([]string, len(sig.Args))
	for index, typ := range sig.Args {
		var slots []ARM64GoRegisterValue
		for _, slot := range sig.ARM64GoRegisterABI.Params {
			if slot.Index == index {
				slots = append(slots, slot)
			}
		}
		value, err := c.collectGoABIValue(typ, slots)
		if err != nil {
			return nil, err
		}
		args[index] = fmt.Sprintf("%s %s", typ, value)
	}
	return args, nil
}

func (c *arm64Ctx) storeGoABIRegisterResult(sig FuncSig, value string) error {
	for _, slot := range sig.ARM64GoRegisterABI.Results {
		leaf := c.extractGoABIValue(sig.Ret, value, slot)
		if err := c.storeABIRegisterValue(slot.Register, slot.Type, leaf); err != nil {
			return err
		}
	}
	return nil
}
