package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type amd64ImplicitSystemOperand uint8

const (
	amd64ImplicitSystemNoOperand amd64ImplicitSystemOperand = iota
	amd64ImplicitSystemGP
	amd64ImplicitSystemAddressGP
)

type amd64ImplicitRegisterSet uint8

const (
	amd64ImplicitAX amd64ImplicitRegisterSet = 1 << iota
	amd64ImplicitCX
	amd64ImplicitDX
)

type amd64ImplicitSystemSpec struct {
	operand     amd64ImplicitSystemOperand
	inputs      amd64ImplicitRegisterSet
	outputs     amd64ImplicitRegisterSet
	writesCarry bool
	rawPrefix   byte
}

// amd64ImplicitSystemSpecs is the complete Go 1.27 grammar for the system
// instructions whose architectural state is carried by implicit AX/CX/DX
// registers, plus the WAITPKG instructions' one explicit Yrl register. The
// table separates operand syntax from data flow so parsing, register liveness,
// and emission all consume the same typed description.
var amd64ImplicitSystemSpecs = map[Op]amd64ImplicitSystemSpec{
	"MONITOR":  {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"MWAIT":    {inputs: amd64ImplicitAX | amd64ImplicitCX},
	"RDPMC":    {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
	"RDPKRU":   {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
	"WRPKRU":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"XSETBV":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
	"UMONITOR": {operand: amd64ImplicitSystemAddressGP, rawPrefix: 0xf3},
	"UMWAIT":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true, rawPrefix: 0xf2},
	"TPAUSE":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true, rawPrefix: 0x66},
}

type amd64ImplicitSystemForm struct {
	register      Reg
	addressBits   int
	segmentPrefix byte
}

func (c *amd64Ctx) lowerImplicitSystem(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, form, known, err := x86ImplicitSystemProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.emitImplicitSystem(strings.ToUpper(string(op)), spec, form)
}

func x86ImplicitSystemProperties(op Op, ins Instr, arch string) (amd64ImplicitSystemSpec, amd64ImplicitSystemForm, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64ImplicitSystemSpecs[Op(baseOp)]
	if !recognized {
		return spec, amd64ImplicitSystemForm{}, false, nil
	}
	if rawOp != baseOp || arch != "386" && arch != "amd64" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), rawOp) {
		return spec, amd64ImplicitSystemForm{}, true, fmt.Errorf("%s %s has an invalid suffix, mode or dispatch identity: %q", arch, op, ins.Raw)
	}
	form, err := parseX86ImplicitSystemForm(baseOp, spec, ins, arch)
	return spec, form, true, err
}

func parseX86ImplicitSystemForm(op string, spec amd64ImplicitSystemSpec, ins Instr, arch string) (amd64ImplicitSystemForm, error) {
	var form amd64ImplicitSystemForm
	switch spec.operand {
	case amd64ImplicitSystemNoOperand:
		if len(ins.Args) != 0 {
			return form, fmt.Errorf("%s %s takes no operands: %q", arch, op, ins.Raw)
		}
	case amd64ImplicitSystemGP, amd64ImplicitSystemAddressGP:
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[0].Reg, arch) {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Yrl register: %q", arch, op, ins.Raw)
		}
		form.register = ins.Args[0].Reg
		if spec.operand == amd64ImplicitSystemAddressGP {
			form.addressBits = 64
			if arch == "386" {
				form.addressBits = 32
			}
			if ins.x86Encoded {
				if ins.x86AddressBits != 0 {
					if ins.x86AddressBits != form.addressBits && ins.x86AddressBits != form.addressBits/2 {
						return form, fmt.Errorf("invalid %s address size %d", arch, ins.x86AddressBits)
					}
					form.addressBits = ins.x86AddressBits
				}
				form.segmentPrefix = ins.x86SegmentPrefix
			}
		}
	default:
		panic("unknown amd64 implicit-system operand kind")
	}
	return form, nil
}

// UMWAIT/TPAUSE consume their complete dword control and EDX:EAX deadline.
// Intel SDM defines CF and clears AF/PF/SF/ZF/OF on continuation; GP, DF and
// storage are unchanged. This numerical descriptor grants no monitor address,
// raw/native entry or promise that the operation cannot fault.
func x86TypedWaitPackageByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, form, known, err := x86ImplicitSystemProperties(op, ins, arch)
	if !known || !spec.writesCarry {
		return x86TypedByteEffect{}, false, nil
	}
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	if !x86WaitPackagePreservesStorage(ins) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: WAITPKG original/normalized numerical source differs", ErrProbeNeedsContext)
	}
	effect := x86TypedByteEffect{
		operands: []x86TypedByteOperand{
			{index: 0, operand: Operand{Kind: OpReg, Reg: form.register}, width: 4, read: true},
		},
		flagsDefined: x86ByteFlagsAll, flagsKilled: x86ByteFlagsAll, requiresResultProof: true,
	}
	for index, register := range []Reg{AX, CX, DX} {
		if spec.inputs&(1<<uint(index)) != 0 {
			effect.operands = append(effect.operands, x86TypedByteOperand{
				index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: 4, read: true,
			})
		}
	}
	return effect, true, nil
}

// The physical decoder retains WAITPKG's register-only identity. Unlike the
// address-bearing UMONITOR sibling, these two operations preserve GP/DF and
// private storage; FLAGS are independently replaced by the effect above.
func x86WaitPackagePreservesStorage(ins Instr) bool {
	spec, known := amd64ImplicitSystemSpecs[Op(strings.ToUpper(string(ins.Op)))]
	if !known || !spec.writesCarry || len(ins.Args) != 1 ||
		!reflect.DeepEqual(ins.Args[0], Operand{Kind: OpReg, Reg: ins.Args[0].Reg}) ||
		!isX86YrlRegisterForArch(ins.Args[0].Reg, "amd64") ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil && !ins.x86Encoded || origin != nil &&
		strings.EqualFold(string(origin.op), string(ins.Op)) && reflect.DeepEqual(origin.args, ins.Args)
}

func (c *amd64Ctx) emitImplicitSystem(op string, spec amd64ImplicitSystemSpec, form amd64ImplicitSystemForm) (bool, bool, error) {
	wordType := I64
	if c.goarch == "386" {
		wordType = I32
	}
	constraints := make([]string, 0, 8)
	arguments := make([]string, 0, 4)
	if spec.outputs == amd64ImplicitAX|amd64ImplicitDX {
		constraints = append(constraints, "={ax}", "={dx}")
	}
	if spec.writesCarry {
		constraints = append(constraints, "=q")
	}
	if spec.operand != amd64ImplicitSystemNoOperand {
		operandType := I32 // UMWAIT/TPAUSE read control[31:0], even with REX.W.
		if spec.operand == amd64ImplicitSystemAddressGP {
			operandType = LLVMType(fmt.Sprintf("i%d", form.addressBits))
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: form.register}, operandType)
		if err != nil {
			return true, false, err
		}
		if spec.operand == amd64ImplicitSystemAddressGP && operandType != wordType {
			// Monitor the same zero-extended offset using the native address
			// width. The segment base is still applied by the actual instruction.
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", extended, operandType, value, wordType)
			value, operandType = "%"+extended, wordType
		}
		constraints = append(constraints, "r")
		arguments = append(arguments, fmt.Sprintf("%s %s", operandType, value))
	}
	for _, implicit := range []struct {
		bit        amd64ImplicitRegisterSet
		reg        Reg
		constraint string
	}{
		{bit: amd64ImplicitAX, reg: AX, constraint: "{ax}"},
		{bit: amd64ImplicitCX, reg: CX, constraint: "{cx}"},
		{bit: amd64ImplicitDX, reg: DX, constraint: "{dx}"},
	} {
		if spec.inputs&implicit.bit == 0 {
			continue
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: implicit.reg}, I32)
		if err != nil {
			return true, false, err
		}
		constraints = append(constraints, implicit.constraint)
		arguments = append(arguments, "i32 "+value)
	}
	constraints = append(constraints, "~{memory}", "~{dirflag}", "~{fpsr}", "~{flags}")

	assembly := strings.ToLower(op)
	if form.segmentPrefix != 0 {
		assembly = fmt.Sprintf(".byte 0x%02x; %s", form.segmentPrefix, assembly)
	}
	if spec.operand != amd64ImplicitSystemNoOperand {
		operandIndex := 0
		if spec.writesCarry {
			operandIndex = 1
		}
		assembly += fmt.Sprintf(" $%d", operandIndex)
	}
	if spec.writesCarry {
		assembly += "; setc $0"
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, %q(%s)\n",
			call, assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i8 %%%s to i1\n", carry, call)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
		// WAITPKG defines CF and clears the other arithmetic flags (Intel SDM).
		c.clearX86StatusFlags(x86StatusAll &^ x86StatusCF)
		return true, false, nil
	}
	if spec.outputs == amd64ImplicitAX|amd64ImplicitDX {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect %q, %q(%s)\n",
			call, assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
		for index, reg := range []Reg{AX, DX} {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, index)
			if err := c.storeRegSized(reg, I32, "%"+part); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n",
		assembly, strings.Join(constraints, ","), strings.Join(arguments, ", "))
	return true, false, nil
}
