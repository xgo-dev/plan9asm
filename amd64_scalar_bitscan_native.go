package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

func x86BitScanHelperOps(file *File, arch string) []Op {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	seen := make(map[Op]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if _, known, err := x86ScalarBitScanProperties(ins.Op, ins, arch); known && err == nil {
				seen[Op(strings.ToUpper(string(ins.Op)))] = true
			}
		}
	}
	ops := make([]Op, 0, len(seen))
	for op := range seen {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })
	return ops
}

func x86BitScanNamespace(file *File, arch string, resolve func(string) string, sigs map[string]FuncSig) string {
	if len(x86BitScanHelperOps(file, arch)) == 0 {
		return ""
	}
	return x86CompilerHelperNamespace(file, resolve, sigs, "bitscan")
}

func x86BitScanHelperName(namespace, arch string, op Op) string {
	return namespace + arch + "_" + strings.ToLower(string(op))
}

func emitX86BitScanHelpers(b *strings.Builder, file *File, arch, namespace string) {
	if namespace == "" {
		return
	}
	word, push, pop := I64, "pushq", "popq"
	if arch == "386" {
		word, push, pop = I32, "pushl", "popl"
	}
	for _, op := range x86BitScanHelperOps(file, arch) {
		spec := x86ScalarBitScanSpecs[op]
		typ := amd64IntegerTypeForBits(spec.bits)
		modifier := map[int]string{16: "w", 32: "k", 64: "q"}[spec.bits]
		mnemonic := strings.ToLower(string(op))
		name := x86BitScanHelperName(namespace, arch, op)
		fmt.Fprintf(b, "define internal { %s, %s } @%s(%s %%source, %s %%prior, %s %%status) noinline noredzone {\nentry:\n", word, word, name, typ, word, word)
		// Seed only virtual status representatives, never privileged FLAGS,
		// direction/ID or a claimed physical caller-entry identity. The source
		// observer still permits only portable ZF after a scan. Unknown other
		// bits stay unobservable; a zero seed does not establish their validity.
		fmt.Fprintf(b, "  %%masked = and %s %%status, %d\n  %%seed = or %s %%masked, 2\n", word, x86StatusAll, word)
		assembly := fmt.Sprintf("%s $4; popf%s; %s ${3:%s}, ${0:%s}; pushf%s; %s $1", push, strings.TrimPrefix(pop, "pop"), mnemonic, modifier, modifier, strings.TrimPrefix(pop, "pop"), pop)
		// The full native prior is tied to the full native output. In
		// particular no software r32 writeback chooses the dword-zero upper
		// behavior. Balanced temporary stack use lives only in this compiler
		// helper; noinline+noredzone protects callers' red zones and source SP.
		fmt.Fprintf(b, "  %%result = call { %s, %s } asm sideeffect %q, \"=r,=r,0,r,r,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s %%prior, %s %%source, %s %%seed)\n", word, word, assembly, word, typ, word)
		fmt.Fprintf(b, "  ret { %s, %s } %%result\n}\n\n", word, word)
	}
}

func (c *amd64Ctx) lowerScalarBitScan(op Op, ins Instr) (bool, bool, error) {
	arch := c.goarch
	if arch == "" {
		arch = "amd64" // The existing direct emitter's shape default.
	}
	spec, known, err := x86ScalarBitScanProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	if c.bitScanNS == "" || !x86ScalarFloatIntegerNativeTarget(arch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: bit scan needs its compiler-owned bridge and matching explicit x86 target", ErrProbeNeedsContext)
	}
	typ, word := amd64IntegerTypeForBits(spec.bits), I64
	if arch == "386" {
		word = I32
	}
	var source string
	if ins.Args[0].Kind == OpReg {
		source, err = c.evalIntSized(ins.Args[0], typ)
	} else {
		// Retain each existing source role and exact-width volatile native
		// read; FP/AUTO/SB observations do not become native storage authority.
		var bytes string
		bytes, err = c.loadX86PackedShiftBytes(ins.Args[0], spec.bits/8, true)
		if err == nil {
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", name, spec.bits/8, bytes, typ)
			source = "%" + name
		}
	}
	if err != nil {
		return true, false, err
	}
	prior, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	status := c.packX86Flags()
	if word == I32 {
		prior, status = c.truncI64(prior, I32), c.truncI64(status, I32)
	}
	result, value, flags := c.newTmp(), c.newTmp(), c.newTmp()
	name := x86BitScanHelperName(c.bitScanNS, arch, Op(strings.ToUpper(string(op))))
	returnType := fmt.Sprintf("{ %s, %s }", word, word)
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, %s %s)\n", result, returnType, name, typ, source, word, prior, word, status)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n  %%%s = extractvalue %s %%%s, 1\n", value, returnType, result, flags, returnType, result)
	for _, flag := range c.x86StatusFlagSlots() {
		shift, bit := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, %d\n  %%%s = trunc %s %%%s to i1\n  store i1 %%%s, ptr %s\n", shift, word, flags, flag.bit, bit, word, shift, bit, flag.slot)
	}
	output := "%" + value
	if word == I32 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, output)
		output = "%" + wide
	}
	return true, false, c.storeReg(ins.Args[1].Reg, output)
}
