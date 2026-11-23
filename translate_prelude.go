package plan9asm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

func emitArchPrelude(b *strings.Builder, file *File, resolve func(string) string, goarch string, wasmABI WASMABI) {
	switch file.Arch {
	case ArchARM:
		emitARMPrelude(b)
	case ArchARM64:
		// Emit only referenced declarations after lowering the complete body.
	case ArchAMD64:
		// Keep historical gating to avoid injecting x86-only prelude when
		// parsing x86 syntax for unrelated targets in tests.
		if goarch == "amd64" || goarch == "386" {
			emitAMD64SourcePrelude(b, file, goarch)
		}
	case ArchWASM:
		emitWASMPrelude(b, file, resolve, wasmABI)
	}
}

func emitWASMPrelude(b *strings.Builder, file *File, resolve func(string) string, wasmABI WASMABI) {
	if wasmABI == WASMABIGo {
		// Address space 1 is LLVM's WebAssembly mutable-global address space.
		// These names and types match cmd/link/internal/wasm's register globals.
		b.WriteString("@SP = external addrspace(1) global i32\n")
		for _, name := range []string{"CTXT", "g", "RET0", "RET1", "RET2", "RET3"} {
			b.WriteString("@" + name + " = external addrspace(1) global i64\n")
		}
		b.WriteString("@PAUSE = external addrspace(1) global i32\n\n")
		for _, fn := range file.Funcs {
			for _, ins := range fn.Instrs {
				if normalizeInstructionOpcode(ins.Op) == "CALLIMPORT" {
					// Go 1.20 and older use CallImport wrappers that pass the
					// linear-memory SP to a host function associated with the
					// current Go symbol. LLGo's wasm linker resolves this suffix
					// to the corresponding host import.
					b.WriteString("declare void " + llvmGlobal(resolve(fn.Sym)+"$wasmimport") + "(i32)\n")
					break
				}
			}
		}
		b.WriteString("\n")
	}
	want := make(map[string]bool)
	wantFloatUnary := make(map[string]bool)
	wantFloatBinary := make(map[string]bool)
	wantIntegerIntrinsic := make(map[string]bool)
	wantConversion := make(map[string]wasmConversionOp)
	var wantVectorIntrinsic map[string]wasmsimd.Form
	// Go function bodies can reach the assembler's implicit final UNDEF.
	wantTrap := wasmABI == WASMABIGo
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			op := normalizeInstructionOpcode(ins.Op)
			wantTrap = wantTrap || wasmSourceTrap(op)
			if spec, ok := wasmIntegerCountOps[op]; ok {
				wantIntegerIntrinsic[spec.intrinsic+"."+string(spec.typ)] = true
			}
			if spec, ok := wasmIntegerBinaryOps[op]; ok {
				wantTrap = wantTrap || spec.traps()
				if intrinsic := spec.rotateIntrinsic(); intrinsic != "" {
					wantIntegerIntrinsic[intrinsic] = true
				}
			}
			if spec, ok := wasmConversionOps[op]; ok {
				wantTrap = wantTrap || spec.traps
				if spec.intrinsic != "" {
					wantConversion[spec.intrinsic] = spec
				}
			}
			if memory, ok := lookupWASMMemoryOp(op); ok {
				switch {
				case memory.guardedWidth() != 0:
					if len(ins.Args) == 0 || ins.Args[len(ins.Args)-1].Kind != OpFP {
						want["memory.size"] = true
						wantTrap = true
					}
				case len(ins.Args) == 1:
					arg := ins.Args[0]
					wantTrap = wantTrap || arg.Kind == OpImm && arg.Imm != 0 || arg.Kind == OpMem && arg.Mem.Off != 0
				}
			}
			if spec, ok := wasmFloatUnaryOps[op]; ok && spec.intrinsic != "" {
				wantFloatUnary[string(spec.typ)+"|"+spec.intrinsic] = true
			}
			if spec, ok := wasmFloatBinaryOps[op]; ok && spec.intrinsic != "" {
				wantFloatBinary[string(spec.typ)+"|"+spec.intrinsic] = true
			}
			if spec, ok := wasmsimd.Lookup(op); ok && spec.HasIntrinsic() {
				if wantVectorIntrinsic == nil {
					wantVectorIntrinsic = make(map[string]wasmsimd.Form)
				}
				wantVectorIntrinsic[spec.IntrinsicName()] = spec
			}
			if spec, ok := wasmMemoryBuiltins[op]; ok {
				want[spec.intrinsic] = true
			}
		}
	}
	if wantTrap {
		b.WriteString("declare void @llvm.trap()\n")
	}
	conversions := make([]string, 0, len(wantConversion))
	for intrinsic := range wantConversion {
		conversions = append(conversions, intrinsic)
	}
	sort.Strings(conversions)
	for _, intrinsic := range conversions {
		spec := wantConversion[intrinsic]
		fmt.Fprintf(b, "declare %s @%s(%s)\n", spec.result, intrinsic, spec.source)
	}
	vectorIntrinsics := make([]string, 0, len(wantVectorIntrinsic))
	for intrinsic := range wantVectorIntrinsic {
		vectorIntrinsics = append(vectorIntrinsics, intrinsic)
	}
	sort.Strings(vectorIntrinsics)
	for _, intrinsic := range vectorIntrinsics {
		spec := wantVectorIntrinsic[intrinsic]
		result, input := spec.IntrinsicSignature()
		fmt.Fprintf(b, "declare %s @%s(%s", result, intrinsic, input)
		if spec.Emission == wasmsimd.IntegerAbs {
			b.WriteString(", i1 immarg")
		} else {
			b.WriteString(strings.Repeat(", "+input, spec.Arity()-1))
		}
		b.WriteString(")\n")
	}
	if want["memmove"] {
		b.WriteString("declare void @llvm.memmove.p0.p0.i32(ptr, ptr, i32, i1 immarg)\n")
	}
	for _, typ := range []LLVMType{I32, I64} {
		for _, intrinsic := range []string{"ctlz", "cttz", "ctpop", "fshl", "fshr"} {
			name := intrinsic + "." + string(typ)
			if wantIntegerIntrinsic[name] {
				fmt.Fprintf(b, "declare %s @llvm.%s(%s", typ, name, typ)
				switch intrinsic {
				case "ctlz", "cttz":
					b.WriteString(", i1 immarg")
				case "fshl", "fshr":
					fmt.Fprintf(b, ", %s, %s", typ, typ)
				}
				b.WriteString(")\n")
			}
		}
	}
	if want["memset"] {
		b.WriteString("declare void @llvm.memset.p0.i32(ptr, i8, i32, i1 immarg)\n")
	}
	if want["memory.size"] {
		b.WriteString("declare i32 @llvm.wasm.memory.size.i32(i32)\n")
	}
	if want["memory.grow"] {
		b.WriteString("declare i32 @llvm.wasm.memory.grow.i32(i32, i32)\n")
	}
	for _, typ := range []LLVMType{LLVMType("float"), LLVMType("double")} {
		bits := "32"
		if typ == LLVMType("double") {
			bits = "64"
		}
		for _, name := range []string{"fabs", "ceil", "floor", "trunc", "roundeven", "sqrt"} {
			if wantFloatUnary[string(typ)+"|"+name] {
				fmt.Fprintf(b, "declare %s @llvm.%s.f%s(%s)\n", typ, name, bits, typ)
			}
		}
		for _, name := range []string{"minimum", "maximum", "copysign"} {
			if wantFloatBinary[string(typ)+"|"+name] {
				fmt.Fprintf(b, "declare %s @llvm.%s.f%s(%s, %s)\n", typ, name, bits, typ, typ)
			}
		}
	}
	if len(want) != 0 || len(wantIntegerIntrinsic) != 0 || len(wantFloatUnary) != 0 ||
		len(wantFloatBinary) != 0 || len(conversions) != 0 || len(vectorIntrinsics) != 0 || wantTrap {
		b.WriteString("\n")
	}
}
