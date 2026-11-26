package plan9asm

import (
	"github.com/xgo-dev/plan9asm/internal/arm"
	"github.com/xgo-dev/plan9asm/internal/arm64"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/x86"
	"strings"
)

func emitArchPrelude(b *strings.Builder, file *File, resolve func(string) string, goarch string, wasmABI WASMABI, x87Mode X87Mode) {
	switch file.Arch {
	case ArchARM:
		arm.EmitPrelude(b)
	case ArchARM64:
		arm64.EmitPrelude(b)
	case ArchAMD64:
		// Keep historical gating to avoid injecting x86-only prelude when
		// parsing x86 syntax for unrelated targets in tests.
		if goarch == "amd64" || goarch == "386" {
			x86.EmitPreludeWithX87Mode(b, goarch, x87Mode, file)
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
				if asm.NormalizeInstructionOpcode(ins.Op) == "CALLIMPORT" {
					// Go 1.20 and older use CallImport wrappers that pass the
					// linear-memory SP to a host function associated with the
					// current Go symbol. LLGo's wasm linker resolves this suffix
					// to the corresponding host import.
					b.WriteString("declare void " + asm.LLVMGlobal(resolve(fn.Sym)+"$wasmimport") + "(i32)\n")
					break
				}
			}
		}
		b.WriteString("\n")
	}
	want := make(map[string]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			switch asm.NormalizeInstructionOpcode(ins.Op) {
			case "F64FLOOR":
				want["floor"] = true
			case "F64CEIL":
				want["ceil"] = true
			case "F64TRUNC":
				want["trunc"] = true
			case "MEMORYCOPY":
				want["memmove"] = true
			case "MEMORYFILL":
				want["memset"] = true
			case "CURRENTMEMORY":
				want["memory.size"] = true
			case "GROWMEMORY":
				want["memory.grow"] = true
			}
		}
	}
	if want["memmove"] {
		b.WriteString("declare void @llvm.memmove.p0.p0.i32(ptr, ptr, i32, i1 immarg)\n")
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
	for _, name := range []string{"floor", "ceil", "trunc"} {
		if want[name] {
			b.WriteString("declare double @llvm." + name + ".f64(double)\n")
		}
	}
	if len(want) != 0 {
		b.WriteString("\n")
	}
}
