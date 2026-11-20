package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func resolveARM64SymbolMemoryTest(symbol string) string {
	return strings.TrimPrefix(symbol, "·")
}

// Go 1.27 asm7.go's C_ADDR load/store rows cover MOVD and the signed and
// unsigned byte/halfword/word aliases. C_VCONADDR is separately address-valued.
func TestARM64SymbolScalarCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT symbolForms(SB),$0-0\n")
	for _, form := range arm64ScalarWritebackOps {
		for _, off := range []int{-65537, -8, 0, 1, 8, 65537} {
			fmt.Fprintf(&source, "%s buffer%+d(SB), R2\n%s R2, buffer%+d(SB)\n%s ZR, buffer%+d(SB)\n%s $0, buffer%+d(SB)\n", form.op, off, form.op, off, form.op, off, form.op, off)
		}
	}
	// The encoder rejects MOVW addresses but permits MOVWU through its
	// address-materialization row; that spelling retains the full address.
	for _, op := range []string{"MOVD", "MOVWU"} {
		fmt.Fprintf(&source, "%s $buffer+3(SB), R2\n", op)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolveARM64SymbolMemoryTest, Sigs: map[string]FuncSig{
			"symbolForms": {Name: "symbolForms", Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "symbol-scalar.ll", "symbol-scalar.o", ir)
	}
}

func TestARM64SymbolScalarLoadStoreNotAddress(t *testing.T) {
	for _, form := range arm64ScalarWritebackOps {
		t.Run(form.op, func(t *testing.T) {
			source := fmt.Sprintf("TEXT symbolMemory(SB),$0-0\n%s buffer(SB), R2\n%s R2, buffer(SB)\nRET\n", form.op, form.op)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: resolveARM64SymbolMemoryTest, Sigs: map[string]FuncSig{
				"symbolMemory": {Name: "symbolMemory", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			wantPointer := fmt.Sprintf("ptr %s, align 1", llvmGlobal("buffer"))
			wantLoad := fmt.Sprintf("load i%d, %s", form.bits, wantPointer)
			wantStore := fmt.Sprintf("store i%d ", form.bits)
			stored := false
			for _, line := range strings.Split(ir, "\n") {
				stored = stored || strings.Contains(line, wantStore) && strings.Contains(line, wantPointer)
			}
			if !strings.Contains(ir, wantLoad) || !stored {
				t.Fatalf("%s symbolic load/store must access memory at native width, not return its address or omit the store; missing %q/%q", form.op, wantLoad, wantStore)
			}
		})
	}
}

func TestARM64SymbolScalarRejectsGoInvalidForms(t *testing.T) {
	instructions := []string{
		"MOVD buffer(SB), other(SB)", "MOVD $1, buffer(SB)",
		"MOVD R2, $buffer(SB)", "MOVD $buffer(SB), buffer(SB)",
		"MOVB $buffer(SB), R2", "MOVBU $buffer(SB), R2",
		"MOVH $buffer(SB), R2", "MOVHU $buffer(SB), R2",
		"MOVW $buffer(SB), R2",
		"MOVD.P buffer(SB), R2", "MOVD.W R2, buffer(SB)",
	}
	for _, form := range arm64ScalarWritebackOps {
		instructions = append(instructions, form.op+" $1, buffer(SB)", form.op+" $UNRESOLVED_ZERO, buffer(SB)")
	}
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT badSymbol(SB),$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"badSymbol": {Name: "badSymbol", Ret: Void}}})
			if err == nil {
				t.Fatal("translator accepted Go-rejected symbolic memory move")
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64SymbolScalarZeroStore(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, declarations, checks, goDeclarations, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range arm64ScalarWritebackOps {
		name := fmt.Sprintf("scalar_wb_zero_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n%s $0, buffer+7(SB)\nRET\n", name, form.op)
		sigs[name] = FuncSig{Name: name, Ret: Void}
		fmt.Fprintf(&declarations, "extern void %s(void);\n", name)
		fmt.Fprintf(&goDeclarations, "func %s()\n", name)
		fmt.Fprintf(&checks, "{ unsigned char expected[80]; for(unsigned i=0;i<80;i++) buffer[i]=(unsigned char)(i*13+131); memcpy(expected,buffer,80); memset(expected+7,0,%d); %s(); if(memcmp(buffer,expected,80)) return %d; }\n", form.bits/8, name, len(sigs))
		fmt.Fprintf(&goChecks, "{ for i:=range buffer { buffer[i]=byte(i*13+131) }; expected:=buffer; for i:=0;i<%d;i++ { expected[7+i]=0 }; %s(); if buffer!=expected { panic(\"%s zero store oracle\") } }\n", form.bits/8, name, form.op)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	goSource := "package main\nvar buffer [80]byte\n" + goDeclarations.String() + "func main() {\n" + goChecks.String() + "}\n"
	arm64ScalarWritebackGoOracle(t, strings.ReplaceAll(source.String(), "buffer", "·buffer"), goSource, len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolveARM64SymbolMemoryTest, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <string.h>\nunsigned char buffer[80];\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "symbol_scalar_zero_store", triple, ir, main, runner)
}

func TestCrossLinuxRuntimeMatrixARM64SymbolScalarMemory(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, declarations, checks, goDeclarations, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range arm64ScalarWritebackOps {
		for _, off := range []int{0, 1, 7, 8, 32} {
			loadName := fmt.Sprintf("scalar_wb_symbol_%d", len(sigs))
			fmt.Fprintf(&source, "TEXT %s(SB),$0-8\n%s buffer+%d(SB), R2\nMOVD R2, ret+0(FP)\nRET\n", loadName, form.op, off)
			sigs[loadName] = FuncSig{Name: loadName, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
			storeName := fmt.Sprintf("scalar_wb_symbol_%d", len(sigs))
			fmt.Fprintf(&source, "TEXT %s(SB),$0-8\nMOVD value+0(FP), R2\n%s R2, buffer+%d(SB)\nRET\n", storeName, form.op, off)
			sigs[storeName] = FuncSig{Name: storeName, Args: []LLVMType{I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
			fmt.Fprintf(&declarations, "extern uint64_t %s(void);\nextern void %s(uint64_t);\n", loadName, storeName)
			fmt.Fprintf(&goDeclarations, "func %s() uint64\nfunc %s(value uint64)\n", loadName, storeName)
			fmt.Fprintf(&checks, "{ unsigned char expected[80]; for (unsigned i=0;i<80;i++) buffer[i]=(unsigned char)(i*13+131); memcpy(expected,buffer,80); uint64_t want=0; memcpy(&want,buffer+%d,%d);\n", off, form.bits/8)
			fmt.Fprintf(&goChecks, "{ for i := range buffer { buffer[i]=byte(i*13+131) }; expected:=buffer; var want uint64; for i:=0;i<%d;i++ { want |= uint64(buffer[%d+i]) << (8*i) };\n", form.bits/8, off)
			if form.signed {
				fmt.Fprintf(&checks, "want=(uint64_t)(int64_t)(int%d_t)want;\n", form.bits)
				fmt.Fprintf(&goChecks, "want=uint64(int64(int%d(want)));\n", form.bits)
			}
			fmt.Fprintf(&checks, "if (%s()!=want) { fprintf(stderr,\"%s +%d load failed\\n\"); return 1; } uint64_t value=UINT64_C(0xfedcba9876543210); memcpy(expected+%d,&value,%d); %s(value); if(memcmp(buffer,expected,80)) { fprintf(stderr,\"%s +%d store failed\\n\"); return 2; } }\n", loadName, form.op, off, off, form.bits/8, storeName, form.op, off)
			fmt.Fprintf(&goChecks, "if %s()!=want { panic(\"%s load failed\") }; value:=uint64(0xfedcba9876543210); for i:=0;i<%d;i++ { expected[%d+i]=byte(value>>(8*i)) }; %s(value); if buffer!=expected { panic(\"%s store failed\") } }\n", loadName, form.op, form.bits/8, off, storeName, form.op)
		}
	}
	for _, op := range []string{"MOVD"} {
		name := fmt.Sprintf("scalar_wb_symbol_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-8\n%s $buffer+3(SB), R2\nMOVD R2, ret+0(FP)\nRET\n", name, op)
		sigs[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}}
		fmt.Fprintf(&declarations, "extern uint64_t %s(void);\n", name)
		fmt.Fprintf(&goDeclarations, "func %s() uint64\n", name)
		fmt.Fprintf(&checks, "if (%s()!=(uintptr_t)(buffer+3)) { fprintf(stderr,\"%s symbolic address failed\\n\"); return 3; }\n", name, op)
		fmt.Fprintf(&goChecks, "if %s()!=uint64(uintptr(unsafe.Pointer(&buffer[3]))) { panic(\"%s symbolic address failed\") };\n", name, op)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	goSource := "package main\nimport \"unsafe\"\nvar buffer [80]byte\n" + goDeclarations.String() + "func main() {\n" + goChecks.String() + "}\n"
	arm64ScalarWritebackGoOracle(t, strings.ReplaceAll(source.String(), "buffer", "·buffer"), goSource, len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolveARM64SymbolMemoryTest, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\nunsigned char buffer[80];\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "symbol_scalar_memory", triple, ir, main, runner)
}

func TestCrossLinuxRuntimeMatrixARM64SymbolScalarAddress(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = "TEXT scalar_wb_symbol_address(SB),$0-8\nMOVWU $buffer+3(SB), R2\nMOVD R2, ret+0(FP)\nRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	const goSource = `package main
import "unsafe"
var buffer [80]byte
func scalar_wb_symbol_address() uint64
func main() {
 if scalar_wb_symbol_address() != uint64(uintptr(unsafe.Pointer(&buffer[3]))) { panic("Go MOVWU address oracle") }
}
`
	arm64ScalarWritebackGoOracle(t, strings.ReplaceAll(source, "buffer", "·buffer"), goSource, len(runner) != 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolveARM64SymbolMemoryTest, Sigs: map[string]FuncSig{
		"scalar_wb_symbol_address": {Name: "scalar_wb_symbol_address", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
unsigned char buffer[80];
extern uint64_t scalar_wb_symbol_address(void);
int main(void) { return scalar_wb_symbol_address() != (uintptr_t)(buffer+3); }
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "symbol_scalar_address", triple, ir, main, runner)
}

// Keep the MOVD store's old no-op independently observable: a load failure in
// the combined family oracle must not hide this separate memory side effect.
func TestCrossLinuxRuntimeMatrixARM64SymbolScalarStore(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = "TEXT scalar_wb_symbol_store(SB),$0-8\nMOVD value+0(FP), R2\nMOVD R2, buffer+7(SB)\nRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	const goSource = `package main
var buffer [80]byte
func scalar_wb_symbol_store(value uint64)
func main() {
 for i := range buffer { buffer[i]=byte(i*13+131) }
 expected:=buffer
 value:=uint64(0xfedcba9876543210)
 for i:=0;i<8;i++ { expected[7+i]=byte(value>>(8*i)) }
 scalar_wb_symbol_store(value)
 if buffer!=expected { panic("Go MOVD symbolic store oracle") }
}
`
	arm64ScalarWritebackGoOracle(t, strings.ReplaceAll(source, "buffer", "·buffer"), goSource, len(runner) != 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolveARM64SymbolMemoryTest, Sigs: map[string]FuncSig{
		"scalar_wb_symbol_store": {Name: "scalar_wb_symbol_store", Args: []LLVMType{I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
#include <string.h>
unsigned char buffer[80];
extern void scalar_wb_symbol_store(uint64_t);
int main(void) {
 unsigned char expected[80];
 for(unsigned i=0;i<80;i++) buffer[i]=(unsigned char)(i*13+131);
 memcpy(expected,buffer,80);
 uint64_t value=UINT64_C(0xfedcba9876543210);
 memcpy(expected+7,&value,8);
 scalar_wb_symbol_store(value);
 return memcmp(buffer,expected,80)!=0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "symbol_scalar_store", triple, ir, main, runner)
}
