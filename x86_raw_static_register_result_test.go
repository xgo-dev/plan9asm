package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86DirectStaticRegisterResultRejectsForeignSignatureRoles(t *testing.T) {
	file := mustParseX86RawReturn(t, "TEXT Raw(SB),4,$0-0\nMOVQ saved(SB),AX\nRET\n")
	for _, typ := range []LLVMType{Void, I1, Ptr, "float", "double", "i128", "{i32,i32}"} {
		t.Run(string(typ), func(t *testing.T) {
			if x86DirectStaticRegisterResultCandidate(file.Funcs[0], FuncSig{Name: "Raw", Ret: typ}, "amd64") {
				t.Fatal("a foreign scalar role borrowed the integer AX result observer")
			}
		})
	}
}

func TestX86RawStaticRegisterReturnCompleteMoveWidths(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			op, register string
			typ          LLVMType
		}{{"MOVB", "AL", I8}, {"MOVW", "AX", I16}, {"MOVL", "AX", I32}, {"MOVQ", "AX", I64}} {
			if row.typ == I64 && target.arch == "386" {
				continue // This direct scalar role has no physical mode32 qword GP transport.
			}
			for _, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
				t.Run(target.triple+"/"+row.op+"/"+encoding, func(t *testing.T) {
					source := fmt.Sprintf("GLOBL saved<>(SB),8,$32\nTEXT Raw(SB),4,$0-0\n%s $17,%s\n%s %s,saved<>+4(SB)\n%s saved<>+4(SB),%s\n%s\nRET\n",
						row.op, row.register, row.op, row.register, row.op, row.register, encoding)
					requireX86GoAssemblerResult(t, target.arch, source, true)
					options := Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Ret: row.typ}}}
					x86RawReturnPointerAPIs(t, source, options, false)
					if err := CheckX86ABI0ResultInitialization(mustParseX86RawReturn(t, source).Funcs[0], options.Sigs["Raw"], target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("the standalone ABI0 query borrowed direct-register lowering", err)
					}
				})
			}
		}
	}
}

// Execute the portable integer/static LLVM lowering on the actual host.
// This is not an original-Go ABI or physical raw-RET execution certificate.
func TestX86DirectStaticRegisterResultHostRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	var source, reference strings.Builder
	options := Options{Goarch: "amd64", TargetTriple: testTargetTriple(runtime.GOOS, runtime.GOARCH), Sigs: make(map[string]FuncSig)}
	reference.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	var checks strings.Builder
	for _, row := range []struct {
		op, register, cType string
		typ                 LLVMType
	}{{"MOVB", "AL", "uint8_t", I8}, {"MOVW", "AX", "uint16_t", I16}, {"MOVL", "AX", "uint32_t", I32}, {"MOVQ", "AX", "uint64_t", I64}} {
		for index, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
			name := fmt.Sprintf("Result%s%d", row.op, index)
			// The original compile-only counterexamples use RODATA (8).
			// This explicit executable counterpart needs writable NOPTR (16).
			fmt.Fprintf(&source, "GLOBL %sData<>(SB),16,$32\nTEXT %s(SB),4,$0-0\n%s $17,%s\n%s %s,%sData<>+4(SB)\n%s %sData<>+4(SB),%s\n%s\nRET\n",
				name, name, row.op, row.register, row.op, row.register, name, row.op, name, row.register, encoding)
			options.Sigs[name] = FuncSig{Name: name, Ret: row.typ}
			fmt.Fprintf(&reference, "extern %s %s(void);\n", row.cType, name)
			fmt.Fprintf(&checks, "if(%s()!=17){fprintf(stderr,\"%s incorrect\\n\");return 1;}\n", name, name)
		}
	}
	reference.WriteString("int main(void){\n" + checks.String() + "return 0;\n}\n")
	file := mustParseX86RawReturn(t, source.String())
	for _, api := range []string{"text", "module", "owned-module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87UnboundOriginalAPI(t, file, options, api)
			if err != nil || ir == "" {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				objectIR := ir
				if optimized {
					objectIR = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "direct-static", options.TargetTriple, objectIR, reference.String(), nil, level)
					})
				}
			}
		})
	}
}

func TestX86RawStaticRegisterReturnDoesNotInventSourceBytes(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			op, register string
			typ          LLVMType
		}{{"MOVB", "AL", I8}, {"MOVW", "AX", I16}, {"MOVL", "AX", I32}, {"MOVQ", "AX", I64}} {
			if row.typ == I64 && target.arch == "386" {
				continue
			}
			body := fmt.Sprintf("%s $17,%s\n%s %s,saved<>+4(SB)\n%s saved<>+4(SB),%s\n",
				row.op, row.register, row.op, row.register, row.op, row.register)
			for _, mutation := range []struct{ name, body string }{
				{"unknown-store-input", strings.Replace(body, row.op+" $17,"+row.register, "NOP", 1)},
				{"unbound-static-read", strings.Replace(body, "saved<>+4(SB),"+row.register, "external+4(SB),"+row.register, 1)},
				{"outside-static-extent", strings.Replace(body, "saved<>+4(SB),"+row.register, "saved<>+32(SB),"+row.register, 1)},
				{"unknown-final-result", body + "MOVL DX,AX\n"},
			} {
				t.Run(target.triple+"/"+row.op+"/"+mutation.name, func(t *testing.T) {
					source := "GLOBL saved<>(SB),8,$32\nTEXT Raw(SB),4,$0-0\n" + mutation.body + "BYTE $0xc3\nRET\n"
					requireX86GoAssemblerResult(t, target.arch, source, true)
					options := Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Ret: row.typ}}}
					x86RawReturnPointerAPIs(t, source, options, true)
				})
			}
		}
	}
}
