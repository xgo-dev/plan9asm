package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func wasmPackedResolve(symbol string) string {
	return strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(symbol, "·"), "<>"), "·", ".")
}

func wasmPackedTranslate(t *testing.T, file *File, options Options, route string) (string, error) {
	t.Helper()
	if route == "Translate" {
		return Translate(file, options)
	}
	if route == "TranslateModule" {
		mod, err := TranslateModule(file, options)
		if err != nil {
			return "", err
		}
		defer mod.Dispose()
		return mod.String(), nil
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	mod, err := TranslateModuleInContext(ctx, file, options)
	if err != nil {
		return "", err
	}
	defer mod.Dispose()
	return mod.String(), nil
}

func wasmPackedNativeSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "runtime", "sys_wasm.s"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "TEXT runtime·wasmDiv(SB)")
	if start < 0 {
		t.Fatal("actual Go wasmDiv source absent")
	}
	end := strings.Index(source[start+1:], "\nTEXT ")
	if end < 0 {
		t.Fatal("actual Go wasmDiv source boundary absent")
	}
	return source[start:start+1+end] + "\n"
}

func wasmPackedOptions(sigs map[string]FuncSig, abi WASMABI) Options {
	return Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: wasmPackedResolve, Sigs: sigs, WASMABI: abi}
}

func TestWASMMoveFamilyMatchesActualGoTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "wasm", "anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]bool)
	for _, match := range regexp.MustCompile(`(?m)^\s*"(MOV[A-Z]+)",`).FindAllSubmatch(data, -1) {
		actual[string(match[1])] = true
	}
	if len(actual) != len(wasmMoveTypes) {
		t.Fatalf("Go MOV family %v differs from typed memory widths %v", actual, wasmMoveTypes)
	}
	for opcode := range actual {
		if _, ok := wasmMoveTypes[opcode]; !ok {
			t.Errorf("Go MOV format missing: %s", opcode)
		}
	}
}

func TestWASMPackedFunctionAddressFamily(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, addend := range []int64{0, 1, 65535} {
			for _, opcode := range []string{"I64Const", "I32Const", "MOVD", "MOVW", "MOVH", "MOVB"} {
				label := fmt.Sprintf("native=%v/%s/addend=%d", native, opcode, addend)
				t.Run(label, func(t *testing.T) {
					target := "·target"
					prefix := "TEXT ·target(SB),4,$0-0\nRET\n"
					callee := FuncSig{Name: "target", Ret: Void}
					if native {
						target, prefix = "runtime·wasmDiv", wasmPackedNativeSource(t)
						var ok bool
						callee, ok = LookupGoWASMNativeFuncSig("runtime.wasmDiv")
						if !ok {
							t.Fatal("actual native contract absent")
						}
					}
					operand := fmt.Sprintf("$%s%+d(SB)", target, addend)
					body := opcode + " " + operand + "\n"
					if strings.HasPrefix(opcode, "MOV") {
						body = opcode + " " + operand + ", R0\nGet R0\n"
					} else if opcode == "I32Const" {
						body += "I64ExtendI32U\n"
					}
					source := prefix + "TEXT ·address(SB),4,$0-8\nGet SP\n" + body + "I64Store ret+0(FP)\nRET\n" +
						fmt.Sprintf("DATA holder<>(SB)/8,%s\nGLOBL holder<>(SB),24,$8\n", operand)
					for _, goos := range wasmPackedGoPlatforms {
						wasmDataGoObject(t, strings.ReplaceAll(source, "NOSPLIT", "4"), goos)
					}
					file, err := Parse(ArchWASM, source)
					if err != nil {
						t.Fatal(err)
					}
					sigs := map[string]FuncSig{wasmPackedResolve(target): callee, "address": {
						Name: "address", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}},
					}}
					for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
						ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIGo), route)
						if err != nil {
							t.Fatalf("%s actual Go address: %v", route, err)
						}
						if strings.Contains(ir, "blockaddress") || strings.Contains(ir, "llvm.global_ctors") || !strings.Contains(ir, "shl i64") {
							t.Fatalf("%s address is not a statically initialized Go packed PC:\n%s", route, ir)
						}
						if strings.Contains(ir, "i32 65536") || strings.Contains(ir, "i64 65536") {
							t.Fatal("a table index was guessed")
						}
						wasmPackedObject(t, ir)
					}
				})
			}
		}
	}
}

func wasmPackedObject(t *testing.T, ir string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	input, optimized := filepath.Join(dir, "source.ll"), filepath.Join(dir, "optimized.ll")
	object, partial := filepath.Join(dir, "source.o"), filepath.Join(dir, "partial.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	wasmDataCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
	wasmDataCommand(t, wasmDataTool(t, "llc"), "-filetype=obj", optimized, "-o", object)
	wasmDataCommand(t, wasmDataTool(t, "wasm-ld"), "-r", object, "-o", partial)
	relocs := wasmDataCommand(t, wasmDataTool(t, "llvm-readobj"), "--relocations", partial)
	if !strings.Contains(relocs, "R_WASM_TABLE_INDEX_I32") {
		t.Fatalf("partial object lost the real packed table-index relocation:\n%s", relocs)
	}
	return partial, dir
}

func TestWASMPackedFunctionAddressBoundaries(t *testing.T) {
	for _, addend := range []int64{-1, 65536, 1 << 32, -(1 << 32), 1<<63 - 1, -1 << 63} {
		for _, opcode := range []string{"DATA", "I64Const", "I32Const", "MOVD", "MOVW", "MOVH", "MOVB"} {
			t.Run(fmt.Sprintf("%s/%d", opcode, addend), func(t *testing.T) {
				source := "TEXT ·target(SB),4,$0-0\nRET\n"
				operand := fmt.Sprintf("$·target%+d(SB)", addend)
				if opcode == "DATA" {
					source += fmt.Sprintf("DATA holder(SB)/8,%s\nGLOBL holder(SB),16,$8\n", operand)
				} else {
					body := opcode + " " + operand + "\nDrop\n"
					if strings.HasPrefix(opcode, "MOV") {
						body = opcode + " " + operand + ", R0\n"
					}
					source += "TEXT ·address(SB),4,$0-0\n" + body + "RET\n"
				}
				for _, goos := range wasmPackedGoPlatforms {
					wasmDataGoObject(t, source, goos)
				}
				file, err := Parse(ArchWASM, source)
				if err != nil {
					t.Fatal(err)
				}
				sigs := map[string]FuncSig{"target": {Name: "target", Ret: Void}, "address": {Name: "address", Ret: Void}}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					_, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIGo), route)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s unrepresentable signed addend accepted: %v", route, err)
					}
				}
			})
		}
	}
}

func TestWASMPackedNativeTargetStillRejectsGoControlABI(t *testing.T) {
	for _, op := range []string{"CALL", "JMP"} {
		source := wasmPackedNativeSource(t) + "TEXT ·caller(SB),4,$0-0\n" + op + " runtime·wasmDiv(SB)\nRET\n"
		file, err := Parse(ArchWASM, source)
		if err != nil {
			t.Fatal(err)
		}
		native, _ := LookupGoWASMNativeFuncSig("runtime.wasmDiv")
		for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
			_, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{
				"runtime.wasmDiv": native, "caller": {Name: "caller", Ret: Void},
			}, WASMABIGo), route)
			if err == nil || !strings.Contains(err.Error(), "native WebAssembly signature") {
				t.Fatalf("%s %s native ABI falsely callable as Go: %v", route, op, err)
			}
		}
	}
}

func TestWASMPackedFunctionAddressUnboundExternalRemainsContext(t *testing.T) {
	for _, opcode := range []string{"DATA", "I64Const", "I32Const", "MOVB", "MOVH", "MOVW", "MOVD"} {
		source := "DATA holder(SB)/8,$external(SB)\nGLOBL holder(SB),16,$8\n"
		if opcode != "DATA" {
			body := opcode + " $external(SB)\nDrop\n"
			if strings.HasPrefix(opcode, "MOV") {
				body = opcode + " $external(SB), R0\n"
			}
			source = "TEXT ·caller(SB),4,$0-0\n" + body + "RET\n"
		}
		file, err := Parse(ArchWASM, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, native := range []bool{false, true} {
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				_, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{
					"external": {Name: "external_alias", Ret: Void, WASMNative: native}, "caller": {Name: "caller", Ret: Void},
				}, WASMABIGo), route)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s guessed the external logical PC role: %v", route, opcode, err)
				}
			}
		}
	}
}

func TestWASMPackedActualStdlibABIAddress(t *testing.T) {
	root := runtime.GOROOT()
	path := filepath.Join(root, "src", "internal", "abi", "abi_test.s")
	source, err := ReadGoAssemblySource(path, root)
	if err != nil {
		t.Fatal(err)
	}
	decl, err := os.ReadFile(filepath.Join(root, "src", "internal", "abi", "export_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.Index(string(decl), "\nvar FuncPCTestFnAddr")
	if end < 0 {
		t.Fatal("actual stdlib FuncPCTestFn declaration absent")
	}
	pkg := mustGoPackage(t, "internal/abi", string(decl[:end]))
	resolve := func(symbol string) string {
		return strings.ReplaceAll(wasmPackedResolve(symbol), "∕", "/")
	}
	for _, goos := range []string{"js", "wasip1"} {
		t.Run(goos, func(t *testing.T) {
			expanded, err := preprocessWithDefines(string(source), GoAssemblerDefines(goos, "wasm"))
			if err != nil {
				t.Fatal(err)
			}
			for _, oracleOS := range wasmPackedGoPlatforms {
				wasmDataGoObject(t, expanded, oracleOS)
			}
			file, err := Parse(ArchWASM, expanded)
			if err != nil {
				t.Fatal(err)
			}
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "wasm", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			triple := "wasm32-unknown-unknown"
			if goos == "wasip1" {
				triple = "wasm32-wasi"
			}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := wasmPackedTranslate(t, file, Options{Sigs: sigs, ResolveSym: resolve, Goarch: "wasm", TargetTriple: triple, WASMABI: WASMABIGo}, route)
				if err != nil {
					t.Fatal(err)
				}
				ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 4096", 1)
				ir += "@index = constant i32 ptrtoint (ptr @\"internal/abi.FuncPCTestFn\" to i32)\n"
				partial, dir := wasmPackedObject(t, ir)
				final := filepath.Join(dir, "stdlib.wasm")
				wasmDataCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", "--export-memory", partial, "-o", final)
				out := wasmDataCommand(t, wasmPackedNode(t), "-e", `const fs=require('fs');WebAssembly.instantiate(fs.readFileSync(process.argv[1]),{}).then(({instance:{exports:e}})=>{const v=new DataView(e.memory.buffer);const want=BigInt(v.getUint32(e.index.value,true))<<16n;const got=v.getBigUint64(e['internal/abi.FuncPCTestFnAddr'].value,true);if(got!==want)throw Error('original stdlib first-memory PC');console.log('original internal/abi/abi_test.s packed DATA PASS')}).catch(e=>{console.error(e);process.exit(1)});`, final)
				t.Logf("%s: %s", route, strings.TrimSpace(out))
			}
		})
	}
}

// A missing required runtime is a hard failure, not a skipped source form.
func wasmPackedNode(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("required Node WebAssembly runtime is unavailable")
	}
	return path
}
