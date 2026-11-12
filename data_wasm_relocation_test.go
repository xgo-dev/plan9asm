package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

// These are Go's eight-byte DATA slots, not widened LLVM wasm32 pointers.
// The address arithmetic oracle below uses independent JavaScript BigInts.
var wasmDataAddends = []int64{0, 4, -4, 1 << 32, -(1 << 32), 1<<63 - 1, -1 << 63}

func wasmDataResolve(symbol string) string {
	symbol = strings.TrimSuffix(strings.TrimPrefix(symbol, "·"), "<>")
	return "wasm_data." + symbol
}

func wasmDataSource() string {
	var source strings.Builder
	source.WriteString(`TEXT return42<>(SB),4,$0-8
Get SP
I64Const $42
I64Store ret+0(FP)
RET
DATA payload(SB)/8,$0x1122334455667788
GLOBL payload(SB),16,$8
DATA private_target<>(SB)/8,$0x8877665544332211
GLOBL private_target<>(SB),24,$8
`)
	for _, holder := range []struct {
		name  string
		start int
		flags int
	}{
		{"public_holder", 1, 16},
		{"private_holder<>", 3, 16},
		{"readonly_holder", 3, 24},
	} {
		fmt.Fprintf(&source, "DATA %s(SB)/1,$0xa5\n", holder.name)
		for index, addend := range wasmDataAddends {
			suffix := ""
			if addend != 0 {
				suffix = fmt.Sprintf("%+d", addend)
			}
			fmt.Fprintf(&source, "DATA %s+%d(SB)/8,$payload%s(SB)\n", holder.name, holder.start+index*8, suffix)
		}
		fmt.Fprintf(&source, "DATA %s+%d(SB)/1,$0x5a\nGLOBL %s(SB),%d,$64\n", holder.name, holder.start+56, holder.name, holder.flags)
	}
	source.WriteString(`DATA function_holder<>(SB)/1,$0xa5
DATA function_holder<>+1(SB)/8,$return42<>(SB)
DATA function_holder<>+9(SB)/1,$0x5a
GLOBL function_holder<>(SB),24,$16
DATA private_target_holder<>(SB)/8,$private_target<>(SB)
GLOBL private_target_holder<>(SB),24,$8
`)
	return source.String()
}

func wasmDataCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %q: %v\n%s", filepath.Base(name), args, err, out)
	}
	return string(out)
}

func wasmDataTool(t *testing.T, name string) string {
	t.Helper()
	if path := findLLVM22Tool(name); path != "" {
		return path
	}
	t.Fatalf("required LLVM 22 %s is unavailable", name)
	return ""
}

func wasmDataGoObject(t *testing.T, source, goos string) {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "data.s"), filepath.Join(dir, "go.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "wasm_data", "-o", object, input)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual Go %s/wasm rejected source: %v\n%s\n%s", goos, err, out, source)
	}
	if info, err := os.Stat(object); err != nil || info.Size() == 0 {
		t.Fatalf("actual Go %s/wasm produced no object: %v", goos, err)
	}
}

// Add ordinary LLVM consumers to the actual translated module. No consumer
// names return42 or private_target: those definitions are module-asm-only roots.
func wasmDataConsumers(t *testing.T, ctx llvm.Context, mod llvm.Module) {
	t.Helper()
	builder := ctx.NewBuilder()
	defer builder.Dispose()
	i32, i64 := ctx.Int32Type(), ctx.Int64Type()
	for _, name := range []string{"public_holder", "private_holder", "readonly_holder", "function_holder", "private_target_holder"} {
		global := mod.NamedGlobal(wasmDataResolve(name))
		if global.IsNil() {
			t.Fatalf("translated holder %s is absent", name)
		}
		address := llvm.AddFunction(mod, name+"_address", llvm.FunctionType(i32, nil, false))
		builder.SetInsertPointAtEnd(ctx.AddBasicBlock(address, "entry"))
		builder.CreateRet(builder.CreatePtrToInt(global, i32, "address"))

		load := llvm.AddFunction(mod, name+"_load", llvm.FunctionType(i64, []llvm.Type{i32}, false))
		builder.SetInsertPointAtEnd(ctx.AddBasicBlock(load, "entry"))
		pointer := builder.CreateGEP(ctx.Int8Type(), global, []llvm.Value{load.Param(0)}, "slot")
		value := builder.CreateLoad(i64, pointer, "value")
		value.SetAlignment(1)
		builder.CreateRet(value)
	}

	address := llvm.AddFunction(mod, "payload_address", llvm.FunctionType(i32, nil, false))
	builder.SetInsertPointAtEnd(ctx.AddBasicBlock(address, "entry"))
	builder.CreateRet(builder.CreatePtrToInt(mod.NamedGlobal(wasmDataResolve("payload")), i32, "address"))

	call := llvm.AddFunction(mod, "call_from_holder", llvm.FunctionType(i64, nil, false))
	builder.SetInsertPointAtEnd(ctx.AddBasicBlock(call, "entry"))
	pointer := builder.CreateGEP(ctx.Int8Type(), mod.NamedGlobal(wasmDataResolve("function_holder")), []llvm.Value{llvm.ConstInt(i32, 1, false)}, "slot")
	value := builder.CreateLoad(i64, pointer, "table_index")
	value.SetAlignment(1)
	index := builder.CreateTrunc(value, i32, "physical_table_index")
	function := builder.CreateIntToPtr(index, llvm.PointerType(ctx.Int8Type(), 0), "function")
	builder.CreateRet(builder.CreateCall(llvm.FunctionType(i64, nil, false), function, nil, "result"))
}

func TestWASMDataRelocationsOptimizeLinkAndExecute(t *testing.T) {
	opt, llc := wasmDataTool(t, "opt"), wasmDataTool(t, "llc")
	readobj, linker := wasmDataTool(t, "llvm-readobj"), wasmDataTool(t, "wasm-ld")
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("required Node WebAssembly runtime is unavailable")
	}
	source := wasmDataSource()
	// js/wasm is shared by the historical Go 1.20 matrix. wasip1 starts in
	// Go 1.21 and belongs in a separately version-tagged source oracle.
	wasmDataGoObject(t, source, "js")
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: wasmDataResolve,
		Sigs: map[string]FuncSig{
			"wasm_data.return42": {Name: "wasm_data.return42", Ret: I64,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Field: -1}}}},
		},
	}
	for _, route := range []string{"Translate", "TranslateModule"} {
		t.Run(route, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			var mod llvm.Module
			var err error
			if route == "Translate" {
				ir, translateErr := Translate(file, options)
				if translateErr != nil {
					t.Fatal(translateErr)
				}
				mod, err = parseIRModuleInContext(ctx, ir)
			} else {
				mod, err = TranslateModuleInContext(ctx, file, options)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer mod.Dispose()
			for name, readOnly := range map[string]bool{
				"public_holder": false, "private_holder": false, "readonly_holder": true,
				"function_holder": true, "private_target_holder": true,
			} {
				global := mod.NamedGlobal(wasmDataResolve(name))
				if global.IsNil() || global.IsGlobalConstant() != readOnly {
					t.Fatalf("holder %s lost its source readonly/mutable contract", name)
				}
			}
			wasmDataConsumers(t, ctx, mod)
			ir := mod.String()
			for _, forbidden := range []string{"blockaddress(", "p:64:", "addrspacecast", "@llvm.global_ctors"} {
				if strings.Contains(ir, forbidden) {
					t.Fatalf("wasm DATA must not use %s", forbidden)
				}
			}
			dir := t.TempDir()
			input, optimized := filepath.Join(dir, "source.ll"), filepath.Join(dir, "optimized.ll")
			object, partial := filepath.Join(dir, "data.o"), filepath.Join(dir, "partial.o")
			final := filepath.Join(dir, "linked.wasm")
			if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			wasmDataCommand(t, opt, "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
			optimizedIR, err := os.ReadFile(optimized)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(optimizedIR), "@llvm.used") || !strings.Contains(string(optimizedIR), "internal constant [8 x i8]") {
				t.Fatalf("module-only private target was lost to DCE:\n%s", optimizedIR)
			}
			wasmDataCommand(t, llc, "-O2", "-filetype=obj", optimized, "-o", object)
			relocations := wasmDataCommand(t, readobj, "--file-headers", "--relocations", "--symbols", object)
			if !strings.Contains(relocations, "Arch: wasm32") || !strings.Contains(relocations, "AddressSize: 32bit") {
				t.Fatalf("not a real wasm32 object:\n%s", relocations)
			}
			if strings.Count(relocations, "R_WASM_MEMORY_ADDR_I64") != 22 || strings.Count(relocations, "R_WASM_TABLE_INDEX_I64") != 1 {
				t.Fatalf("missing full-width DATA relocations:\n%s", relocations)
			}
			for _, name := range []string{"private_holder", "function_holder", "private_target_holder"} {
				start := strings.Index(relocations, "Name: "+wasmDataResolve(name))
				if start < 0 {
					t.Fatalf("local holder %s absent from object", name)
				}
				end := strings.Index(relocations[start:], "\n  }")
				if end < 0 || !strings.Contains(relocations[start:start+end], "BINDING_LOCAL") || !strings.Contains(relocations[start:start+end], "VISIBILITY_HIDDEN") {
					t.Fatalf("local holder %s escaped object-local visibility:\n%s", name, relocations)
				}
			}
			for _, addend := range wasmDataAddends {
				if !strings.Contains(relocations, "wasm_data.payload "+fmt.Sprint(addend)) {
					t.Fatalf("missing signed64 addend %d:\n%s", addend, relocations)
				}
			}
			wasmDataCommand(t, linker, "-r", object, "-o", partial)
			partialRelocations := wasmDataCommand(t, readobj, "--relocations", partial)
			for _, addend := range wasmDataAddends {
				if !strings.Contains(partialRelocations, "wasm_data.payload "+fmt.Sprint(addend)) {
					t.Fatalf("partial linking lost signed64 addend %d:\n%s", addend, partialRelocations)
				}
			}
			wasmDataCommand(t, linker, "--no-entry", "--export-all", "--export-memory", "--export-table", "--emit-relocs", partial, "-o", final)
			out := wasmDataCommand(t, node, "-e", wasmDataNodeOracle, final)
			if strings.TrimSpace(out) != "wasm32 full64 DATA + LLVM loads + indirect call PASS" {
				t.Fatalf("unexpected Node result: %q", out)
			}
			t.Log(strings.TrimSpace(out))
		})
	}
}

const wasmDataNodeOracle = `
const fs = require("fs");
WebAssembly.instantiate(fs.readFileSync(process.argv[1]), {}).then(({instance}) => {
  const e = instance.exports;
  const view = new DataView(e.memory.buffer);
  const target = BigInt(e.payload_address() >>> 0);
  const addends = [0n, 4n, -4n, 4294967296n, -4294967296n, 9223372036854775807n, -9223372036854775808n];
  for (const [name, start] of [["public_holder",1], ["private_holder",3], ["readonly_holder",3]]) {
    const address = e[name + "_address"]() >>> 0;
    if (address % 16 || view.getUint8(address) !== 165 || view.getUint8(address + start + 56) !== 90) throw Error("holder alignment or guards");
    for (let i = 1; i < start; i++) if (view.getUint8(address + i) !== 0) throw Error("prefix byte gap");
    for (let i = start + 57; i < 64; i++) if (view.getUint8(address + i) !== 0) throw Error("tail byte gap");
    addends.forEach((addend, i) => {
      const offset = start + i * 8;
      const want = BigInt.asUintN(64, target + addend);
      const direct = view.getBigUint64(address + offset, true);
      const fromLLVM = BigInt.asUintN(64, e[name + "_load"](offset));
      if (direct !== want || fromLLVM !== want) throw Error(name + " slot" + i + " lost full64 address/addend");
    });
  }
  const functionAddress = e.function_holder_address() >>> 0;
  if (view.getUint8(functionAddress) !== 165 || view.getUint8(functionAddress + 9) !== 90) throw Error("function guards");
  const index = view.getBigUint64(functionAddress + 1, true);
  if (BigInt.asUintN(64, e.function_holder_load(1)) !== index || e.__indirect_function_table.get(Number(index))() !== 42n || e.call_from_holder() !== 42n) throw Error("real function index/LLVM indirect call");
  const privateAddress = e.private_target_holder_load(0);
  if (privateAddress <= 0n || privateAddress >= 4294967296n || view.getBigUint64(Number(privateAddress), true) !== 0x8877665544332211n) throw Error("module-only private target DCE/layout");
  console.log("wasm32 full64 DATA + LLVM loads + indirect call PASS");
}).catch(error => { console.error(error); process.exitCode = 1; });
`

func TestWASMDataFunctionAddendsRequireContextAfterGoAcceptance(t *testing.T) {
	for _, binding := range []string{"source_TEXT", "declared_function"} {
		for _, addend := range []int64{1, -1, 1 << 32, -(1 << 32), 1<<63 - 1, -1 << 63} {
			t.Run(binding+"/"+fmt.Sprint(addend), func(t *testing.T) {
				target, prefix := "target", ""
				if binding == "source_TEXT" {
					target, prefix = "target<>", "TEXT target<>(SB),4,$0-0\nRET\n"
				}
				source := prefix + fmt.Sprintf("DATA holder<>(SB)/8,$%s%+d(SB)\nGLOBL holder<>(SB),24,$8\n", target, addend)
				wasmDataGoObject(t, source, "js")
				file, err := Parse(ArchWASM, source)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: wasmDataResolve,
					Sigs: map[string]FuncSig{"wasm_data.target": {Name: "wasm_data.target", Ret: Void}},
				}
				if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Go-accepted function addend must retain Context, got %v", err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateModuleInContext(ctx, file, options)
				if err == nil {
					mod.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("module route accepted an unrepresentable function addend: %v", err)
				}
			})
		}
	}
}

func TestWASMDataRelocationsRequireLLVM22Tools(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestWASMDataRelocationsOptimizeLinkAndExecute$", "-test.v")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(variable), "LLVM_CONFIG=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "LLVM_CONFIG="+filepath.Join(t.TempDir(), "missing-llvm-config"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "required LLVM 22 opt is unavailable") {
		t.Fatalf("missing required tools must fail, not skip or succeed: %v\n%s", err, out)
	}
}

func TestWASMDataFunctionAddressesRespectPhysicalABI(t *testing.T) {
	opt, llc := wasmDataTool(t, "opt"), wasmDataTool(t, "llc")
	readobj := wasmDataTool(t, "llvm-readobj")
	for _, binding := range []string{"source_TEXT", "declared_function_alias", "source_DATA"} {
		t.Run(binding, func(t *testing.T) {
			source := "DATA holder<>(SB)/8,$target(SB)\nGLOBL holder<>(SB),24,$8\n"
			name := "wasm_data.external_alias"
			if binding == "source_TEXT" {
				source = "TEXT target(SB),4,$0-0\nRET\n" + source
				name = "wasm_data.target"
			} else if binding == "source_DATA" {
				source = "DATA target(SB)/8,$42\nGLOBL target(SB),16,$8\n" + source
				name = "wasm_data.target"
			}
			wasmDataGoObject(t, source, "js")
			file, err := Parse(ArchWASM, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, abi := range []WASMABI{WASMABIDirect, WASMABIGo} {
				label := "direct_table_index"
				if binding == "source_DATA" {
					label = "direct_linear_data_address"
				}
				if abi == WASMABIGo {
					label = "Go_packed_resume_PC"
					if binding == "declared_function_alias" {
						label = "unbound_Go_logical_PC_requires_context"
					}
					if binding == "source_DATA" {
						label = "Go_linear_data_address"
					}
				}
				t.Run(label, func(t *testing.T) {
					options := Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", ResolveSym: wasmDataResolve, WASMABI: abi,
						Sigs: map[string]FuncSig{"wasm_data.target": {Name: name, Ret: Void}},
					}
					if binding == "source_DATA" {
						options.Sigs = nil
					}
					for _, route := range []string{"Translate", "TranslateModule"} {
						t.Run(route, func(t *testing.T) {
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							var ir string
							var err error
							if route == "Translate" {
								ir, err = Translate(file, options)
							} else {
								var mod llvm.Module
								mod, err = TranslateModuleInContext(ctx, file, options)
								if err == nil {
									ir = mod.String()
									mod.Dispose()
								}
							}
							if abi == WASMABIGo && binding == "declared_function_alias" {
								// A physical signature alone does not establish the
								// unknown external function's logical-PC role.
								if !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatalf("Go function DATA cannot impersonate a direct table index, got %v", err)
								}
								return
							}
							if err != nil {
								t.Fatal(err)
							}
							dir := t.TempDir()
							input, optimized := filepath.Join(dir, "source.ll"), filepath.Join(dir, "optimized.ll")
							object := filepath.Join(dir, "data.o")
							if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
								t.Fatal(err)
							}
							wasmDataCommand(t, opt, "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
							wasmDataCommand(t, llc, "-filetype=obj", optimized, "-o", object)
							relocations := wasmDataCommand(t, readobj, "--relocations", object)
							expected, wrong := "R_WASM_TABLE_INDEX_I64", "R_WASM_MEMORY_ADDR_I64"
							if binding == "source_DATA" {
								expected, wrong = wrong, expected
							} else if abi == WASMABIGo {
								expected = "R_WASM_TABLE_INDEX_I32"
							}
							if !strings.Contains(relocations, expected+" "+name) || strings.Contains(relocations, wrong+" "+name) {
								t.Fatalf("typed data/code target was not retained in its proper address space:\n%s", relocations)
							}
						})
					}
				})
			}
		})
	}
}
