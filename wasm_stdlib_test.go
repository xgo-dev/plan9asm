package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestOfficialWasmBytealgCompareTranslationAndExecution(t *testing.T) {
	file := parseOfficialWasmAssembly(t, "internal/bytealg", "compare_wasm.s")
	resolve := officialWasmResolver("internal/bytealg")
	sigs := inferOfficialWasmLocalSigs(t, file, resolve)
	sigs["internal/bytealg.Compare"] = FuncSig{
		Name: "internal/bytealg.Compare", Args: []LLVMType{"{ ptr, i64, i64 }", "{ ptr, i64, i64 }"}, Ret: I64,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: 0}, {Offset: 8, Type: I64, Index: 0, Field: 1},
			{Offset: 24, Type: Ptr, Index: 1, Field: 0}, {Offset: 32, Type: I64, Index: 1, Field: 1},
		}, Results: []FrameSlot{{Offset: 48, Type: I64, Index: 0, Field: -1}}},
	}
	sigs["runtime.cmpstring"] = FuncSig{
		Name: "runtime.cmpstring", Args: []LLVMType{"{ ptr, i64 }", "{ ptr, i64 }"}, Ret: I64,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: 0}, {Offset: 8, Type: I64, Index: 0, Field: 1},
			{Offset: 16, Type: Ptr, Index: 1, Field: 0}, {Offset: 24, Type: I64, Index: 1, Field: 1},
		}, Results: []FrameSlot{{Offset: 32, Type: I64, Index: 0, Field: -1}}},
	}
	ir := translateOfficialWasm(t, file, resolve, sigs)
	for _, want := range []string{
		`define i64 @"internal/bytealg.cmpbody$local"`,
		`define i32 @"internal/bytealg.memcmp$local"`,
		"wasm_loop_",
		"wasm_function_return:",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("translated compare IR is missing %q", want)
		}
	}
	assertWasmLocalsPromoted(t, ir)
	executeOfficialWasm(t, ir, []string{"internal/bytealg.memcmp$local"},
		`const m=new Uint8Array(i.exports.memory.buffer);m.set([1,2,3],1024);m.set([1,2,4],2048);const f=i.exports["internal/bytealg.memcmp$local"];console.log(f(1024,2048,3)+","+f(1024,1024,3)+","+f(2048,1024,3));`,
		"-1,0,1")
}

func TestOfficialWasmBytealgIndexByteTranslationAndExecution(t *testing.T) {
	file := parseOfficialWasmAssembly(t, "internal/bytealg", "indexbyte_wasm.s")
	file.Funcs = keepWasmFuncs(file.Funcs, "memchr<>")
	resolve := officialWasmResolver("internal/bytealg")
	sigs := inferOfficialWasmLocalSigs(t, file, resolve)
	ir := translateOfficialWasm(t, file, resolve, sigs)
	if !strings.Contains(ir, `define i32 @"internal/bytealg.memchr$local"`) {
		t.Fatalf("translated indexbyte IR is missing memchr")
	}
	assertWasmLocalsPromoted(t, ir)
	executeOfficialWasm(t, ir, []string{"internal/bytealg.memchr$local"},
		`const m=new Uint8Array(i.exports.memory.buffer);m.set([4,8,15,16],1024);const f=i.exports["internal/bytealg.memchr$local"];console.log(f(1024,15,4)+","+f(1024,23,4)+","+f(1024,4,4));`,
		"1026,0,1024")
}

func TestOfficialWasmBytealgEqualTranslationAndExecution(t *testing.T) {
	file := parseOfficialWasmAssembly(t, "internal/bytealg", "equal_wasm.s")
	file.Funcs = keepWasmFuncs(file.Funcs, "memeqbody<>")
	resolve := officialWasmResolver("internal/bytealg")
	sigs := inferOfficialWasmLocalSigs(t, file, resolve)
	ir := translateOfficialWasm(t, file, resolve, sigs)
	if !strings.Contains(ir, `define i64 @"internal/bytealg.memeqbody$local"`) {
		t.Fatalf("translated equal IR is missing memeqbody")
	}
	assertWasmLocalsPromoted(t, ir)
	executeOfficialWasm(t, ir, []string{"internal/bytealg.memeqbody$local"},
		`const m=new Uint8Array(i.exports.memory.buffer);m.set([1,2,3],1024);m.set([1,2,3],2048);m.set([1,2,4],3072);const f=i.exports["internal/bytealg.memeqbody$local"];console.log(f(1024n,2048n,3n)+","+f(1024n,3072n,3n)+","+f(1024n,3072n,0n));`,
		"1,0,1")
}

func TestOfficialWasmAtomicStoreTranslationAndExecution(t *testing.T) {
	file, pkg := parseOfficialWasmAssemblyFromPackages(t, []string{"internal/runtime/atomic", "runtime/internal/atomic"}, "atomic_wasm.s")
	resolve := officialWasmResolver(pkg)
	storeName := pkg + ".StorepNoWB"
	sigs := map[string]FuncSig{
		storeName: {
			Name: storeName, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		},
	}
	ir := translateOfficialWasm(t, file, resolve, sigs)
	if !strings.Contains(ir, "store i64") {
		t.Fatalf("translated atomic store IR is missing the 64-bit Go pointer store")
	}
	assertWasmLocalsPromoted(t, ir)
	executeOfficialWasm(t, ir, []string{storeName},
		`const f=i.exports[`+strconv.Quote(storeName)+`];f(1024,2048);console.log(new DataView(i.exports.memory.buffer).getBigUint64(1024,true));`,
		"2048n")
}

func TestOfficialWasmMemorySizeAndGrowTranslationAndExecution(t *testing.T) {
	file := parseOfficialWasmAssembly(t, "runtime", "sys_wasm.s")
	hasCurrentMemory := hasWasmFunc(file.Funcs, "runtime·currentMemory")
	if hasCurrentMemory {
		file.Funcs = keepWasmFuncs(file.Funcs, "runtime·currentMemory", "runtime·growMemory")
	} else {
		file.Funcs = keepWasmFuncs(file.Funcs, "runtime·growMemory")
	}
	resolve := officialWasmResolver("runtime")
	sigs := map[string]FuncSig{
		"runtime.growMemory": {
			Name: "runtime.growMemory", Args: []LLVMType{I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
	}
	if hasCurrentMemory {
		sigs["runtime.currentMemory"] = FuncSig{
			Name: "runtime.currentMemory", Ret: I32,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
		}
	}
	ir := translateOfficialWasm(t, file, resolve, sigs)
	if !strings.Contains(ir, "llvm.wasm.memory.grow.i32") {
		t.Fatal("translated sys IR is missing llvm.wasm.memory.grow.i32")
	}
	if hasCurrentMemory && !strings.Contains(ir, "llvm.wasm.memory.size.i32") {
		t.Fatal("translated sys IR is missing llvm.wasm.memory.size.i32")
	}
	if hasCurrentMemory {
		executeOfficialWasm(t, ir, []string{"runtime.currentMemory", "runtime.growMemory"},
			`const size=i.exports["runtime.currentMemory"],grow=i.exports["runtime.growMemory"];const before=size(),old=grow(1),after=size();console.log(old===before&&after===before+1);`,
			"true")
		return
	}
	executeOfficialWasm(t, ir, []string{"runtime.growMemory"},
		`const grow=i.exports["runtime.growMemory"];console.log(grow(1));`, "2")
}

func TestOfficialWasmClosureContextTranslationAndExecution(t *testing.T) {
	file := parseOfficialWasmAssembly(t, "internal/bytealg", "equal_wasm.s")
	resolve := officialWasmResolver("internal/bytealg")
	sigs := inferOfficialWasmLocalSigs(t, file, resolve)
	sigs["runtime.memequal"] = FuncSig{
		Name: "runtime.memequal", Args: []LLVMType{Ptr, Ptr, I64}, Ret: I1,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: I64, Index: 2, Field: -1},
		}, Results: []FrameSlot{{Offset: 24, Type: I1, Index: 0, Field: -1}}},
	}
	sigs["runtime.memequal_varlen"] = FuncSig{
		Name: "runtime.memequal_varlen", Args: []LLVMType{Ptr, Ptr}, Ret: I1,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}, Results: []FrameSlot{{Offset: 16, Type: I1, Index: 0, Field: -1}}},
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		ResolveSym:   resolve,
		Sigs:         sigs,
		Goarch:       "wasm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, `define i1 @runtime.memequal_varlen(ptr %wasm_context, ptr %arg0, ptr %arg1)`) ||
		!strings.Contains(ir, "getelementptr i8, ptr %wasm_context, i32 8") {
		t.Fatalf("translated closure entry does not preserve its physical context:\n%s", ir)
	}
	executeOfficialWasm(t, ir, []string{"runtime.memequal_varlen"},
		`const m=new Uint8Array(i.exports.memory.buffer),v=new DataView(m.buffer);m.set([1,2,3],1024);m.set([1,2,3],2048);m.set([1,2,4],3072);v.setBigUint64(4104,3n,true);const f=i.exports["runtime.memequal_varlen"];console.log(f(4096,1024,2048)+","+f(4096,1024,3072));`,
		"1,0")
}

func parseOfficialWasmAssembly(t *testing.T, pkg, name string) *File {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(pkg), name))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchWASM, string(src))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func parseOfficialWasmAssemblyFromPackages(t *testing.T, packages []string, name string) (*File, string) {
	t.Helper()
	for _, pkg := range packages {
		path := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(pkg), name)
		if _, err := os.Stat(path); err == nil {
			return parseOfficialWasmAssembly(t, pkg, name), pkg
		}
	}
	t.Fatalf("%s not found under any of %v", name, packages)
	return nil, ""
}

func officialWasmResolver(pkg string) func(string) string {
	return func(sym string) string {
		local := strings.HasSuffix(sym, "<>")
		sym = strings.TrimSuffix(sym, "<>")
		var name string
		if strings.HasPrefix(sym, "·") {
			name = pkg + "." + strings.TrimPrefix(sym, "·")
		} else {
			name = strings.ReplaceAll(sym, "·", ".")
			if !strings.Contains(name, ".") {
				name = pkg + "." + name
			}
		}
		if local {
			name += "$local"
		}
		return name
	}
}

func inferOfficialWasmLocalSigs(t *testing.T, file *File, resolve func(string) string) map[string]FuncSig {
	t.Helper()
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		if !strings.HasSuffix(fn.Sym, "<>") {
			continue
		}
		name := resolve(fn.Sym)
		sig, err := InferWASMAssemblyFuncSig(fn, name)
		if err != nil {
			t.Fatal(err)
		}
		sigs[name] = sig
	}
	return sigs
}

func keepWasmFuncs(funcs []Func, symbols ...string) []Func {
	want := make(map[string]bool, len(symbols))
	for _, symbol := range symbols {
		want[symbol] = true
	}
	kept := make([]Func, 0, len(symbols))
	for _, fn := range funcs {
		if want[fn.Sym] {
			kept = append(kept, fn)
		}
	}
	return kept
}

func hasWasmFunc(funcs []Func, symbol string) bool {
	for _, fn := range funcs {
		if fn.Sym == symbol {
			return true
		}
	}
	return false
}

func translateOfficialWasm(t *testing.T, file *File, resolve func(string) string, sigs map[string]FuncSig) string {
	t.Helper()
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		ResolveSym:   resolve,
		Sigs:         sigs,
		Goarch:       "wasm",
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func assertWasmLocalsPromoted(t *testing.T, ir string) {
	t.Helper()
	if strings.Contains(ir, " alloca ") {
		t.Fatalf("translated wasm still spills virtual registers through allocas")
	}
}

func executeOfficialWasm(t *testing.T, ir string, exports []string, body, want string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	wasmLD := findLLVM22Tool("wasm-ld")
	node := findExecutable("node")
	if llc == "" || wasmLD == "" || node == "" {
		t.Log("wasm execution tools unavailable; translation was still verified")
		return
	}

	dir := t.TempDir()
	llFile := filepath.Join(dir, "test.ll")
	objFile := filepath.Join(dir, "test.o")
	wasmFile := filepath.Join(dir, "test.wasm")
	if err := os.WriteFile(llFile, []byte(ir), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(llc, "-filetype=obj", llFile, "-o", objFile).CombinedOutput(); err != nil {
		t.Fatalf("llc: %v\n%s", err, out)
	}
	// Keep one page for the stack and one for test data. Newer wasm-ld releases
	// place the stack immediately above the first page and reject a one-page
	// initial memory before any test code can run.
	linkArgs := []string{"--no-entry", "--export-memory", "--initial-memory=131072"}
	for _, name := range exports {
		linkArgs = append(linkArgs, "--export="+name)
	}
	linkArgs = append(linkArgs, objFile, "-o", wasmFile)
	if out, err := exec.Command(wasmLD, linkArgs...).CombinedOutput(); err != nil {
		t.Fatalf("wasm-ld: %v\n%s", err, out)
	}
	script := `const fs=require("fs");WebAssembly.instantiate(fs.readFileSync(process.argv[1]),{}).then(({instance:i})=>{` + body + `})`
	out, err := exec.Command(node, "-e", script, wasmFile).CombinedOutput()
	if err != nil {
		t.Fatalf("node wasm execution: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("wasm result = %q, want %q", got, want)
	}
}

func findExecutable(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
