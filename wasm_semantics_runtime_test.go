package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Optimize before execution: LLVM poison and dead operations can pass llc yet
// produce different results from WebAssembly's defined arithmetic and traps.
func TestCrossArchWasmObservableSemantics(t *testing.T) {
	type example struct{ name, body, want string }
	var cases []example
	add := func(name, body, want string) { cases = append(cases, example{name, body, want}) }
	for _, width := range []int{32, 64} {
		typ := fmt.Sprintf("I%d", width)
		result := ""
		if width == 64 {
			result = "\nI32WrapI64"
		}
		min := "-2147483648"
		if width == 64 {
			min = "-9223372036854775808"
		}
		for _, op := range []string{"DivS", "DivU", "RemS", "RemU"} {
			add(typ+op+"Zero", typ+"Const $3\n"+typ+"Const $0\n"+typ+op+"\nDrop\nI32Const $7", "trap")
		}
		add(typ+"DivOverflow", typ+"Const $"+min+"\n"+typ+"Const $-1\n"+typ+"DivS\nDrop\nI32Const $7", "trap")
		add(typ+"RemOverflow", typ+"Const $"+min+"\n"+typ+"Const $-1\n"+typ+"RemS"+result, "0")
		for _, op := range []string{"Shl", "ShrS", "ShrU"} {
			add(typ+op+"Wrap", fmt.Sprintf("%sConst $5\n%sConst $%d\n%s%s%s", typ, typ, width, typ, op, result), "5")
		}
	}
	add("Inf32", "F32Const $Inf\nI32ReinterpretF32", "2139095040")
	add("SignalingNaN32", "F32Const $0x7f800001\nI32ReinterpretF32", "2139095041")
	add("NegativeSNaN32", "F32Const $0xff800001\nI32ReinterpretF32", "-8388607")
	add("NegInf32", "F32Const $-Inf\nI32ReinterpretF32", "-8388608")
	add("Nan32", "F32Const $NaN\nI32ReinterpretF32", "2143289344")
	for _, bit := range []int{0, 1} {
		want := "22"
		if bit != 0 {
			want = "11"
		}
		add(fmt.Sprintf("SelectVector%d", bit), fmt.Sprintf("V128Const $11,$0\nSet V2\nGet V2\nV128Const $22,$0\nI32Const $%d\nSelect\nI32x4ExtractLane $0", bit), want)
	}
	add("DecimalFloat", "F32Const $1.5\nI32ReinterpretF32", "1069547520")
	add("VectorLocal", "V128Const $42,$0\nSet V0\nGet V0\nI32x4ExtractLane $0", "42")
	add("ExplicitTrap", "Unreachable", "trap")
	add("DroppedLoad", "I32Const $-1\nI32Load8U $0\nDrop\nI32Const $7", "trap")
	add("OverflowingOffset", "I32Const $-1\nI32Load8U $1", "trap")
	add("DroppedRegisterMemarg", "MOVD $-1, R0\nI32Load8U 0(R0)\nDrop\nI32Const $7", "trap")
	add("RegisterOffsetWrap", "MOVD $-1, R0\nI32Load8U 1(R0)", "trap")
	add("MoveStoreOffsetWrap", "MOVD $-1, R0\nMOVB $31, 1(R0)\nI32Const $7", "trap")
	add("ValidNull", "I32Const $0\nI32Load8U $0", "0")
	add("TableResult", "Block $1\nI32Const $42\nI32Const $0\nBrTable $0,$0\nEnd", "42")
	add("TableRoot", "I32Const $42\nI32Const $0\nBrTable $0", "42")
	add("NestedDead", "Block $1\nI32Const $42\nBr $0\nBlock\nEnd\nEnd", "42")
	add("BulkFillOOBZero", "I32Const $-1\nI32Const $0\nI32Const $0\nMemoryFill\nI32Const $7", "trap")
	add("BulkCopySameOOB", "I32Const $-1\nI32Const $-1\nI32Const $1\nMemoryCopy\nI32Const $7", "trap")
	end := "CurrentMemory\nI32Const $16\nI32Shl"
	add("FillAtEndEmpty", end+"\nI32Const $123\nI32Const $0\nMemoryFill\nI32Const $7", "7")
	add("CopyAtEndEmpty", end+"\n"+end+"\nI32Const $0\nMemoryCopy\nI32Const $7", "7")
	add("SourceBeyondEndEmpty", end+"\n"+end+"\nI32Const $1\nI32Add\nI32Const $0\nMemoryCopy\nI32Const $7", "trap")
	last := end + "\nI32Const $1\nI32Sub"
	add("CopyFromLastByte", last+"\nI32Const $23\nI32Store8 $0\nI32Const $10\n"+last+"\nI32Const $1\nMemoryCopy\nI32Const $9\nI32Load8U $1", "23")
	add("DroppedWideLoadAtEnd", last+"\nI64Load $0\nDrop\nI32Const $7", "trap")
	add("BulkNegativeLength", "I32Const $0\nI32Const $0\nI32Const $-1\nMemoryCopy\nI32Const $7", "trap")
	for _, prefix := range []string{"F32x4", "F64x2"} {
		nan := "0x7fc00011"
		if prefix == "F64x2" {
			nan = "0x7ff8000000000011"
		}
		for _, op := range []string{"PMin", "PMax"} {
			add(prefix+op+"NaN", "V128Const $0,$0\nV128Const $"+nan+",$0\n"+prefix+op+"\nI32x4ExtractLane $0", "0")
		}
	}
	add("BranchFrameResult", "I32Const $1\nIf\nI32Const $42\nI32Store ret+0(FP)\nElse\nI32Const $13\nI32Store ret+0(FP)\nEnd\nRET", "42")
	var source, script strings.Builder
	sigs := map[string]FuncSig{}
	for _, c := range cases {
		sigs[c.name] = FuncSig{Name: c.name, Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
		src := fmt.Sprintf("TEXT %s(SB),NOSPLIT,$0-4\n%s\nI32Store ret+0(FP)\nRET\n", c.name, c.body)
		source.WriteString(src)
		fmt.Fprintf(&script, "check(%q,%q);\n", c.name, c.want)
	}
	source.WriteString(`TEXT vecResult<>(SB),NOSPLIT,$0
V128Const $0x000002ab0000002a,$9
RET
TEXT vecLanes(SB),NOSPLIT,$0-4
Call vecResult<>(SB)
I32x4ExtractLane $1
I32Store ret+0(FP)
RET
TEXT PtrLoad(SB),NOSPLIT,$0-8
I32Load addr+0(FP)
I32Load8U $1
I32Store ret+4(FP)
RET
TEXT WidenLoad(SB),NOSPLIT,$0-8
I32Load addr+0(FP)
V128Load32x2U $1
I32x4ExtractLane $0
I32Store ret+4(FP)
RET
TEXT NearEndStore(SB),NOSPLIT,$0-4
I32Load addr+0(FP)
V128Const $-1,$-1
V128Store $1
RET
`)
	sigs["vecResult<>"] = FuncSig{Name: "vecResult<>", Ret: "<4 x i32>"}
	sigs["vecLanes"] = FuncSig{Name: "vecLanes", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}
	script.WriteString("check('vecLanes','683');\n")
	param := FrameSlot{Type: Ptr, Field: -1}
	sigs["PtrLoad"] = FuncSig{Name: "PtrLoad", Args: []LLVMType{Ptr}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{param}, Results: []FrameSlot{{Offset: 4, Type: I32, Field: -1}}}}
	sigs["NearEndStore"] = FuncSig{Name: "NearEndStore", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{param}}}
	wideSig := sigs["PtrLoad"]
	wideSig.Name, wideSig.Attrs = "WidenLoad", "noinline"
	sigs["WidenLoad"] = wideSig
	file, e := Parse(ArchWASM, source.String())
	if e != nil {
		t.Fatal(e)
	}
	ll, e := Translate(file, Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", Sigs: sigs})
	if e != nil {
		t.Fatal(e)
	}
	group := ""
	for _, line := range strings.Split(ll, "\n") {
		if strings.HasPrefix(line, "define ") && strings.Contains(line, "@WidenLoad(") {
			_, rest, _ := strings.Cut(line, ") ")
			group, _, _ = strings.Cut(rest, " ")
			break
		}
	}
	_, attrGroup, found := strings.Cut(ll, "attributes "+group+" = {")
	attrGroup, _, _ = strings.Cut(attrGroup, "}")
	if !found || !strings.Contains(attrGroup, "noinline") || !strings.Contains(attrGroup, `"target-features"="+simd128"`) {
		t.Fatal("explicit Wasm attributes lost the inferred SIMD feature")
	}
	js := `const f = new WebAssembly.Instance(new WebAssembly.Module(require("fs").readFileSync(process.argv[1]))).exports;
function check(name,want) {
 let got;
 try { got=String(f[name]()); } catch (e) { if (!(e instanceof WebAssembly.RuntimeError)) throw e; got="trap"; }
 if (got!==want) { console.error(name+": got "+got+", want "+want); process.exitCode=1; }
}
` + script.String() + `
const mem = new Uint8Array(f.memory.buffer);
mem[111] = 0x42;
if (f.PtrLoad(110) !== 0x42) throw new Error("nonzero pointer + 1");
function mustTrap(name, arg) {
 try { f[name](arg); } catch (e) { if (e instanceof WebAssembly.RuntimeError) return; throw e; }
 throw new Error(name + " did not trap");
}
mustTrap("PtrLoad", -1);
mustTrap("WidenLoad", -5);
mustTrap("WidenLoad",mem.length-8);
new DataView(mem.buffer).setUint32(257,42,true);
if (f.WidenLoad(256)!==42) throw Error("valid widening load");
mem.fill(0x42, 0, 8);
mustTrap("NearEndStore", -9);
if (!mem.subarray(0,8).every(v => v === 0x42)) throw new Error("wrapped V128Store");
mem.fill(0x42, mem.length-8);
mustTrap("NearEndStore", mem.length-8);
if (!mem.subarray(mem.length-8).every(v => v === 0x42)) throw new Error("partial V128Store on trap");
`
	runWasmWithNode(t, ll, js)
}

func runWasmWithNode(t *testing.T, ll, js string) {
	t.Helper()
	dir := t.TempDir()
	obj := filepath.Join(dir, "semantics.o")
	wasm := filepath.Join(dir, "semantics.wasm")
	llc, ld, node := wasmExecutionTools(t)
	cmd := exec.Command(llc, "-filetype=obj", "-o", obj, "-")
	cmd.Stdin = strings.NewReader(runOptO2(t, ll))
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("llc: %v %s", e, out)
	}
	if out, e := exec.Command(ld, "--no-entry", "--export-all", "-o", wasm, obj).CombinedOutput(); e != nil {
		t.Fatalf("wasm-ld: %v %s", e, out)
	}
	if out, e := exec.Command(node, "-e", js, wasm).CombinedOutput(); e != nil {
		t.Errorf("Wasm VM: %v\n%s", e, out)
	}
}

func TestWasmDataOnlyObject(t *testing.T) {
	f, err := Parse(ArchWASM, "DATA table(SB)/4,$42\nGLOBL table(SB),RODATA,$4")
	if err != nil {
		t.Fatal(err)
	}
	for _, annotate := range []bool{false, true} {
		const triple = "wasm32-unknown-unknown"
		ir, err := Translate(f, Options{Goarch: "wasm", TargetTriple: triple, WASMABI: WASMABIGo, AnnotateSource: annotate})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ir, "addrspace(1)") {
			t.Fatal("data-only object acquired Go stack register imports")
		}
		verifyLLVMWithTargetLLC(t, ir, triple)
	}
}

func TestWasmExpandedLocalPointerMap(t *testing.T) {
	const triple = "wasm32-unknown-unknown"
	for _, tc := range []struct {
		sym   string
		valid bool
	}{{"no_pointers_stackmap", true}, {"custom_stackmap", false}} {
		f, err := Parse(ArchWASM, "TEXT run(SB),4,$0\nFUNCDATA $1, "+tc.sym+"(SB)\nRET")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(f, Options{Goarch: "wasm", WASMABI: WASMABIGo, TargetTriple: triple, Sigs: map[string]FuncSig{"run": {Ret: Void}}})
		if !tc.valid {
			if err == nil {
				t.Error("accepted unknown stack map")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		verifyLLVMWithTargetLLC(t, ir, triple)
	}
}

func wasmExecutionTools(t *testing.T) (string, string, string) {
	t.Helper()
	requireExec := os.Getenv("PLAN9ASM_REQUIRE_WASM_EXEC") == "1" || os.Getenv("PLAN9ASM_REQUIRE_AMD64_DIFF") == "1"
	wasmLD := findLLVM22Tool("wasm-ld")
	nodeBin, _ := exec.LookPath("node")
	llc := findLLVM22Tool("llc")
	if wasmLD == "" || nodeBin == "" || llc == "" {
		msg := fmt.Sprintf("Wasm execution prerequisites missing (wasm-ld-22=%q node=%q llc-22=%q)", wasmLD, nodeBin, llc)
		if requireExec {
			t.Fatal("PLAN9ASM_REQUIRE_WASM_EXEC=1: " + msg)
		}
		t.Skip(msg)
	}
	return llc, wasmLD, nodeBin
}

func TestWasmGoABIResumeAndFrameExecution(t *testing.T) {
	const src = `TEXT caller(SB),4,$40
	Get SP
	Get SP
	I64ExtendI32U
	I64Const $argframe+0(FP)
	I64Add
	I64Store result+0(FP)
	CALL helper(SB)
	RET helper(SB)
	CALL helper(SB)

TEXT helper(SB),4,$0
	RET
TEXT indirect(SB),4,$0
	MOVD $helper(SB), R0
	Get R0
	CALL
	RET
TEXT panicCaller(SB),4,$0
	I32Const $1
	If
	CALLNORESUME runtime·sigpanic(SB)
	End
	RET
TEXT resumePanic(SB),4,$16
	CALL runtime·sigpanic(SB)
	RET
TEXT twoCalls(SB),4,$16
	CALL helper(SB)
	CALL runtime·sigpanic(SB)
	RET
TEXT runtime·sigpanic(SB),4,$0
	RETUNWIND
TEXT cannotResume(SB),4,$0
	CALLNORESUME unwind(SB)
	RET
TEXT unwind(SB),4,$0
	RETUNWIND`
	file, err := Parse(ArchWASM, src)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{}
	for _, fn := range file.Funcs {
		sigs[fn.Sym] = FuncSig{Name: fn.Sym, Ret: Void}
	}
	sigs["caller"] = FuncSig{Name: "caller", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Type: I64, Field: -1}}}}
	ir, err := Translate(file, Options{Goarch: "wasm", TargetTriple: "wasm32-unknown-unknown", WASMABI: WASMABIGo, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	// Supply the stack global normally provided by the Go linker.
	ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 0", 1)
	ir += "\ndefine void @initSP() { store i32 16384, ptr addrspace(1) @SP\n ret void }\ndefine i32 @readSP() { %sp = load i32, ptr addrspace(1) @SP\n ret i32 %sp }\n"
	runWasmWithNode(t, ir, `
const f = new WebAssembly.Instance(new WebAssembly.Module(require("fs").readFileSync(process.argv[1]))).exports;
f.initSP();
if (f.caller(0)!==0 || f.readSP()!==16392 || new DataView(f.memory.buffer).getBigUint64(16392,true)!==16392n) throw Error("caller frame");
f.initSP();
if (f.indirect(0)!==0 || f.readSP()!==16392) throw Error("indirect PC");
f.initSP();
for (const [name,pc] of [["resumePanic",1],["twoCalls",2]]) {
  if (f[name](0)!==1 || f.readSP()!==16368) throw Error(name+" fresh call or frame");
  if ((new DataView(f.memory.buffer).getUint32(16360,true)&0xffff)!==pc-1) throw Error(name+" panic PC");
  if (f[name](pc)!==0 || f.readSP()!==16392) throw Error(name+" resume");
  f.initSP();
}
if (f.panicCaller(0)!==1) throw Error("sigpanic unwind");
f.initSP();
try { f.cannotResume(0); throw Error("unexpected return"); } catch (e) { if (!(e instanceof WebAssembly.RuntimeError)) throw e; }
`)
}

func TestWasmInvalidControlAndConstants(t *testing.T) {
	simd, err := Parse(ArchWASM, "TEXT vec(SB),4,$0\nV128Const $0,$0\nDrop\nRET")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "wasm", Sigs: map[string]FuncSig{"vec": {Name: "vec", Ret: Void, Attrs: `noinline "target-features"="+mutable-globals"`}}}
	ir, err := Translate(simd, opt)
	if err != nil || !strings.Contains(ir, `"target-features"="+mutable-globals,+simd128"`) {
		t.Fatalf("Wasm function attribute composition failed: %v\n%s", err, ir)
	}
	sig := opt.Sigs["vec"]
	sig.Attrs = `"target-features"="-simd128"`
	opt.Sigs["vec"] = sig
	if _, err = Translate(simd, opt); err == nil || !strings.Contains(err.Error(), "-simd128") {
		t.Fatalf("conflicting Wasm SIMD attributes: %v", err)
	}

	nested, err := Parse(ArchWASM, "TEXT bad(SB),4,$0\nBlock\nCALL bad(SB)\nEnd\nRET")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(nested, Options{Goarch: "wasm", WASMABI: WASMABIGo, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}})
	if err == nil || !strings.Contains(err.Error(), "top-level") {
		t.Fatalf("resumable call inside block: %v", err)
	}

	var invalid []string
	for _, op := range []string{"I8x16Div", "I8x16Lt", "F32x4AddSatS", "I8x16Sqrt", "I64x2LeU", "F64x2And", "I16x8ConvertI32x4S"} {
		invalid = append(invalid, "V128Const $0,$0\nV128Const $0,$0\n"+op+"\nDrop")
	}
	invalid = append(invalid, "F32Const $0x100000000\nDrop", "F32Const $-2147483649\nDrop")
	for _, body := range append(invalid, "Unreachable\nBlock", "I64Const $UNDEF_CONST\nDrop", "V128", "V128Const $UNDEF_CONST,$0", "V128Const $1,$0\nV128Const $2,$0\nV128XADD", "I32Const $0\nV128Load $UNDEF_CONST") {
		t.Run(body, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT bad(SB),4,$0\n"+body+"\nRET")
			if err == nil {
				_, err = Translate(file, Options{Goarch: "wasm", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}})
			}
			if err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
