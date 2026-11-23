package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWASMGoCallReturnPCMatchesGo(t *testing.T) {
	rows := []struct {
		name, body string
		frame, pc  int
	}{
		{"plain", "CALL ·capture(SB)\n", 0, 1},
		{"framed", "CALL ·capture(SB)\n", 16, 2},
		{"marked", "Nop\nNop\nCALL ·capture(SB)\n", 16, 4},
		{"noResume", "Nop\nCALLNORESUME ·capture(SB)\n", 16, 3},
		{"explicit", "Nop\nCALLNORESUME ·capture(SB)\nRESUMEPOINT\n", 16, 4},
		{"mixed", "Nop\nCALLNORESUME ·capture(SB)\nNop\nCALL ·capture(SB)\n", 0, 4},
	}
	var source, declarations, checks, wrappers, comparisons strings.Builder
	source.WriteString(`TEXT ·capture(SB),4,$0-0
Get SP
I64Load $0
I64Const $65535
I64And
Set R0
MOVD $·captured(SB), R1
MOVD R0, 0(R1)
RET
GLOBL ·captured(SB),16,$8
TEXT ·readCapture(SB),4,$0-8
MOVD $·captured(SB), R1
MOVD 0(R1), R0
MOVD R0, ret+0(FP)
RET
`)
	declarations.WriteString("func capture()\nfunc readCapture() uint64\n")
	sigs := map[string]FuncSig{
		"capture": {Name: "capture", Ret: Void},
		"readCapture": {Name: "readCapture", Ret: I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}}},
	}
	for _, row := range rows {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$%d-0\n%sRET\n", row.name, row.frame, row.body)
		fmt.Fprintf(&declarations, "func %s()\n", row.name)
		fmt.Fprintf(&checks, "%s(); if got := readCapture(); got != %d { panic(fmt.Sprintf(\"%s %%d\", got)) }\n", row.name, row.pc, row.name)
		fmt.Fprintf(&wrappers, `
define i64 @probe_%s() {
  store i32 4096, ptr addrspace(1) @SP
  %%unwind = call i32 @%s(i32 0)
  store i32 4096, ptr addrspace(1) @SP
  %%done = call i32 @readCapture(i32 0)
  %%pc = load i64, ptr inttoptr(i32 4104 to ptr), align 1
  ret i64 %%pc
}
`, row.name, row.name)
		fmt.Fprintf(&comparisons, "if (m.probe_%s() !== %dn) throw Error('%s PC_B=' + m.probe_%s());\n", row.name, row.pc, row.name, row.name)
		sigs[row.name] = FuncSig{Name: row.name, Ret: Void}
	}
	goSource := "package main\nimport \"fmt\"\n" + declarations.String() +
		"func main(){\n" + checks.String() + "fmt.Println(\"packed call PCs verified\")\n}\n"
	nodeScript := `
const bytes = require('node:fs').readFileSync(process.argv[1]);
const m = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
` + comparisons.String()
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			verifyWASMOriginalCallPCs(t, source.String(), goSource, goos)
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				t.Run(api, func(t *testing.T) {
					options := wasmPackedOptions(sigs, WASMABIGo)
					if goos == "wasip1" {
						options.TargetTriple = "wasm32-unknown-wasi"
					}
					ir, err := wasmPackedTranslate(t, file, options, api)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "blockaddress") {
						t.Fatal("Go wasm CALL emitted blockaddress")
					}
					ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 0", 1)
					for _, level := range []string{"0", "2"} {
						t.Run("O"+level, func(t *testing.T) {
							runLLVMWASMObject(t, ir+wrappers.String(), level, nodeScript)
						})
					}
				})
			}
		})
	}
}

func verifyWASMOriginalCallPCs(t *testing.T, source, goSource, goos string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module callpc\n\ngo 1.20\n", "main.go": goSource, "calls_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	binary := filepath.Join(dir, "original.wasm")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH=wasm")
	if out, err := runtimeOracleCombinedOutput(ctx, build); err != nil {
		t.Fatalf("build original Go calls: %v\n%s", err, out)
	}
	node := wasmPackedNode(t)
	if goos == "wasip1" {
		const run = `
const { WASI } = require("node:wasi");
const wasi = new WASI({version:"preview1", args:[], env:{}});
const mod = new WebAssembly.Module(require("node:fs").readFileSync(process.argv[1]));
wasi.start(new WebAssembly.Instance(mod, wasi.getImportObject()));
`
		if out := wasmDataCommand(t, node, "--no-warnings", "-e", run, binary); strings.TrimSpace(out) != "packed call PCs verified" {
			t.Fatalf("original Go WASI oracle: %s", out)
		}
		return
	}
	command, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), node, binary)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runtimeOracleCombinedOutput(ctx, command); err != nil || strings.TrimSpace(string(out)) != "packed call PCs verified" {
		t.Fatalf("original Go JS oracle: %v\n%s", err, out)
	}
}

func TestWASMGoSigpanicCallPCAndUnwind(t *testing.T) {
	const source = `TEXT ·panicCaller(SB),4,$16-0
Nop
CALLNORESUME runtime·sigpanic<ABIInternal>(SB)
RET
`
	dir := t.TempDir()
	input, object := filepath.Join(dir, "panic.s"), filepath.Join(dir, "panic.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := append(arm64ClosureGoAsmArgs(t), "-S", "-o", object, input)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Env = append(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOOS=js", "GOARCH=wasm")
	out, err := runtimeOracleCombinedOutput(ctx, cmd)
	listing := strings.ReplaceAll(string(out), `"".panicCaller`, "runtime.panicCaller")
	if err != nil || !strings.Contains(listing, "runtime.panicCaller+3") ||
		!strings.Contains(string(out), "\tBrIf\t$0") {
		t.Fatalf("stock Go sigpanic relocation or unwind edge differs: %v\n%s", err, out)
	}

	// Exercise the actual caller with a stub that returns the runtime's
	// unwind result. An ordinary CALLNORESUME to that stub must still trap.
	file, err := Parse(ArchWASM, source+`TEXT ·panicStub(SB),4,$0-0
I32Const $256
I32Load $0
Return
TEXT ·ordinaryCaller(SB),4,$0-0
CALLNORESUME ·panicStub(SB)
RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"panicCaller":    {Name: "panicCaller", Ret: Void},
		"panicStub":      {Name: "panicStub", Ret: Void},
		"ordinaryCaller": {Name: "ordinaryCaller", Ret: Void},
	}
	options := wasmPackedOptions(sigs, WASMABIGo)
	options.ResolveSym = func(name string) string {
		if name == "runtime·sigpanic<ABIInternal>" {
			return "panicStub"
		}
		return wasmPackedResolve(name)
	}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 0", 1)
	ir += `
define i32 @probePanic() {
  store i32 4096, ptr addrspace(1) @SP
  %result = call i32 @panicCaller(i32 0)
  ret i32 %result
}
define i32 @probeOrdinary() {
  store i32 4096, ptr addrspace(1) @SP
  %result = call i32 @ordinaryCaller(i32 0)
  ret i32 %result
}
`
	runLLVMWASMObject(t, ir, "2", `
const bytes = require('node:fs').readFileSync(process.argv[1]);
const m = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const memory = new DataView(m.memory.buffer);
memory.setUint32(256, 1, true);
if (m.probePanic() !== 1) throw Error('sigpanic did not propagate unwind');
const pc = memory.getBigUint64(4096 - 16 - 8, true);
if ((pc & 65535n) !== 3n) throw Error('sigpanic saved PC_B=' + (pc & 65535n));
let trapped = false;
try { m.probeOrdinary(); } catch (e) {
  if (!(e instanceof WebAssembly.RuntimeError)) throw e;
  trapped = true;
}
if (!trapped) throw Error('ordinary CALLNORESUME accepted unwind');
memory.setUint32(256, 0, true);
if (m.probeOrdinary() !== 0) throw Error('ordinary CALLNORESUME lost normal return');
`)
}
