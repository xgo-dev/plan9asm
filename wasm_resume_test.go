package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Wrap the stock assembler's actual function bytes, including the local
// declarations and dispatcher, in a module with one Go SP global.
const wasmResumeOracle = `
const fs = require("fs");
function uleb(value) {
    const bytes = [];
    while (value >= 128) {
        bytes.push((value & 127) | 128);
        value >>>= 7;
    }
    return [...bytes, value];
}
const original = fs.readFileSync(process.argv[1], "utf8");
const body = [];
for (const row of original.split("\n")) {
    const match = /^\s*0x[\da-f]+ ((?:[\da-f]{2}(?: |$)){1,16})/i.exec(row);
    if (match) body.push(...Buffer.from(match[1].replace(/ /g, ""), "hex"));
}
if (!original.includes("BrTable") || !body.length) throw Error(original);
const moduleBytes = [
    0, 97, 115, 109, 1, 0, 0, 0, // magic/version
    1, 6, 1, 0x60, 1, 0x7f, 1, 0x7f, // type (i32) -> i32
    3, 2, 1, 0, // one function of type zero
    6, 6, 1, 0x7f, 1, 0x41, 0, 0x0b, // mutable i32 SP
    7, 15, 2, 6, ...Buffer.from("resume"), 0, 0, 2, 83, 80, 3, 0,
    10, ...uleb(1 + uleb(body.length).length + body.length),
    1, ...uleb(body.length), ...body,
];
const reference = new WebAssembly.Instance(new WebAssembly.Module(Uint8Array.from(moduleBytes))).exports;
const translated = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(process.argv[2]))).exports;
for (const pc of [0, 1, 2, 3, 4, 5, 65535, -1]) {
    reference.SP.value = 4096;
    const want = reference.resume(pc) + 2 * (reference.SP.value - 4096);
    const got = translated.probe(pc);
    if (got !== want) throw Error("PC_B=" + pc + ": translated " + got + ", stock Go " + want);
}
`

func TestWASMGoResumeDispatcherMatchesGo(t *testing.T) {
	const source = `TEXT ·resume(SB), 4, $0-0
	Nop
	I32Const $1
	If
		JMP advance
	End
	RETUNWIND
	RESUMEPOINT
	JMP advance
	RESUMEPOINT
advance:
	Nop
	Get PC_B
	I32Const $3
	I32Eq
	If
		RET
	End
	RETUNWIND
`
	checkWASMGoResumeDispatcher(t, source)
	t.Run("framed", func(t *testing.T) {
		framed := strings.Replace(source, "$0-0", "$16-0", 1)
		framed = strings.Replace(framed, "I32Const $3", "I32Const $4", 1)
		checkWASMGoResumeDispatcher(t, framed)
	})
}

func checkWASMGoResumeDispatcher(t *testing.T, source string) {
	t.Helper()
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	node := wasmPackedNode(t)
	sigs := map[string]FuncSig{"resume": {Name: "resume", Ret: Void}}
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			listing := wasmStockFunctionListing(t, dir, goos, source)
			options := wasmPackedOptions(sigs, WASMABIGo)
			if goos == "wasip1" {
				options.TargetTriple = "wasm32-unknown-wasi"
			}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				t.Run(route, func(t *testing.T) {
					ir, err := wasmPackedTranslate(t, file, options, route)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "blockaddress") {
						t.Fatal("wasm resume dispatch emitted blockaddress")
					}
					ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 0", 1)
					ir += `
define i32 @probe(i32 %pc) {
  store i32 4096, ptr addrspace(1) @SP
  %ret = call i32 @resume(i32 %pc)
  %sp = load i32, ptr addrspace(1) @SP
  %delta = sub i32 %sp, 4096
  %stack = shl i32 %delta, 1
  %result = add i32 %stack, %ret
  ret i32 %result
}
`
					checkWASMResumeRuntime(t, ir, node, listing)
				})
			}
		})
	}
}

func checkWASMResumeRuntime(t *testing.T, ir, node, listing string) {
	t.Helper()
	dir := t.TempDir()
	input, optimized := filepath.Join(dir, "source.ll"), filepath.Join(dir, "optimized.ll")
	object, binary := filepath.Join(dir, "resume.o"), filepath.Join(dir, "resume.wasm")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	wasmDataCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
	for _, config := range []struct{ level, ir string }{{"0", input}, {"2", optimized}} {
		wasmDataCommand(t, wasmDataTool(t, "llc"), "-O"+config.level, "-filetype=obj", config.ir, "-o", object)
		wasmDataCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export=probe", object, "-o", binary)
		wasmDataCommand(t, node, "-e", wasmResumeOracle, listing, binary)
	}
}

func wasmStockFunctionListing(t *testing.T, dir, goos, source string) string {
	t.Helper()
	input := filepath.Join(dir, "original.s")
	listing := filepath.Join(dir, "go-asm.txt")
	object := filepath.Join(dir, "go.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "test", "-S", "-o", object, input)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH=wasm")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go %s/wasm assembly: %v\n%s", goos, err, output)
	}
	if err := os.WriteFile(listing, output, 0600); err != nil {
		t.Fatal(err)
	}
	return listing
}

func TestWASMGoResumeDispatcherRejectsInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		name, source, diagnostic string
		direct                   bool
	}{
		{name: "nested", source: "Block\nRESUMEPOINT\nEnd\nRET\n", diagnostic: "RESUMEPOINT requires top-level"},
		{name: "operands", source: "RESUMEPOINT $1\nRET\n", diagnostic: "RESUMEPOINT takes no operands"},
		{name: "stack", source: "I32Const $1\nRESUMEPOINT\nDrop\nRET\n", diagnostic: "RESUMEPOINT requires an empty"},
		{name: "unknown label", source: "JMP missing\nRESUMEPOINT\nRET\n", diagnostic: "unknown wasm JMP label"},
		{name: "direct", source: "RESUMEPOINT\nRET\n", diagnostic: "requires the Go WebAssembly ABI", direct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT resume(SB), 4, $0-0\n"+tc.source)
			if err != nil {
				t.Fatal(err)
			}
			options := wasmPackedOptions(map[string]FuncSig{"resume": {Name: "resume", Ret: Void}}, WASMABIGo)
			if tc.direct {
				options.WASMABI = WASMABIDirect
			}
			if _, err = Translate(file, options); err == nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Fatalf("translation error = %v, want %s", err, tc.diagnostic)
			}
		})
	}
}
