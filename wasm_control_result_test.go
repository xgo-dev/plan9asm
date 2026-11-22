package plan9asm

import "testing"

const wasmRepeatedControlResultSource = `TEXT count(SB),4,$0-16
 I64Load loops+0(FP)
 Set R0
 Loop
  Block $2
   Get R0
  End
  Set R1
  Get R0
  I64Const $1
  I64Sub
  Tee R0
  I64Const $0
  I64Ne
  BrIf $0
 End
 MOVD R1,ret+8(FP)
 RET
`

func TestWASMControlResultStorageInsideLoop(t *testing.T) {
	file, err := Parse(ArchWASM, wasmRepeatedControlResultSource)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{"count": {
		Name: "count", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Name: "loops", Type: I64, Field: -1}},
			Results: []FrameSlot{{Name: "ret", Offset: 8, Type: I64, Field: -1}},
		},
	}}
	const oracle = `
const bytes = require('node:fs').readFileSync(process.argv[1]);
const wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
for (const count of [1n, 250000n]) {
  if (wasm.count(count) !== 1n) throw Error('wrong final block result for ' + count);
}
`
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil {
				t.Fatal(err)
			}
			runLLVMWASMObject(t, ir, "0", oracle)
			runLLVMWASMObject(t, ir, "2", oracle)
		})
	}
}

func TestWASMControlResultExplicitEmptyAndVectorTypes(t *testing.T) {
	const source = `TEXT empty(SB),4,$0-0
 Block $0
  Loop $0
   I32Const $1
   If $0
   End
  End
 End
 I32Const $19
 Return

TEXT vector(SB),4,$0-0
 I32Const $1
 If $5
  Loop $5
   Block $5
    V128Const $73,$0
   End
  End
 Else
  V128Const $11,$0
 End
 I32x4ExtractLane $0,$0
 Return
`
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		sig, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil {
			t.Fatal(err)
		}
		if sig.Ret != I32 {
			t.Fatalf("%s inferred %s, want i32", fn.Sym, sig.Ret)
		}
		sigs[fn.Sym] = sig
	}
	const oracle = `
const bytes = require('node:fs').readFileSync(process.argv[1]);
const wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
if (wasm.empty() !== 19 || wasm.vector() !== 73) throw Error('wrong structured result');
`
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			t.Run(route+"/"+triple, func(t *testing.T) {
				options := wasmPackedOptions(sigs, WASMABIDirect)
				options.TargetTriple = triple
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil {
					t.Fatal(err)
				}
				runLLVMWASMObject(t, ir, "0", oracle)
				runLLVMWASMObject(t, ir, "2", oracle)
			})
		}
	}
}
