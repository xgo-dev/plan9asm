package plan9asm

import (
	"strings"
	"testing"
)

const wasmV128MemorySource = `TEXT storeVec(SB),4,$0-0
	Get R0
	I32WrapI64
	V128Const $0x0807060504030201,$0x100f0e0d0c0b0a09
	V128Store $0,$3
	Return
TEXT storeZero(SB),4,$0-0
	Get R0
	I32WrapI64
	V128Const $0x0807060504030201,$0x100f0e0d0c0b0a09
	V128Store
	Return
TEXT copyVec(SB),4,$0-0
	Get R1
	I32WrapI64
	V128Load 3(R0)
	V128Store $0,5(R15)
	Return
TEXT discardVec(SB),4,$0-0
	Get R0
	I32WrapI64
	V128Load $3
	Drop
	Return
`

func TestWASMV128MemoryBoundsAndStackForms(t *testing.T) {
	file, err := Parse(ArchWASM, wasmV128MemorySource)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		sig, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil {
			t.Fatal(fn.Sym, err)
		}
		regs := []Reg{"R0"}
		if fn.Sym == "copyVec" {
			regs = append(regs, "R1")
		}
		if sig.Ret != Void || len(sig.Args) != len(regs) || len(sig.ArgRegs) != len(regs) {
			t.Fatalf("%s inferred wrong memory signature %+v", fn.Sym, sig)
		}
		for index, reg := range regs {
			if sig.Args[index] != I64 || sig.ArgRegs[index] != reg {
				t.Fatalf("%s inferred wrong address input %+v", fn.Sym, sig)
			}
		}
		sigs[fn.Sym] = sig
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			t.Run(route+"/"+triple, func(t *testing.T) {
				options := wasmPackedOptions(sigs, WASMABIDirect)
				options.TargetTriple = triple
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil || ir == "" || strings.Contains(ir, "blockaddress") {
					t.Fatal("vector memory translation rejected", err)
				}
				for _, level := range []string{"0", "2"} {
					t.Run("O"+level, func(t *testing.T) {
						runLLVMWASMObject(t, ir, level, wasmV128MemoryCheck)
					})
				}
			})
		}
	}
}

func TestWASMV128MemoryRejectsInvalidFormats(t *testing.T) {
	for _, source := range []string{
		"V128Load 0(F0)", "I64Const $0\nV128Load $0", "I32Const $0\nV128Load $-1",
		"I32Const $0\nV128Load $4294967296", "RET\nV128Load.invalid $0",
		"I32Const $0\nI32Const $1\nV128Store",
		"RET\nV128Store $3", "RET\nV128Store $1,$3", "RET\nV128Store $0,$-1",
		"RET\nV128Store $0,$4294967296", "RET\nV128Store $0,$1,$2",
	} {
		file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+source+"\nRET\n")
		if err != nil {
			continue
		}
		if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
			t.Errorf("inference accepted %q", source)
		}
		sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
		if out, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil || out != "" {
			t.Errorf("translation accepted %q", source)
		}
	}
}

const wasmV128MemoryCheck = `
const fs = require('fs');
const {storeVec,storeZero,copyVec,discardVec,memory} =
  new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(process.argv[1]))).exports;
const bytes = new Uint8Array(memory.buffer);
const expected = Array.from({length:16}, (_, index) => index + 1);
const pattern = expected.map(value => value + 80);
function check(offset, want) {
  for (let i = 0; i < want.length; i++) {
    if (bytes[offset+i] !== want[i]) throw Error('byte ' + (offset+i));
  }
}
function traps(f) {
  try { f(); }
  catch (error) {
    if (error instanceof WebAssembly.RuntimeError) return;
    throw error;
  }
  throw Error('expected memory trap');
}
storeZero(0n);
check(0, expected);
bytes.fill(0xa5, 192, 215);
storeVec(192n);
check(192, [0xa5,0xa5,0xa5,...expected,0xa5,0xa5,0xa5,0xa5]);
bytes.set(pattern, 131);
copyVec(0x100000080n, 256n);
check(261, pattern);
discardVec(128n);
const end = bytes.length;
storeVec(BigInt(end - 19));
check(end - 16, expected);
discardVec(BigInt(end - 19));
bytes.fill(0xa5, end-24);
traps(() => storeVec(BigInt(end - 18)));
traps(() => storeZero(BigInt(end - 12)));
traps(() => copyVec(128n, BigInt(end - 20)));
check(end-24, new Array(24).fill(0xa5));
traps(() => discardVec(BigInt(end - 18)));
traps(() => discardVec(0xffffffffn));
traps(() => storeVec(0xffffffffn));
check(0, expected);
`
