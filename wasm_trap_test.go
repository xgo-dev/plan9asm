package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestWASMSourceTrapsMatchGoAfterOptimization(t *testing.T) {
	var source strings.Builder
	rows := 0
	for _, op := range []string{"Unreachable", "UNDEF"} {
		for _, operands := range []string{"", " $0", " R0,$0"} {
			fmt.Fprintf(&source, "TEXT trap%d(SB),4,$0-0\nGet PC_B\nIf\n%s%s\nEnd\nI32Const $73\nReturn\n", rows, op, operands)
			rows++
		}
	}
	checkWASMTrapsAgainstGo(t, source.String(), WASMABIDirect, WASMABIGo)
}

func TestWASMGoFallthroughTrapMatchesGoAfterOptimization(t *testing.T) {
	const source = `TEXT trap0(SB),4,$0-0
Get PC_B
I32Eqz
If
 I32Const $73
 Return
End

TEXT trap1(SB),4,$0-0
Get PC_B
I32Eqz
If
 I32Const $73
 Return
End
RESUMEPOINT
`
	checkWASMTrapsAgainstGo(t, source, WASMABIGo)
}

func TestWASMDeadStructuredControlMatchesGo(t *testing.T) {
	const source = `TEXT trap0(SB),4,$0-0
Get PC_B
If
 Unreachable
 Block
  I32Const $1
  If
   Loop
   End
  Else
  End
 End
Else
 I32Const $73
 Return
End
Unreachable

TEXT trap1(SB),4,$0-0
Get PC_B
I32Eqz
If
 I32Const $73
 Return
 Loop $2
  I64Const $5
 End
 Drop
End
UNDEF

TEXT trap2(SB),4,$0-0
Get PC_B
If
 UNDEF
Else
 Block $1
  I32Const $73
  Br $0
  Block
   Loop
   End
  End
 End
 Return
End
Unreachable
`
	checkWASMTrapsAgainstGo(t, source, WASMABIDirect, WASMABIGo)
}

func checkWASMTrapsAgainstGo(t *testing.T, source string, abis ...WASMABI) {
	t.Helper()
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
		if len(sig.Args) != 1 || sig.Args[0] != I32 || sig.Ret != I32 {
			t.Fatalf("%s: inferred signature %+v, want (i32) -> i32", fn.Sym, sig)
		}
		sigs[fn.Sym] = sig
	}
	for _, goos := range wasmPackedGoPlatforms {
		t.Run(goos, func(t *testing.T) {
			listing := wasmStockFunctionListing(t, t.TempDir(), goos, source)
			for _, abi := range abis {
				opts := wasmPackedOptions(sigs, abi)
				if goos == "wasip1" {
					opts.TargetTriple = "wasm32-unknown-wasi"
				}
				for _, route := range wasmConditionTestRoutes {
					t.Run(fmt.Sprintf("abi%d/%s", abi, route), func(t *testing.T) {
						ir, err := wasmPackedTranslate(t, file, opts, route)
						if err != nil {
							t.Fatal(err)
						}
						ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 0", 1)
						for _, level := range []string{"0", "2"} {
							t.Run("O"+level, func(t *testing.T) {
								runLLVMWASMObject(t, ir, level, wasmSourceTrapOracle, listing, fmt.Sprint(len(file.Funcs)))
							})
						}
					})
				}
			}
		})
	}
}

const wasmSourceTrapOracle = `
const fs = require('node:fs');
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(Uint8Array.from(bytes))).exports;
` + wasmTestSectionJS + `
const names = Array.from({length: Number(process.argv[3])}, (_, i) => 'trap' + i);
const bodies = new Map();
let body;
for (const line of fs.readFileSync(process.argv[2], 'utf8').split('\n')) {
  if (/^\S/.test(line)) {
    const name = /^(trap\d+) STEXT /.exec(line)?.[1];
    body = name ? [] : undefined;
    if (body) bodies.set(name, body);
  }
  const bytes = /^\s*0x[\da-f]+((?: [\da-f]{2}){1,16})(?:\s|$)/i.exec(line)?.[1];
  if (body && bytes) body.push(...Buffer.from(bytes.replaceAll(' ', ''), 'hex'));
}
const original = instantiate([
  0, 97, 115, 109, 1, 0, 0, 0,
  ...section(1, [1, 0x60, 1, 0x7f, 1, 0x7f]),
  ...section(3, vector(names.map(() => 0))),
  ...section(6, [1, 0x7f, 1, 0x41, 0, 0x0b]), // Go SP
  ...section(7, vector(names.map((name, i) => [...vector([...Buffer.from(name)]), 0, i]))),
  ...section(10, vector(names.map(name => vector(bodies.get(name))))),
]);
const translated = instantiate(fs.readFileSync(process.argv[1]));
function outcome(fn, input) {
  try { return fn(input); }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return 'trap';
  }
}
for (const name of names) {
  for (const input of [0, 1, -1, -2147483648]) {
    const want = outcome(original[name], input);
    if (want !== (input === 0 ? 73 : 'trap')) throw Error(name + ': invalid original Go oracle');
    const got = outcome(translated[name], input);
    if (got !== want) throw Error(name + '/' + input + ': translated ' + got + ', original Go ' + want);
  }
}
`

func TestWASMSourceTrapValidatesDeadOperands(t *testing.T) {
	for _, instruction := range []string{"UNDEF R0,R1,R2", "Unreachable R0,R1,R2", "Unreachable.INVALID"} {
		t.Run(instruction, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT trap(SB),4,$0-0\nRET\n"+instruction+"\n")
			if err != nil {
				if strings.Contains(instruction, ".") && strings.Contains(err.Error(), "instruction suffix") {
					return
				}
				t.Fatal(err)
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "trap"); err == nil {
				t.Error("signature inference accepted malformed trap operands")
			}
			sigs := map[string]FuncSig{"trap": {Name: "trap", Ret: Void}}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Error("translation accepted malformed trap operands")
			}
		})
	}
}

func TestWASMDeadStructuredControlValidatesDelimiters(t *testing.T) {
	for _, body := range []string{"Block\nElse\nEnd", "If\nElse\nElse\nEnd", "If $1\nEnd", "Loop"} {
		t.Run(body, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT trap(SB),4,$0-0\nUnreachable\n"+body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "trap"); err == nil {
				t.Error("inference accepted malformed dead structured control")
			}
			sigs := map[string]FuncSig{"trap": {Name: "trap", Ret: Void}}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Error("translation accepted malformed dead structured control")
			}
		})
	}
}
