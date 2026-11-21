package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type wasmV128ArithmeticCase struct {
	Name     string
	Opcode   string
	Code     int
	Bits     int
	Operands int
}

func wasmV128RelaxedFloatCases() []wasmV128ArithmeticCase {
	return []wasmV128ArithmeticCase{
		{Name: "madd32", Opcode: "F32x4RelaxedMadd", Code: 0x105, Bits: 32, Operands: 3},
		{Name: "nmadd32", Opcode: "F32x4RelaxedNmadd", Code: 0x106, Bits: 32, Operands: 3},
		{Name: "madd64", Opcode: "F64x2RelaxedMadd", Code: 0x107, Bits: 64, Operands: 3},
		{Name: "nmadd64", Opcode: "F64x2RelaxedNmadd", Code: 0x108, Bits: 64, Operands: 3},
		{Name: "min32", Opcode: "F32x4RelaxedMin", Code: 0x10d, Bits: 32, Operands: 2},
		{Name: "max32", Opcode: "F32x4RelaxedMax", Code: 0x10e, Bits: 32, Operands: 2},
		{Name: "min64", Opcode: "F64x2RelaxedMin", Code: 0x10f, Bits: 64, Operands: 2},
		{Name: "max64", Opcode: "F64x2RelaxedMax", Code: 0x110, Bits: 64, Operands: 2},
	}
}

func wasmV128ArithmeticSource(rows []wasmV128ArithmeticCase) string {
	var source strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nI32Const $128\n", row.Name)
		for i := 1; i <= row.Operands; i++ {
			fmt.Fprintf(&source, "I32Const $%d\nV128Load $0\n", i*32)
		}
		fmt.Fprintf(&source, "%s\nV128Store\nReturn\n", row.Opcode)
	}
	return source.String()
}

func TestWASMV128RelaxedFloatDifferential(t *testing.T) {
	rows := wasmV128RelaxedFloatCases()
	checkWASMV128MemoryRuntime(t, wasmV128ArithmeticSource(rows), rows, wasmV128RelaxedFloatOracle)
}

func TestWASMV128RelaxedFloatRejectsMalformedSource(t *testing.T) {
	checkWASMV128ArithmeticRejectsMalformedSource(t, wasmV128RelaxedFloatCases())
}

func checkWASMV128ArithmeticRejectsMalformedSource(t *testing.T, rows []wasmV128ArithmeticCase) {
	t.Helper()
	for _, row := range rows {
		for _, body := range []string{
			"RET\n" + row.Opcode + " $1",
			"RET\n" + row.Opcode + ".invalid",
			strings.Repeat("V128Const $0,$0\n", row.Operands-1) + row.Opcode,
			strings.Repeat("V128Const $0,$0\n", row.Operands-1) + "I32Const $0\n" + row.Opcode,
		} {
			file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+body+"\nRET\n")
			if err != nil {
				continue
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
				t.Errorf("inference accepted %q", body)
			}
			sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
			if out, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil || out != "" {
				t.Errorf("translation accepted %q", body)
			}
		}
	}
}

const wasmV128RelaxedFloatOracle = wasmV128MemoryKernelJS + `
const native = nativeMemory(row => row.Operands);
const views = [native, translated].map(mod => new DataView(mod.memory.buffer));
for (const {Name, Bits, Operands} of rows) {
  const narrow = Bits === 32;
  const width = Bits / 8;
  const round = narrow ? Math.fround : x => x;
  const ulp = 2 ** (1 - (narrow ? 24 : 53));
  const negate = Name.startsWith('nmadd');
  const samples = [
    [3,-4,5], [-7,4,3], [1+ulp,1-ulp,negate ? 1 : -1],
    [-0,1,-0], [0,-0,0], [-0,0,-0], [0,-0,-0],
    [NaN,2,1], [3,NaN,1], [NaN,NaN,1], [2,3,NaN],
    [Infinity,0,2], [Infinity,-Infinity,5], [-Infinity,Infinity,-3],
    [4,4,4], [2 ** (narrow ? -140 : -1060),2,0],
  ];
  for (let seed = 0; seed < samples.length; seed++) {
    const lanes = Array.from({length:16/width}, (_, i) => (seed+3*i) % samples.length);
    for (const view of views) {
      view.setUint8(127, 0x5a);
      view.setUint8(144, 0xa5);
      for (const [lane, sample] of lanes.entries()) {
        for (const [arg, value] of samples[sample].entries()) {
          const at = (arg+1)*32 + lane*width;
          if (Number.isNaN(value)) {
            // Signaling payloads must become an arithmetic NaN even at -O2.
            if (narrow) view.setUint32(at, 0xff800007, true);
            else view.setBigUint64(at, 0xfff0000000000007n, true);
          } else if (narrow) view.setFloat32(at, value, true);
          else view.setFloat64(at, value, true);
        }
      }
    }
    native[Name]();
    translated[Name]();
    for (const [lane, sample] of lanes.entries()) {
      const [a,b,c] = samples[sample];
      const at = 128+lane*width;
      const read = view => narrow ? view.getFloat32(at, true) : view.getFloat64(at, true);
      let want, observed = read(views[0]);
      if (Operands === 3) {
        want = round(round((negate ? -a : a)*b)+c);
        const fused = sample === 2 ? (negate ? 1 : -1)*ulp*ulp : want;
        if (!Object.is(observed, want) && !Object.is(observed, fused)) {
          throw Error(Name + ': native multiply-add has an unexpected result for sample ' + sample);
        }
      } else {
        want = (Name.startsWith('min') ? Math.min : Math.max)(a,b);
        const allowed = Number.isNaN(want) ? [a,b,NaN] : a === 0 && b === 0 ? [0,-0] : [want];
        if (!allowed.some(value => Object.is(value, observed))) {
          throw Error(Name + ': native min/max has an unexpected result for sample ' + sample);
        }
      }
      if (!Object.is(read(views[1]), want)) {
        throw Error(Name + ': wrong deterministic result for sample ' + sample + ', lane ' + lane);
      }
      if (Number.isNaN(want)) {
        const actual = narrow ? BigInt(views[1].getUint32(at, true)) : views[1].getBigUint64(at, true);
        if (actual !== (narrow ? 0x7fc00000n : 0x7ff8000000000000n)) {
          throw Error(Name + ': result did not quiet the input NaN');
        }
      }
    }
    if (views.some(view => view.getUint8(127) !== 0x5a || view.getUint8(144) !== 0xa5)) {
      throw Error(Name + ': write escaped the vector width');
    }
  }
}
`
