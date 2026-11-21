package plan9asm

import "testing"

func wasmV128IntegerArithmeticCases() []wasmV128ArithmeticCase {
	return []wasmV128ArithmeticCase{
		{Name: "avg8", Opcode: "I8x16AvgrU", Code: 0x7b, Bits: 8, Operands: 2},
		{Name: "avg16", Opcode: "I16x8AvgrU", Code: 0x9b, Bits: 16, Operands: 2},
		{Name: "q15", Opcode: "I16x8Q15MulrSatS", Code: 0x82, Bits: 16, Operands: 2},
		{Name: "q15Relaxed", Opcode: "I16x8RelaxedQ15MulrS", Code: 0x111, Bits: 16, Operands: 2},
		{Name: "dot16", Opcode: "I32x4DotI16x8S", Code: 0xba, Bits: 32, Operands: 2},
		{Name: "dot8", Opcode: "I16x8RelaxedDotI8x16I7x16S", Code: 0x112, Bits: 16, Operands: 2},
		{Name: "dotAdd8", Opcode: "I32x4RelaxedDotI8x16I7x16AddS", Code: 0x113, Bits: 32, Operands: 3},
	}
}

func TestWASMV128IntegerArithmeticDifferential(t *testing.T) {
	rows := wasmV128IntegerArithmeticCases()
	// Node 22's x64 Liftoff SSE path can lose one input when a relaxed
	// dot product reuses its register. Use the optimizing tier as the
	// native reference and still check every signed input against the
	// independent scalar results.
	checkWASMV128MemoryRuntime(t, wasmV128ArithmeticSource(rows), rows, wasmV128IntegerArithmeticOracle, "--no-liftoff")
}

func TestWASMV128IntegerArithmeticRejectsMalformedSource(t *testing.T) {
	checkWASMV128ArithmeticRejectsMalformedSource(t, wasmV128IntegerArithmeticCases())
}

const wasmV128IntegerArithmeticOracle = wasmV128MemoryKernelJS + `
const native = nativeMemory(row => row.Operands);
const views = [native, translated].map(mod => new DataView(mod.memory.buffer));
const unsigned = (i, bits) => Number(BigInt.asUintN(bits, BigInt(i)));
const signed = (i, bits) => Number(BigInt.asIntN(bits, BigInt(i)));
for (const {Name, Bits, Operands} of rows) {
  const dot = Name.startsWith('dot');
  const fixed = Name.startsWith('q15');
  const input = dot ? (Name === 'dot16' ? 16 : 8) : Bits;
  const lanes = 128 / input;
  const group = Bits / input;
  const sign = 2 ** (input-1);
  const edges = [0,1,2,3,sign/2,sign-1,sign,sign+1,sign+sign/2,2*sign-1,2*sign-2];
  for (let seed = 0; seed <= edges.length; seed++) {
    const a = Array.from({length:lanes}, (_, i) => seed === 0 ? sign : edges[(seed+3*i) % edges.length]);
    const b = Array.from({length:lanes}, (_, i) => seed === 0 ? sign : edges[(seed+5*i+1) % edges.length]);
    const c = [0x7fffffff, 0x80000000, 0xffffffff, 0].map(x => (x+seed) >>> 0);
    for (const view of views) {
      view.setUint8(127, 0x5a);
      view.setUint8(144, 0xa5);
      for (let i = 0; i < lanes; i++) {
        const pos = i * input / 8;
        if (input === 8) {
          view.setUint8(32+pos, a[i]);
          view.setUint8(64+pos, b[i]);
        } else {
          view.setUint16(32+pos, a[i], true);
          view.setUint16(64+pos, b[i], true);
        }
      }
      c.forEach((acc, i) => view.setUint32(96+4*i, acc, true));
    }
    native[Name]();
    translated[Name]();
    for (let lane = 0; lane < 128/Bits; lane++) {
      let expect, nativeAllowed;
      if (dot) {
        const start = lane*group;
        function product(index, unsignedRight) {
          const rhs = unsignedRight ? b[index] : signed(b[index], input);
          return signed(a[index], input) * rhs;
        }
        function pair(index, mode, width) {
          const sum = product(index, mode === 'sat') + product(index+1, mode === 'sat');
          if (mode === 'sat') return Math.max(-(2 ** (width-1)), Math.min(2 ** (width-1)-1, sum));
          return signed(sum, width);
        }
        if (Operands === 3) {
          // The deterministic dot-add first wraps each signed i16 pair.
          expect = pair(start,'wrap',16) + pair(start+2,'wrap',16) + c[lane];
          nativeAllowed = ['wrap','sat'].flatMap(mode => [16,32].map(width =>
            pair(start,mode,width) + pair(start+2,mode,width) + c[lane]));
        } else {
          expect = pair(start,'wrap',Bits);
          nativeAllowed = Name === 'dot16' ? [expect] : [expect,pair(start,'sat',Bits)];
        }
      } else if (fixed) {
        const raw = Math.floor((signed(a[lane],16)*signed(b[lane],16)+16384)/32768);
        expect = Math.min(32767, raw);
        nativeAllowed = Name === 'q15Relaxed' ? [expect,raw] : [expect];
      } else {
        expect = Math.ceil((a[lane]+b[lane])/2);
        nativeAllowed = [expect];
      }
      const at = 128+lane*Bits/8;
      const read = view => Bits === 8 ? view.getUint8(at) :
        Bits === 16 ? view.getUint16(at, true) : view.getUint32(at, true);
      const observed = read(views[0]);
      if (!nativeAllowed.some(value => unsigned(value, Bits) === observed)) {
        throw Error(Name + ': native result differs for seed ' + seed + ', lane ' + lane + ': ' + observed);
      }
      if (read(views[1]) !== unsigned(expect, Bits)) {
        throw Error(Name + ': wrong deterministic result for seed ' + seed + ', lane ' + lane);
      }
    }
    if (views.some(view => view.getUint8(127) !== 0x5a || view.getUint8(144) !== 0xa5)) {
      throw Error(Name + ': write escaped the vector width');
    }
  }
}
`
