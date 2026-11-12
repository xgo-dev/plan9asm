package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Called by the required Linux cross-runtime matrix: QEMU supplies SVE on
// runners whose host CPU does not have it. No host-feature skip is involved.
func testARM64RawSVECountIndexRuntime(t *testing.T, llc string) {
	var source, main strings.Builder
	sigs := make(map[string]FuncSig)
	main.WriteString(`#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>

static uint64_t count(unsigned pattern, unsigned lanes) {
  if (pattern == 31) return lanes;
  if (pattern == 30) return lanes / 3 * 3;
  if (pattern == 29) return lanes / 4 * 4;
  if (pattern == 0) {
    unsigned n = 1;
    while (n * 2 <= lanes) n *= 2;
    return n;
  }
  unsigned n = pattern <= 8 ? pattern : pattern <= 13 ? 1u << (pattern - 5) : 0;
  return n <= lanes ? n : 0;
}
`)
	var checks strings.Builder
	for size := uint32(0); size < 4; size++ {
		for pattern := uint32(0); pattern < 32; pattern++ {
			name := fmt.Sprintf("predicate_count_%d_%d", size, pattern)
			tested := uint32(0x2518e000) | size<<22 | pattern<<5 | 1
			governing := uint32(0x2518e000) | size<<22 | (31-pattern)<<5 | 15
			count := uint32(0x25208000) | size<<22 | 15<<10 | 1<<5 | 10
			fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nWORD $%#08x\nWORD $%#08x\nWORD $%#08x\nMOVD R10,ret+8(FP)\nRET\n", name, tested, governing, count)
			sigs[name] = crossUnarySig("arm64", name)
			fmt.Fprintf(&main, "extern uint64_t %s(uint64_t);\n", name)
			fmt.Fprintf(&checks, `    {
      uint64_t tested = count(%d, vl / %d), governing = count(%d, vl / %d);
      if (%s(x) != (tested < governing ? tested : governing)) return 6;
    }
`, pattern, 1<<size, 31-pattern, 1<<size, name)
			selectName := name + "_select"
			all := uint32(0x2518e3e2) | size<<22 // P2 is the inactive selection.
			selectWord := uint32(0x25004210 | 2<<16 | 1<<5 | 15<<10 | 3)
			selectCount := uint32(0x25208000) | size<<22 | 2<<10 | 3<<5 | 10
			fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nWORD $%#08x\nWORD $%#08x\nWORD $%#08x\nWORD $%#08x\nWORD $%#08x\nMOVD R10,ret+8(FP)\nRET\n", selectName, tested, governing, all, selectWord, selectCount)
			sigs[selectName] = crossUnarySig("arm64", selectName)
			fmt.Fprintf(&main, "extern uint64_t %s(uint64_t);\n", selectName)
			fmt.Fprintf(&checks, `    {
      uint64_t tested = count(%d, vl / %d), governing = count(%d, vl / %d);
      uint64_t active = tested < governing ? tested : governing;
      if (%s(x) != vl / %d - governing + active) return 7;
    }
`, pattern, 1<<size, 31-pattern, 1<<size, selectName, 1<<size)
		}
		for operation, base := range []uint32{0x0420e000, 0x0430e000, 0x0430e400} {
			for pattern := uint32(0); pattern < 32; pattern++ {
				name := fmt.Sprintf("count_%d_%d_%d", size, operation, pattern)
				multiplier := pattern%16 + 1
				word := base | size<<22 | (multiplier-1)<<16 | pattern<<5 | 10
				fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVD x+0(FP),R10\nWORD $%#08x\nMOVD R10,ret+8(FP)\nRET\n", name, word)
				sigs[name] = crossUnarySig("arm64", name)
				fmt.Fprintf(&main, "extern uint64_t %s(uint64_t);\n", name)
				want := fmt.Sprintf("count(%d, vl / %d) * %d", pattern, 1<<size, multiplier)
				if operation == 1 {
					want = "x + " + want
				} else if operation == 2 {
					want = "x - " + want
				}
				fmt.Fprintf(&checks, "    if (%s(x) != (%s)) return %d;\n", name, want, 1+operation)
			}
		}
		for form := uint32(0); form < 4; form++ {
			name := fmt.Sprintf("index_%d_%d", size, form)
			start, step := uint32(16), uint32(15)
			if form&1 != 0 {
				start = 1
			}
			if form&2 != 0 {
				step = 2
			}
			word := uint32(0x04204000) | size<<22 | form<<10 | start<<5 | step<<16 | 16
			fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD out+0(FP),R0\nMOVD start+8(FP),R1\nMOVD step+16(FP),R2\nWORD $%#08x\nWORD $0x2518e3e0\nZST1B [Z16.B],P0,(R0)\nRET\n", name, word)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}}}
			fmt.Fprintf(&main, "extern void %s(void *, int64_t, int64_t);\n", name)
			wantStart, wantStep := -16, 15
			if form&1 != 0 {
				wantStart = -257
			}
			if form&2 != 0 {
				wantStep = 129
			}
			fmt.Fprintf(&checks, `    %s(buf, -257, 129);
    for (unsigned i = 0; i < vl / %d; i++) {
      uint64_t got = 0, want = (uint64_t)((int64_t)%d + (int64_t)i * %d);
      memcpy(&got, buf + i * %d, %d);
      if (memcmp(&got, &want, %d) != 0) return 4;
    }
`, name, 1<<size, wantStart, wantStep, 1<<size, 1<<size, 1<<size)
		}
	}
	mainC := arm64SVEVectorLengthMain(main.String(),
		"unsigned char buf[256] = {0};\nuint64_t x = UINT64_MAX - 3;\n"+checks.String())
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "raw_sve_count_index", triple, ir, mainC,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
