package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

type x86MADDOracleRow struct {
	width, inputBytes, source, alias, masking int
	legacy, mmx                               bool
}

func x86MADDOracleRows() []x86MADDOracleRow {
	var rows []x86MADDOracleRow
	for _, inputBytes := range []int{1, 2} {
		for _, width := range []int{8, 16, 32, 64} {
			for _, legacy := range []bool{true, false} {
				if legacy && width > 16 || !legacy && width == 8 || width == 8 && inputBytes == 1 {
					continue
				}
				for source := 0; source < 2; source++ {
					for alias := 0; alias < 3; alias++ {
						if legacy && alias == 2 {
							continue
						}
						for mask := 0; mask < 3; mask++ {
							if legacy && mask != 0 {
								continue
							}
							rows = append(rows, x86MADDOracleRow{width, inputBytes, source, alias, mask, legacy, width == 8})
						}
					}
				}
			}
		}
	}
	return rows
}

func (row x86MADDOracleRow) instruction() (string, string) {
	bank := map[int]string{8: "M", 16: "X", 32: "Y", 64: "Z"}[row.width]
	first, destination := bank+"0", fmt.Sprintf("%s%d", bank, row.alias)
	if row.legacy {
		destination = bank + "1"
		if row.alias == 1 {
			first = destination
		}
	}
	if row.source == 1 {
		first = "(CX)"
		if row.legacy && row.alias == 1 {
			first = "(DX)"
		}
	}
	name := "PMADDWL"
	if row.inputBytes == 1 {
		name = "PMADDUBSW"
	}
	if row.legacy {
		return name + " " + first + "," + destination, destination
	}
	name = "VPMADDWD"
	if row.inputBytes == 1 {
		name = "VPMADDUBSW"
	}
	if row.masking == 2 {
		name += ".Z"
	}
	mask := ""
	if row.masking != 0 {
		mask = "K1,"
	}
	return name + " " + first + "," + bank + "1," + mask + destination, destination
}

// Independent widened integer arithmetic, not a production helper/intrinsic.
// Signed word pairs wrap modulo 2^32; signed-byte * unsigned-byte pairs
// saturate to signed16. Every pair stays in its source byte position.
const x86MADDIndependentCReference = `
static const int32_t edges[] = {
  0, 1, -1, 2, -2, 127, -128, 255, 256, -257, 32767, -32768, 16384, -16384
};

static void fill(uint8_t *out, unsigned sample, unsigned salt, int bytes) {
  for (int i = 0; i < 64; i += bytes) {
    int32_t v = edges[(sample + salt + i * 3) % 14];
    if (sample >= 14) v = (int32_t)(sample * 7919 + i * 104729 + salt * 65537);
    out[i] = (uint8_t)v;
    if (bytes == 2) out[i + 1] = (uint8_t)(v >> 8);
  }
}

static int64_t signed_word(const uint8_t *p) {
  uint32_t bits = (uint32_t)p[0] | (uint32_t)p[1] << 8;
  return bits < 32768 ? (int64_t)bits : (int64_t)bits - 65536;
}

static void independent_madd(uint8_t *out, const uint8_t *first,
                             const uint8_t *second, int width, int bytes) {
  int group = bytes * 2;
  for (int i = 0; i < width; i += group) {
    int64_t sum;
    if (bytes == 2) sum = signed_word(first + i) * signed_word(second + i) +
                          signed_word(first + i + 2) * signed_word(second + i + 2);
    else {
      int32_t a = first[i] < 128 ? first[i] : (int32_t)first[i] - 256;
      int32_t b = first[i + 1] < 128 ? first[i + 1] : (int32_t)first[i + 1] - 256;
      sum = (int64_t)a * second[i] + (int64_t)b * second[i + 1];
      if (sum < -32768) sum = -32768;
      if (sum > 32767) sum = 32767;
    }
    uint32_t bits = (uint32_t)sum;
    for (int j = 0; j < group; ++j) out[i + j] = (uint8_t)(bits >> (j * 8));
  }
}
`

func TestCrossLinuxRuntimeMatrixX86MADDTypedIndependentWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	rows := x86MADDOracleRows()
	var assembly, declarations, table, main strings.Builder
	declarations.WriteString("package narroworacle\n")
	main.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	for index, row := range rows {
		name := fmt.Sprintf("madd%d", index)
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b,old *[64]byte,mask,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-52\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nMOVQ mask+32(FP),R9\n", name)
		// Set the independent state before entering MMX. Its physical x87
		// region must remain uninterrupted through the real EMMS instruction.
		assembly.WriteString("LDMXCSR csr+48(FP)\nPUSHQ flags+40(FP)\nPOPFQ\n")
		if row.mmx {
			assembly.WriteString("MOVQ (CX),M0\nMOVQ (DX),M1\n")
		} else {
			assembly.WriteString("VMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (R8),Z2\nKMOVQ R9,K1\n")
		}
		instruction, destination := row.instruction()
		fmt.Fprintf(&assembly, "%s\n", instruction)
		if row.mmx {
			fmt.Fprintf(&assembly, "MOVQ %s,(AX)\nEMMS\n", destination)
		} else {
			fmt.Fprintf(&assembly, "VMOVUPS Z%s,(AX)\n", destination[1:])
		}
		assembly.WriteString("PUSHFQ\nPOPQ R10\nMOVQ R10,64(AX)\nSTMXCSR 72(AX)\nRET\n")
		fmt.Fprintf(&main, "extern void %s(void*,const void*,const void*,const void*,uint64_t,uint64_t,uint32_t);\n", name)
		fmt.Fprintf(&table, "{%s,%d,%d,%d,%d,%d,%d},\n", name, row.width, row.inputBytes, row.source, row.alias, row.masking, x86FloatAddSubBoolInt(row.legacy))
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	main.WriteString("static const struct {void (*run)(void*,const void*,const void*,const void*,uint64_t,uint64_t,uint32_t);int width,bytes,source,alias,masking,legacy;} cases[]={\n" + table.String() + "};\n")
	main.WriteString(x86MADDIndependentCReference)
	main.WriteString(`
int main(void) {
  unsigned saved;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));
  const uint32_t profiles[] = {0x1f80, 0x3fc1, 0x5f82, 0x9fe5};
  unsigned long long observations = 0;
  for (unsigned row = 0; row < sizeof(cases) / sizeof(cases[0]); ++row) {
    int lanes = cases[row].width / (cases[row].bytes * 2);
    for (unsigned sample = 0; sample < 32; ++sample)
    for (int select = 0; select < lanes + 4; ++select)
    for (unsigned profile = 0; profile < 4; ++profile)
    for (unsigned seed = 0; seed < 2; ++seed) {
      _Alignas(64) uint8_t a[64], b[64], old[64], beforeA[64], beforeB[64], beforeOld[64];
      uint8_t out[82], want[82], packed[64];
      fill(a, sample, 0, cases[row].bytes);
      fill(b, sample, 7, cases[row].bytes);
      for (int i = 0; i < 64; ++i) old[i] = (uint8_t)(0x91 + i * 11);
      if (cases[row].bytes == 2 && sample == 0)
      for (int i = 0; i < 64; i += 2) {
        a[i] = b[i] = 0;
        a[i + 1] = b[i + 1] = 0x80;
      }
      if (cases[row].bytes == 1 && sample < 2) {
        memset(a, sample ? 0x80 : 0x7f, 64);
        memset(b, 0xff, 64);
      }
      memcpy(beforeA, a, 64);
      memcpy(beforeB, b, 64);
      memcpy(beforeOld, old, 64);
      memset(out, 0xc3, sizeof(out));
      memcpy(want, out, sizeof(want));

      uint64_t mask = select == 0 ? 0 : select == 1 ? UINT64_MAX :
                      select == 2 ? UINT64_C(0xaaaaaaaaaaaaaaaa) :
                      select == 3 ? UINT64_MAX << lanes : UINT64_C(1) << (select - 4);
      uint64_t flags = 2 | (seed ? 0x8d5 : 0);
      cases[row].run(out + 1, a, b, old, mask, flags, profiles[profile]);
      const uint8_t *first = cases[row].legacy && cases[row].alias ? b : a;
      independent_madd(packed, first, b, cases[row].width, cases[row].bytes);
      const uint8_t *previous = cases[row].legacy ? b :
                                cases[row].alias == 0 ? a : cases[row].alias == 1 ? b : old;
      for (int i = 0; i < 64; ++i) {
        uint8_t value = cases[row].width == 8 ? 0xc3 : cases[row].legacy ? previous[i] : 0;
        if (i < cases[row].width) {
          value = packed[i];
          if (cases[row].masking && !(mask >> (i / (cases[row].bytes * 2)) & 1))
            value = cases[row].masking == 2 ? 0 : previous[i];
        }
        want[i + 1] = value;
      }

      uint64_t actualFlags;
      uint32_t actualCSR;
      memcpy(&actualFlags, out + 65, 8);
      memcpy(&actualCSR, out + 73, 4);
      memcpy(want + 65, out + 65, 12);
      ++observations;
      if ((actualFlags & 0x8d5) != (flags & 0x8d5) || actualCSR != profiles[profile] ||
          memcmp(out, want, sizeof(out)) || memcmp(a, beforeA, 64) ||
          memcmp(b, beforeB, 64) || memcmp(old, beforeOld, 64)) {
        fprintf(stderr, "MADD row%u sample%u width%d bytes%d source%d alias%d mask%llx flags%llx csr%x\n",
                row, sample, cases[row].width, cases[row].bytes, cases[row].source,
                cases[row].alias, (unsigned long long)mask, (unsigned long long)actualFlags, actualCSR);
        for (unsigned i = 0; i < sizeof(out); ++i)
          if (out[i] != want[i]) fprintf(stderr, "byte%u got%u want%u\n", i, out[i], want[i]);
        return 1;
      }
    }
  }
  __asm__ volatile("ldmxcsr %0" :: "m"(saved));
  printf("MADD kernels=%zu observations=%llu aliases64 sixFlags fullCSR canaries\n",
         sizeof(cases) / sizeof(cases[0]), observations);
  return 0;
}
`)
	observations := 0
	for _, row := range rows {
		observations += (row.width/(row.inputBytes*2) + 4) * 32 * 4 * 2
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			ir := ir
			if level == "-O2" {
				ir = x86MulDivRoundOptimize(t, ir)
			}
			output := execution.compileAndRunLLVM(t, "madd-independent", ir, main.String(), level)
			want := fmt.Sprintf("MADD kernels=%d observations=%d aliases64 sixFlags fullCSR canaries\n", len(rows), observations)
			if string(output) != want {
				t.Fatalf("incomplete MADD denominator: %q want %q", output, want)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
	t.Log("software VEX/EVEX is not original native AVX/AVX512 execution")
}

func TestCrossLinuxRuntimeMatrixX86MADDTypedOriginalLegacy(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, table strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, row := range x86MADDOracleRows() {
		if !row.legacy {
			continue
		}
		name := fmt.Sprintf("original%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(out *[32]byte,a,b *[64]byte,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-36\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nSTMXCSR saved-4(SP)\nLDMXCSR csr+32(FP)\n", name)
		move, bank := "MOVOU", "X"
		if row.mmx {
			move, bank = "MOVQ", "M"
		}
		fmt.Fprintf(&assembly, "%s (CX),%s0\n%s (DX),%s1\nPUSHQ flags+24(FP)\nPOPFQ\n", move, bank, move, bank)
		instruction, destination := row.instruction()
		fmt.Fprintf(&assembly, "%s\n%s %s,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,16(AX)\nSTMXCSR 24(AX)\n", instruction, move, destination)
		if row.mmx {
			assembly.WriteString("EMMS\n")
		}
		assembly.WriteString("LDMXCSR saved-4(SP)\nRET\n")
		fmt.Fprintf(&table, "{%s,%d,%d,%d,-1},\n", name, row.width, row.inputBytes, row.alias)
	}
	// These accepted GP spellings encode MMX ModRM source banks. Initialize
	// each physical M register independently; do not interpret GP contents as
	// numeric MMX inputs or grant this source spelling LLVM admission.
	for index, register := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		name := fmt.Sprintf("original%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(out *[32]byte,a,b *[64]byte,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-36\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nSTMXCSR saved-4(SP)\nLDMXCSR csr+32(FP)\n", name)
		for bank := 0; bank < 8; bank++ {
			fmt.Fprintf(&assembly, "MOVQ %d(CX),M%d\n", bank*8, bank)
		}
		assembly.WriteString("MOVQ (DX),M1\nPUSHQ flags+24(FP)\nPOPFQ\n")
		fmt.Fprintf(&assembly, "PMADDWL %s,M1\nMOVQ M1,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,16(AX)\nSTMXCSR 24(AX)\nEMMS\nLDMXCSR saved-4(SP)\nRET\n", register)
		fmt.Fprintf(&table, "{%s,8,2,0,%d},\n", name, index&7)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	tests := `package oracle
import (
 "testing"
 "encoding/binary"
 "runtime"
 "unsafe"
)

var cases = []struct {
 run func(*[32]byte, *[64]byte, *[64]byte, uint64, uint32)
 width, bytes, alias, bank int
}{
` + table.String() + `}

func aligned(storage *[128]byte) *[64]byte {
 offset := int((-uintptr(unsafe.Pointer(&storage[0]))) & 63)
 return (*[64]byte)(unsafe.Pointer(&storage[offset]))
}

func TestOriginal(t *testing.T) {
 runtime.LockOSThread()
 defer runtime.UnlockOSThread()
 edges := [...]int32{0, 1, -1, 2, -2, 127, -128, 255, 256, -257, 32767, -32768, 16384, -16384}
 profiles := []uint32{0x1f80, 0x3fc1, 0x5f82, 0x9fe5}
 var aa, bb [128]byte
 a, b := aligned(&aa), aligned(&bb)
 observations := 0

 for row, entry := range cases {
  for sample := 0; sample < 32; sample++ {
   for _, csr := range profiles {
    for seed := 0; seed < 2; seed++ {
     for i := range aa {
      aa[i] = 0xa7
      bb[i] = 0xb9
     }
     for i := 0; i < 64; i += entry.bytes {
      x, y := edges[(sample+i*3)%14], edges[(sample+7+i*3)%14]
      if sample >= 14 {
       x = int32(sample*7919+i*104729)
       y = int32(sample*7919+i*104729+7*65537)
      }
      a[i], b[i] = byte(x), byte(y)
      if entry.bytes == 2 {
       a[i+1], b[i+1] = byte(uint32(x)>>8), byte(uint32(y)>>8)
      }
     }
     if entry.bytes == 2 && sample == 0 {
      for i := 0; i < 64; i += 2 {
       a[i] = 0
       b[i] = 0
       a[i+1] = 0x80
       b[i+1] = 0x80
      }
     }
     if entry.bytes == 1 && sample < 2 {
      for i := range a {
       a[i] = 0x7f
       if sample == 1 {
        a[i] = 0x80
       }
       b[i] = 0xff
      }
     }
     beforeA, beforeB := aa, bb
     var out, want [34]byte
     for i := range out {
      out[i] = 0xc3
      want[i] = 0xc3
     }

     flags := uint64(2)
     if seed != 0 {
      flags |= 0x8d5
     }
     entry.run((*[32]byte)(unsafe.Pointer(&out[1])), a, b, flags, csr)
     first := a[:]
     if entry.alias == 1 {
      first = b[:]
     }
     if entry.bank >= 0 {
      first = a[entry.bank*8:]
      if entry.bank == 1 {
       first = b[:]
      }
     }
     for i := 0; i < entry.width; i += entry.bytes * 2 {
      var sum int64
      if entry.bytes == 2 {
       sum = int64(int16(binary.LittleEndian.Uint16(first[i:]))) * int64(int16(binary.LittleEndian.Uint16(b[i:]))) +
             int64(int16(binary.LittleEndian.Uint16(first[i+2:]))) * int64(int16(binary.LittleEndian.Uint16(b[i+2:])))
      } else {
       sum = int64(int8(first[i]))*int64(b[i]) + int64(int8(first[i+1]))*int64(b[i+1])
       if sum < -32768 {
        sum = -32768
       }
       if sum > 32767 {
        sum = 32767
       }
      }
      for j := 0; j < entry.bytes * 2; j++ {
       want[i+j+1] = byte(uint32(sum) >> uint(j*8))
      }
     }

     actualFlags := binary.LittleEndian.Uint64(out[17:25])
     actualCSR := binary.LittleEndian.Uint32(out[25:29])
     copy(want[17:29], out[17:29])
     observations++
     if out != want || aa != beforeA || bb != beforeB || actualFlags&0x8d5 != flags&0x8d5 || actualCSR != csr {
      t.Fatalf("original MADD row%d sample%d width%d bytes%d flags%x CSR%x got%x want%x",
               row, sample, entry.width, entry.bytes, actualFlags, actualCSR, out, want)
     }
    }
   }
  }
 }
 t.Logf("original MADD kernels=%d observations=%d sixFlags fullCSR canaries", len(cases), observations)
}
`
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": tests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, gotoolchain.HostExecutable("original"))
	command := exec.Command("go", "test", "-c", "-p=2", "-vet=off", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	output := execution.run(t, executable, "-test.v", "-test.run=^TestOriginal$", "-test.count=1")
	want := fmt.Sprintf("original MADD kernels=%d observations=%d sixFlags fullCSR canaries", count, count*32*4*2)
	if !strings.Contains(string(output), want) || !strings.Contains(string(output), "--- PASS: TestOriginal") || strings.Contains(string(output), "SKIP") {
		t.Fatalf("incomplete original-Go denominator: %q", output)
	}
	t.Log(strings.TrimSpace(string(output)))
	t.Log("original SSE/MMX including all16 GP-to-MMX encoded bank spellings only; this gate does not execute VEX/EVEX")
}
