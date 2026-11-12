//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

type x86PackedConversionFaultRow struct {
	name       string
	width      int
	laneBytes  int
	lanes      int
	masked     bool
	floating   bool
	precision  bool
	aligned    bool
	conversion string
}

func x86PackedConversionFaultRows(wide bool) []x86PackedConversionFaultRow {
	var rows []x86PackedConversionFaultRow
	for _, spec := range x86PackedConversionOracleSpecs() {
		if !wide && !spec.legacy {
			continue
		}
		for _, shape := range spec.shapes() {
			destination := map[int]string{16: "X1", 32: "Y1", 64: "Z1"}[shape.destination]
			floating := strings.Contains(strings.Split(spec.name, "2")[0], "PS") || strings.Contains(strings.Split(spec.name, "2")[0], "PD")
			precision := floating || spec.input > map[int]int{32: 24, 64: 53}[spec.output]
			rows = append(rows, x86PackedConversionFaultRow{name: spec.name, width: shape.lanes * spec.input / 8, laneBytes: spec.input / 8, lanes: shape.lanes,
				floating: floating, precision: precision, aligned: spec.legacy, conversion: spec.name + " (DI)," + destination})
			if !spec.legacy {
				rows = append(rows,
					x86PackedConversionFaultRow{name: spec.name + ".Z", width: shape.lanes * spec.input / 8, laneBytes: spec.input / 8, lanes: shape.lanes, masked: true,
						floating: floating, precision: precision, conversion: spec.name + ".Z (DI),K1," + destination},
					x86PackedConversionFaultRow{name: spec.name + ".BCST.Z", width: spec.input / 8, laneBytes: spec.input / 8, lanes: shape.lanes, masked: true,
						floating: floating, precision: precision, conversion: spec.name + ".BCST.Z (DI),K1," + destination})
			}
		}
	}
	return rows
}

// One actual Go TEXT holds every independent straight-line kernel. Split at
// decoded RET boundaries, never a byte search (0xc3 can occur in displacement).
// This creates no production native/source authorization.
func x86PackedConversionFaultOriginalBytes(t *testing.T, rows []x86PackedConversionFaultRow) [][]byte {
	t.Helper()
	var source strings.Builder
	source.WriteString("TEXT original(SB),4,$0-0\n")
	for _, row := range rows {
		source.WriteString("LDMXCSR (SI)\n")
		if row.masked {
			source.WriteString("KMOVW DX,K1\n")
		}
		source.WriteString(row.conversion + "\nRET\n")
	}
	code := x86PackedShiftActualGoBytes(t, "amd64", source.String())
	var result [][]byte
	offset := 0
	for _, row := range rows {
		start := offset
		header := []byte{0x0f, 0xae, 0x16} // Actual Go LDMXCSR (SI).
		if row.masked {
			header = append(header, 0xc5, 0xf8, 0x92, 0xca) // KMOVW DX,K1.
		}
		if len(code)-offset < len(header) || !bytes.Equal(code[offset:offset+len(header)], header) {
			t.Fatal("actual original header changed", row.name, offset)
		}
		offset += len(header)
		_, length, known, err := decodedX86PackedNumericConversionInstruction(code[offset:], 64)
		if !known {
			_, length, known, err = decodedX86SameWidthConversionInstruction(code[offset:], 64)
		}
		if !known {
			_, length, known, err = decodedX86PackedDoubleDwordInstruction(code[offset:], 64)
		}
		if !known {
			native, decodeErr := x86asm.Decode(code[offset:], 64)
			err, length = decodeErr, native.Len
		}
		if err != nil || length <= 0 || offset+length >= len(code) || code[offset+length] != 0xc3 {
			t.Fatal("whole original conversion/RET boundary", row.name, offset, err)
		}
		offset += length + 1
		result = append(result, append([]byte(nil), code[start:offset]...))
	}
	if offset != len(code) {
		t.Fatal("unconsumed original Go instruction bytes")
	}
	return result
}

func x86PackedConversionDeadFaults(t *testing.T, wide, nativeTraps bool) {
	t.Helper()
	axis := x86FloatCompareSSE
	if wide || nativeTraps {
		axis = x86FloatCompareEVEX
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	rows := x86PackedConversionFaultRows(wide)
	x86PackedConversionRunFaultRows(t, execution, rows, 96, 0, 1, nativeTraps, false)
}

func x86PackedConversionRunFaultRows(t *testing.T, execution x86FloatCompareExecution, rows []x86PackedConversionFaultRow, limit, owner, owners int, nativeTraps, complete bool) {
	t.Helper()
	consumed := 0
	for batchNumber, start := 0, 0; start < len(rows); batchNumber, start = batchNumber+1, start+limit {
		if batchNumber%owners != owner {
			continue
		}
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			batch := rows[start:end]
			var original [][]byte
			observe := func(t *testing.T) {
				original = x86PackedConversionFaultOriginalBytes(t, batch)
				if len(original) != len(batch) {
					t.Fatal("incomplete original Go opcode reference")
				}
			}
			if complete {
				t.Run("original_go_opcode_reference", observe)
			} else {
				observe(t)
			}
			if len(original) != len(batch) {
				t.Fatal("missing original Go opcode reference")
			}
			var source, decl, native, prototypes, pairs strings.Builder
			for index, row := range batch {
				name, reference := fmt.Sprintf("fault%d", index), fmt.Sprintf("original%d", index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ p+0(FP),DI\nMOVQ csr+8(FP),SI\nLDMXCSR (SI)\n", name)
				if row.masked {
					source.WriteString("MOVL mask+16(FP),DX\nKMOVW DX,K1\n")
				}
				source.WriteString(row.conversion + "\nRET\n")
				fmt.Fprintf(&decl, "func %s(p *uint64,csr *uint32,mask uint32)\n", name)
				var octets []string
				for _, value := range original[index] {
					octets = append(octets, fmt.Sprintf("0x%02x", value))
				}
				symbol := reference
				if strings.Contains(execution.triple, "apple") {
					symbol = "_" + symbol
				}
				fmt.Fprintf(&native, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(octets, ",")+"\n")
				fmt.Fprintf(&prototypes, "extern void %s(uint64_t*,uint32_t*,uint32_t),%s(uint64_t*,uint32_t*,uint32_t);\n", name, reference)
				fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d,%d,%d,%d,%d},\n", reference, name, row.width, row.laneBytes, row.lanes,
					x86FloatAddSubBoolInt(row.masked), x86FloatAddSubBoolInt(row.floating),
					x86FloatAddSubBoolInt(row.precision), x86FloatAddSubBoolInt(row.aligned))
			}
			goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
			driver := fmt.Sprintf("#define NATIVE_TRAPS %d\n#define COMPLETE_NATIVE %d\n", x86FloatAddSubBoolInt(nativeTraps), x86FloatAddSubBoolInt(complete)) + `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + native.String() + prototypes.String() + `
typedef void (*program)(uint64_t*,uint32_t*,uint32_t);
static const struct {program original,translated;int width,lane,lanes,masked,floating,precision,aligned;} pairs[]={
` + pairs.String() + `};
static int outcome(program fn,uint8_t *p,uint32_t csr,uint32_t mask) {
    pid_t child=fork();if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        fn((uint64_t*)p,&csr,mask);_exit(0);
    }
    int status;if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status)&&WEXITSTATUS(status)==0) return 0;
    if(WIFSIGNALED(status)) {int sig=WTERMSIG(status);if(sig==SIGSEGV||sig==SIGBUS)return 1;if(sig==SIGFPE)return 2;}
    return -1;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    uint8_t *p=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(p==MAP_FAILED||mprotect(p+page,page,PROT_NONE))return 2;
    memset(p,0,page);
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);i++) {
        int limits[]={0,pairs[i].width-1,pairs[i].width,pairs[i].width+1};
        for(unsigned m=0;m<(pairs[i].masked?(COMPLETE_NATIVE?4u:3u):1u);m++) for(unsigned n=0;n<4;n++) {
            uint32_t mask=m==0?0xffff:(m==1?0:(m==2?1:(1u<<pairs[i].lanes)));
            int expected=limits[n]<((m==1||m==3)?0:(m==2?pairs[i].lane:pairs[i].width));
            int a=outcome(pairs[i].original,p+page-limits[n],0x1f80,mask),b=outcome(pairs[i].translated,p+page-limits[n],0x1f80,mask);
            int unaligned=pairs[i].aligned&&((uintptr_t)(p+page-limits[n])%16)!=0;
            if(unaligned&&NATIVE_TRAPS) expected=1;
            // Rosetta's legacy axis is differential only. The native owner
            // above must enforce the legacy m128 alignment exception too.
            if(unaligned&&!NATIVE_TRAPS&&!expected&&(a==0||a==1)) expected=a;
            if(a!=expected||b!=expected) {fprintf(stderr,"dead read=%u available=%d mask=%x Go=%d LLVM=%d expected=%d\n",i,limits[n],mask,a,b,expected);return 3;}
        }
        for(int event=0;NATIVE_TRAPS&&event<2;event++) {
            if((event==0&&!pairs[i].floating)||(event==1&&!pairs[i].precision)) continue;
            uint64_t bits;
            if(pairs[i].floating) {
                if(pairs[i].lane==8) bits=event?UINT64_C(0x3ff8000000000000):UINT64_C(0x7ff8123456789abc);
                else bits=event?UINT64_C(0x3fc00000):UINT64_C(0x7fc12345);
            } else bits=pairs[i].lane==8?UINT64_C(0x20000000000001):UINT64_C(0x1000001);
            memset(p,0,64);
            memcpy(p,&bits,pairs[i].lane);
            uint32_t csr=event?0x0f80:0x1f00;
            for(int zero=0;zero<(pairs[i].masked?2:1);zero++) {
                uint32_t mask=zero?0:0xffff;
                int expected=zero?0:2;
                int a=outcome(pairs[i].original,p,csr,mask),b=outcome(pairs[i].translated,p,csr,mask);
                if(a!=expected||b!=expected) {
                    fprintf(stderr,"dead exception=%u event=%d mask=%x Go=%d LLVM=%d expected=%d\n",i,event,mask,a,b,expected);
                    return 4;
                }
            }
        }
    }
    if(munmap(p,2*page))return 5;
    puts("complete original Go/LLVM packed dead-fault receipt");return 0;
}
`
			if complete {
				raw := source.String()
				for index, row := range batch {
					header := 3
					if row.masked {
						header += 4
					}
					conversion := original[index][header : len(original[index])-1]
					raw = strings.Replace(raw, row.conversion+"\nRET\n", x86RawDisplacementDirectives(conversion)+"RET\n", 1)
				}
				for _, spelling := range []struct{ name, source string }{{"named", source.String()}, {"raw", raw}} {
					t.Run(spelling.name, func(t *testing.T) {
						goAssemblerOracleOutput(t, "amd64", spelling.source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, spelling.source, decl.String(), "amd64", execution.triple, api)
								if err != nil {
									t.Fatal("initialized dead native conversion rejected", err)
								}
								x86PackedConversionNativePipelines(t, execution, ir, driver, []byte("complete original Go/LLVM packed dead-fault receipt\n"))
							})
						}
					})
				}
				consumed += len(batch)
				return
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), decl.String(), "amd64", execution.triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, optimized := range []bool{false, true} {
					input := ir
					if optimized {
						input = x86MulDivRoundOptimize(t, ir)
					}
					for _, level := range []string{"-O0", "-O2"} {
						output := execution.compileAndRunLLVM(t, "packed-dead-fault", input, driver, level)
						if string(output) != "complete original Go/LLVM packed dead-fault receipt\n" {
							t.Fatal("incomplete dead-fault receipt", string(output))
						}
					}
				}
			}
			consumed += len(batch)
		})
	}
	if consumed == 0 {
		t.Fatal("empty dead-fault owner")
	}
	t.Logf("%d/%d original-Go-opcode native memory and unmasked-fault kernels owned here", consumed, len(rows))
}

func TestCrossLinuxRuntimeMatrixX86PackedConversionLegacyDeadFaults(t *testing.T) {
	x86PackedConversionDeadFaults(t, false, false)
}

func TestX86PackedConversionCompleteFaultOriginalBoundaries(t *testing.T) {
	rows := x86PackedConversionCompleteFaultRows()
	if len(rows) != 222 {
		t.Fatal("complete42 original fault boundary denominator changed", len(rows))
	}
	const limit = x86PackedConversionFaultCapture
	consumed := 0
	for start := 0; start < len(rows); start += limit {
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			original := x86PackedConversionFaultOriginalBytes(t, rows[start:end])
			if len(original) != end-start {
				t.Fatal("original native fault fixture lost a conversion")
			}
			consumed += len(original)
		})
	}
	if consumed != len(rows) {
		t.Fatal("native fault batches overlap or omit rows")
	}
	t.Logf("%d original-Go complete memory/masked/broadcast fault kernels; assembly only, not native execution", consumed)
}
