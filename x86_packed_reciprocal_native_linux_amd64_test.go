package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedReciprocalNativeMemoryFaults(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	execution.requireAVX(t)
	if len(execution.prefix) != 0 {
		t.Fatal("packed native faults require direct x86 execution")
	}
	source, declaration := x86PackedReciprocalDeadSource()
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	var prototypes, originals, rows, referenceRows strings.Builder
	for index, row := range x86PackedReciprocalReadCases {
		// Independent original Go bytes preserve the legacy alignment-fault
		// contract, unlike a portable volatile-byte reference.
		code := x86OrderingHintGoBytes(t, "amd64", fmt.Sprintf("TEXT original(SB),4,$0-0\n%s (DI),%s2\nRET\n", row.op, row.bank))
		var atoms []string
		for _, value := range code {
			atoms = append(atoms, fmt.Sprintf("0x%02x", value))
		}
		name := fmt.Sprint("Original", index)
		fmt.Fprintf(&prototypes, "extern void PackedEstimate%d(const uint8_t*);\nextern void %s(const uint8_t*);\n", index, name)
		fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+name+"\n"+name+":\n.byte "+strings.Join(atoms, ",")+"\n")
		fmt.Fprintf(&rows, "{PackedEstimate%d,%s,%d},\n", index, name, row.width)
		fmt.Fprintf(&referenceRows, "{%s,%s,%d},\n", name, name, row.width)
	}
	driver := x86MemoryFaultSupportC + prototypes.String() + originals.String() +
		"struct kernel { void (*translated)(const uint8_t*); void (*original)(const uint8_t*); unsigned width; };\n" +
		"static const struct kernel kernels[]={" + rows.String() + "};\n" + x86PackedReciprocalNativeFaultMainC
	// The independent 36 observations belong only to this owner, unchanged
	// source and native host. Every translated API/pipeline is observed anew.
	originalDriver := strings.Replace(driver, rows.String(), referenceRows.String(), 1)
	originalExecutable := execution.compileLLVM(t, "packed-estimate-original-faults", "", originalDriver, "-O0")
	originalOutcomes := make([][6]string, len(x86PackedReciprocalReadCases))
	for index, row := range x86PackedReciprocalReadCases {
		for probe := 0; probe < 6; probe++ {
			want := x86ObserveMemoryFault(t, execution, originalExecutable, index, probe, 1)
			fault := probe == 0 || probe == 1 || probe == 5 || probe == 3 && row.legacy
			if fault && want != "segv" && want != "bus" || !fault && want != "return" {
				t.Fatal("actual original opcode disagrees with its full-width/alignment fault class", row.op, row.width, probe, want)
			}
			originalOutcomes[index][probe] = want
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("initialized native pointer source rejected", err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					executable := execution.compileLLVM(t, "packed-estimate-native-faults", pipeline.ir, driver, pipeline.level)
					for index, row := range x86PackedReciprocalReadCases {
						for probe, want := range originalOutcomes[index] {
							if got := x86ObserveMemoryFault(t, execution, executable, index, probe, 0); got != want {
								t.Fatal("dead packed estimate lost its original native memory/alignment outcome", row.op, row.width, probe, got, want)
							}
						}
					}
				})
			}
		})
	}
	x87IA32RequireNativeHost(t)
}

const x86PackedReciprocalNativeFaultMainC = `
int main(int argc,char **argv) {
    unsigned row,probe,original;char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&row,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 || sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            row>=sizeof(kernels)/sizeof(kernels[0]) || probe>=6 || original>1) return 80;
    if (memory_fault_setup(0)) return 81;
    struct kernel k=kernels[row];
    const uint8_t *input=NULL;
    if (probe==1) input=guard+page-k.width+1;
    else if (probe==2 || probe==4) input=guard+page-k.width;
    else if (probe==3) input=guard+1;
    else if (probe==5) input=guard+page;
    if (probe==4 && mprotect(guard,page,PROT_READ)) return 82;
    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 83;
    if (original) k.original(input); else k.translated(input);
    if (free_guard()) return 84;
    puts("memory complete");
    return fflush(stdout)?85:0;
}
`
