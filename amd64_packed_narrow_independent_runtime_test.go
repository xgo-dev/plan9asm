package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// The independent oracle describes the ISA, not production properties. Go's
// reversed operands put its second source in the low half of each 128-bit lane.
type x86NarrowOracleFamily struct {
	legacy, vector string
	inputBytes     int
	unsigned       bool
}

type x86NarrowOracleRow struct {
	family               x86NarrowOracleFamily
	bank                 string
	width, source, alias int
	masking              int // 0: none, 1: merge, 2: zero
	legacy               bool
}

func x86NarrowOracleRows() []x86NarrowOracleRow {
	var rows []x86NarrowOracleRow
	for _, family := range x86NarrowOracleFamilies {
		for _, bank := range []string{"X", "M"} {
			if bank == "M" && family.legacy == "PACKUSDW" {
				continue
			}
			width := 16
			if bank == "M" {
				width = 8
			}
			for source := 0; source < 2; source++ {
				for alias := 0; alias < 2; alias++ {
					rows = append(rows, x86NarrowOracleRow{family, bank, width, source, alias, 0, true})
				}
			}
		}
		for widthIndex, bank := range []string{"X", "Y", "Z"} {
			for source := 0; source < 3; source++ {
				if source == 2 && family.inputBytes != 4 {
					continue
				}
				for alias := 0; alias < 3; alias++ {
					for mask := 0; mask < 3; mask++ {
						rows = append(rows, x86NarrowOracleRow{family, bank, 16 << widthIndex, source, alias, mask, false})
					}
				}
			}
		}
	}
	return rows
}

func (row x86NarrowOracleRow) instruction() (string, string) {
	first, destination := row.bank+"0", row.bank+fmt.Sprint(row.alias)
	if row.legacy {
		destination = row.bank + "1"
		if row.alias == 1 {
			first = destination
		}
	}
	if row.source != 0 {
		first = "(CX)"
		if row.legacy && row.alias == 1 {
			first = "(DX)"
		}
	}
	if row.legacy {
		return row.family.legacy + " " + first + "," + destination, destination
	}
	op := row.family.vector
	if row.source == 2 {
		op += ".BCST"
	}
	if row.masking == 2 {
		op += ".Z"
	}
	mask := ""
	if row.masking != 0 {
		mask = "K1,"
	}
	return op + " " + first + "," + row.bank + "1," + mask + destination, destination
}

// Each scalar is signed before clamping, including the unsigned output forms.
// This reference does not call or reproduce production's vector/typed helpers.
const x86NarrowIndependentCReference = `
static const int32_t edges[]={
 INT32_MIN,-65537,-32769,-32768,-32767,-257,-256,-129,-128,-127,-1,0,1,
 126,127,128,129,254,255,256,257,32766,32767,32768,32769,
 65534,65535,65536,65537,INT32_MAX-1,INT32_MAX};
static void fill(uint8_t *out,int bytes,unsigned sample,unsigned salt) {
 for(int lane=0;lane<64/bytes;++lane) {
  int32_t value=edges[(sample+salt+lane*7)%(sizeof(edges)/sizeof(edges[0]))];
  if(bytes==4) memcpy(out+lane*bytes,&value,4);
  else {int16_t small=(int16_t)value;memcpy(out+lane*bytes,&small,2);}
 }
}
static void independent_pack(uint8_t *out,const uint8_t *first,const uint8_t *second,
                             int width,int inputBytes,int unsignedOutput,int broadcast) {
 int chunk=width==8?8:16,outputBytes=inputBytes/2;
 int64_t minimum=unsignedOutput?0:-(INT64_C(1)<<(outputBytes*8-1));
 int64_t maximum=unsignedOutput?(INT64_C(1)<<(outputBytes*8))-1:(INT64_C(1)<<(outputBytes*8-1))-1;
 for(int start=0;start<width;start+=chunk) for(int source=0;source<2;++source) {
  const uint8_t *input=source?first:second;
  for(int lane=0;lane<chunk/inputBytes;++lane) {
   int index=broadcast&&source?0:start+lane*inputBytes;
   int64_t value;
   if(inputBytes==4) {int32_t v;memcpy(&v,input+index,4);value=v;}
   else {int16_t v;memcpy(&v,input+index,2);value=v;}
   if(value<minimum) value=minimum;
   if(value>maximum) value=maximum;
   uint32_t result=(uint32_t)value;
   int destination=start+source*(chunk/2)+lane*outputBytes;
   for(int byte=0;byte<outputBytes;++byte) out[destination+byte]=(uint8_t)(result>>(byte*8));
  }
 }
}
`

func x86NarrowIndependentAssembly(name string, row x86NarrowOracleRow) string {
	var assembly strings.Builder
	fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-52\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nMOVQ mask+32(FP),R9\n", name)
	// Prepare status before entering the uninterrupted physical MMX region.
	assembly.WriteString("LDMXCSR csr+48(FP)\nPUSHQ flags+40(FP)\nPOPFQ\n")
	if row.bank == "M" {
		assembly.WriteString("MOVQ (CX),M0\nMOVQ (DX),M1\n")
	} else {
		assembly.WriteString("VMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (R8),Z2\nKMOVQ R9,K1\n")
	}
	instruction, destination := row.instruction()
	fmt.Fprintln(&assembly, instruction)
	if row.bank == "M" {
		fmt.Fprintf(&assembly, "MOVQ %s,(AX)\nEMMS\n", destination)
	} else {
		fmt.Fprintf(&assembly, "VMOVUPS Z%s,(AX)\n", destination[1:])
	}
	assembly.WriteString("PUSHFQ\nPOPQ R10\nMOVQ R10,64(AX)\nSTMXCSR 72(AX)\nRET\n")
	return assembly.String()
}

func TestCrossLinuxRuntimeMatrixX86PackedNarrowIndependentWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	rows := x86NarrowOracleRows()
	var assembly, declarations, table, main strings.Builder
	declarations.WriteString("package narroworacle\n")
	main.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*kernel)(void*,const void*,const void*,const void*,uint64_t,uint64_t,uint32_t);
`)
	for index, row := range rows {
		name := fmt.Sprintf("numeric%d", index)
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b,old *[64]byte,mask,flags uint64,csr uint32)\n", name)
		assembly.WriteString(x86NarrowIndependentAssembly(name, row))
		fmt.Fprintf(&main, "extern void %s(void*,const void*,const void*,const void*,uint64_t,uint64_t,uint32_t);\n", name)
		fmt.Fprintf(&table, "{%s,%d,%d,%t,%d,%d,%d,%t},\n", name, row.width, row.family.inputBytes,
			row.family.unsigned, row.source, row.alias, row.masking, row.legacy)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	main.WriteString("static const struct {kernel run;int width,bytes,uns,source,alias,masking,legacy;} cases[]={\n" + table.String() + "};\n")
	main.WriteString(x86NarrowIndependentCReference)
	main.WriteString(`
int main(void) {
 unsigned saved;__asm__ volatile("stmxcsr %0":"=m"(saved));
 const uint32_t profiles[]={0x1f80,0x3fc1,0x5f82,0x9fe5};
 unsigned long long observations=0;
 for(unsigned row=0;row<sizeof(cases)/sizeof(cases[0]);++row) {
  int lanes=cases[row].width/(cases[row].bytes/2);
  for(unsigned sample=0;sample<32;++sample) for(int select=0;select<lanes+4;++select)
  for(unsigned profile=0;profile<4;++profile) for(unsigned seed=0;seed<2;++seed) {
   _Alignas(64) uint8_t a[64],b[64],old[64],beforeA[64],beforeB[64],beforeOld[64];
   uint8_t output[82],want[82],packed[64];
   fill(a,cases[row].bytes,sample,0);fill(b,cases[row].bytes,sample,13);
   for(int i=0;i<64;++i) old[i]=(uint8_t)(0x91+i*11);
   memcpy(beforeA,a,64);memcpy(beforeB,b,64);memcpy(beforeOld,old,64);
   memset(output,0xc3,sizeof(output));memcpy(want,output,sizeof(want));
   uint64_t mask;
   if(select==0) mask=0;
   else if(select==1) mask=UINT64_MAX;
   else if(select==2) mask=UINT64_C(0xaaaaaaaaaaaaaaaa);
   else if(select==3) mask=lanes==64?0:UINT64_MAX<<lanes;
   else mask=UINT64_C(1)<<(select-4);
   uint64_t flags=2|(seed?0x8d5:0);
   cases[row].run(output+1,a,b,old,mask,flags,profiles[profile]);
   const uint8_t *first=cases[row].legacy&&cases[row].alias?b:a;
   independent_pack(packed,first,b,cases[row].width,cases[row].bytes,cases[row].uns,cases[row].source==2);
   const uint8_t *previous=cases[row].legacy?b:cases[row].alias==0?a:cases[row].alias==1?b:old;
   for(int i=0;i<64;++i) {
    uint8_t value=cases[row].width==8?0xc3:cases[row].legacy?previous[i]:0;
    if(i<cases[row].width) {
     value=packed[i];
     if(cases[row].masking&&!(mask>>(i/(cases[row].bytes/2))&1))
      value=cases[row].masking==2?0:previous[i];
    }
    want[1+i]=value;
   }
   uint64_t observedFlags;uint32_t observedCSR;
   memcpy(&observedFlags,output+65,8);memcpy(want+65,&observedFlags,8);
   memcpy(&observedCSR,output+73,4);memcpy(want+73,&observedCSR,4);
   ++observations;
   if((observedFlags&0x8d5)!=(flags&0x8d5)||observedCSR!=profiles[profile]||
      memcmp(output,want,sizeof(output))||memcmp(a,beforeA,64)||memcmp(b,beforeB,64)||memcmp(old,beforeOld,64)) {
    fprintf(stderr,"PACK row=%u width=%d inputBytes=%d unsigned=%d source=%d alias=%d masking=%d legacy=%d sample=%u mask=%llx flags=%llx csr=%x\n",
      row,cases[row].width,cases[row].bytes,cases[row].uns,cases[row].source,cases[row].alias,cases[row].masking,
      cases[row].legacy,sample,(unsigned long long)mask,(unsigned long long)observedFlags,observedCSR);
    for(unsigned i=0;i<sizeof(output);++i) if(output[i]!=want[i]) fprintf(stderr,"byte%u got=%u want=%u\n",i,output[i],want[i]);
    return 1;
   }
  }
 }
 __asm__ volatile("ldmxcsr %0"::"m"(saved));
 printf("PACK kernels=%zu observations=%llu fullAliasBytes=64 statusMask=8d5\n",sizeof(cases)/sizeof(cases[0]),observations);
 return 0;
}
`)
	// C booleans are numeric metadata, not instruction/property producers.
	cSource := strings.NewReplacer(",true,", ",1,", ",false,", ",0,", ",true}", ",1}", ",false}", ",0}").Replace(main.String())
	observations := 0
	for _, row := range rows {
		observations += (row.width/(row.family.inputBytes/2) + 4) * 32 * 4 * 2
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86MulDivRoundOptimize(t, input)
			}
			output := execution.compileAndRunLLVM(t, "narrow-independent-numeric", input, cSource, level)
			want := fmt.Sprintf("PACK kernels=%d observations=%d fullAliasBytes=64 statusMask=8d5\n", len(rows), observations)
			if string(output) != want {
				t.Fatalf("incomplete independent numerical denominator: %q want %q", output, want)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
	t.Logf("%d independent scalar-reference kernels: original SSE/MMX is a separate gate; VEX/EVEX software is not native ISA execution", len(rows))
}

func TestCrossLinuxRuntimeMatrixX86PackedNarrowOriginalLegacyOracle(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, table strings.Builder
	declarations.WriteString("package narroworacle\n")
	count := 0
	for _, row := range x86NarrowOracleRows() {
		if !row.legacy {
			continue // Actual AVX/AVX512 kernels require an independent native ISA axis.
		}
		name := fmt.Sprintf("original%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(out *[32]byte,a,b *[64]byte,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-36\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nSTMXCSR saved-4(SP)\nLDMXCSR csr+32(FP)\n", name)
		move := "MOVOU"
		if row.bank == "M" {
			move = "MOVQ"
		}
		fmt.Fprintf(&assembly, "%s (CX),%s0\n%s (DX),%s1\nPUSHQ flags+24(FP)\nPOPFQ\n", move, row.bank, move, row.bank)
		instruction, destination := row.instruction()
		fmt.Fprintf(&assembly, "%s\n%s %s,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,16(AX)\nSTMXCSR 24(AX)\n", instruction, move, destination)
		if row.bank == "M" {
			assembly.WriteString("EMMS\n")
		}
		assembly.WriteString("LDMXCSR saved-4(SP)\nRET\n")
		fmt.Fprintf(&table, "{%s,%d,%d,%t,%d},\n", name, row.width, row.family.inputBytes, row.family.unsigned, row.alias)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	// A Go caller invokes the unchanged assembled body. Its expectation is an
	// independent signed scalar clamp, not the translated IR or a native intrinsic.
	tests := `package narroworacle
import("testing";"encoding/binary";"runtime";"unsafe")
type kernel func(*[32]byte,*[64]byte,*[64]byte,uint64,uint32)
var cases=[]struct{run kernel;width,bytes int;unsigned bool;alias int}{
` + table.String() + `}
var edges=[]int64{
 -2147483648,-65537,-32769,-32768,-32767,-257,-256,-129,-128,-127,-1,0,1,
 126,127,128,129,254,255,256,257,32766,32767,32768,32769,65534,65535,65536,65537,2147483646,2147483647}
func aligned(buffer *[128]byte)*[64]byte {
 offset:=int((-uintptr(unsafe.Pointer(&buffer[0])))&63)
 return (*[64]byte)(unsafe.Pointer(&buffer[offset]))
}
func fill(out *[64]byte,bytes,sample,salt int) {
 for lane:=0;lane<64/bytes;lane++ {
  value:=edges[(sample+salt+lane*7)%len(edges)]
  if bytes==4 {binary.LittleEndian.PutUint32(out[lane*bytes:],uint32(value))
  } else {binary.LittleEndian.PutUint16(out[lane*bytes:],uint16(value))}
 }
}
func reference(first,second *[64]byte,width,bytes int,unsigned bool)[16]byte {
 var out [16]byte
 half:=width/2; outputBytes:=bytes/2
 minimum:=-(int64(1)<<(outputBytes*8-1));maximum:=(int64(1)<<(outputBytes*8-1))-1
 if unsigned {minimum=0;maximum=(int64(1)<<(outputBytes*8))-1}
 for source:=0;source<2;source++ {
  input:=second;if source==1 {input=first}
  for lane:=0;lane<width/bytes;lane++ {
   var value int64
   if bytes==4 {value=int64(int32(binary.LittleEndian.Uint32(input[lane*bytes:])))
   } else {value=int64(int16(binary.LittleEndian.Uint16(input[lane*bytes:])))}
   if value<minimum {value=minimum};if value>maximum {value=maximum}
   for byteIndex:=0;byteIndex<outputBytes;byteIndex++ {
    out[source*half+lane*outputBytes+byteIndex]=byte(uint64(value)>>(byteIndex*8))
   }
  }
 }
 return out
}
func TestOriginal(t *testing.T) {
 runtime.LockOSThread();defer runtime.UnlockOSThread()
 profiles:=[]uint32{0x1f80,0x3fc1,0x5f82,0x9fe5}
 var aa,bb [128]byte
 a,b:=aligned(&aa),aligned(&bb)
 observations:=0
 for row,entry:=range cases {for sample:=0;sample<32;sample++ {for _,csr:=range profiles {for seed:=0;seed<2;seed++ {
  for i:=range aa {aa[i]=0xa7;bb[i]=0xb9}
  fill(a,entry.bytes,sample,0);fill(b,entry.bytes,sample,13)
  beforeA,beforeB:=aa,bb
  var output,want [34]byte
  for i:=range output {output[i]=0xc3;want[i]=0xc3}
  flags:=uint64(2);if seed!=0 {flags|=0x8d5}
  entry.run((*[32]byte)(unsafe.Pointer(&output[1])),a,b,flags,csr)
  first:=a;if entry.alias!=0 {first=b}
  packed:=reference(first,b,entry.width,entry.bytes,entry.unsigned)
  copy(want[1:1+entry.width],packed[:entry.width])
  observed:=binary.LittleEndian.Uint64(output[17:25]);copy(want[17:29],output[17:29])
  actualCSR:=binary.LittleEndian.Uint32(output[25:29])
  observations++
  if output!=want||aa!=beforeA||bb!=beforeB||observed&0x8d5!=flags&0x8d5||actualCSR!=csr {
   t.Fatalf("original PACK row%d sample%d width%d signedInputBytes%d flags%x csr%x got%x want%x",row,sample,entry.width,entry.bytes,observed,actualCSR,output,want)
  }
 }}}}
 t.Logf("original SSE/MMX kernels=%d observations=%d sixFlags/fullCSR/input-output-canaries",len(cases),observations)
}
`
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module narroworacle\n\ngo 1.20\n", "value.go": declarations.String(),
		"value_amd64.s": assembly.String(), "value_test.go": tests,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, gotoolchain.HostExecutable("original"))
	command := exec.Command("go", "test", "-c", "-p=2", "-vet=off", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0",
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOMAXPROCS=2")
	if output := x86FloatCompareCaptureCommand(t, command); len(output) != 0 {
		t.Logf("actual original Go build diagnostic (unchanged bytes):\n%s", output)
	}
	output := execution.run(t, executable, "-test.v", "-test.run=^TestOriginal$", "-test.count=1")
	want := fmt.Sprintf("original SSE/MMX kernels=%d observations=%d sixFlags/fullCSR/input-output-canaries", count, count*32*4*2)
	if !strings.Contains(string(output), want) || !strings.Contains(string(output), "--- PASS: TestOriginal") ||
		strings.Contains(string(output), "SKIP") {
		t.Fatalf("incomplete original-Go oracle denominator: %q", output)
	}
	t.Log(strings.TrimSpace(string(output)))
	t.Logf("%d actual stock Go SSE/MMX kernels; no VEX/EVEX original code executed", count)
}

var x86NarrowOracleFamilies = []x86NarrowOracleFamily{
	{"PACKSSLW", "VPACKSSDW", 4, false},
	{"PACKSSWB", "VPACKSSWB", 2, false},
	{"PACKUSDW", "VPACKUSDW", 4, true},
	{"PACKUSWB", "VPACKUSWB", 2, true},
}

func x86NarrowOracleIR(t *testing.T, source, declarations, triple string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "narroworacle", declarations)
	sigs := make(map[string]FuncSig)
	for _, function := range file.Funcs {
		name := strings.TrimPrefix(function.Sym, "·")
		object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			t.Fatal("independent source lacks its declaration", name)
		}
		sig, err := DeriveGoFuncABI0Signature(name, object, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sigs[name] = sig
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, Options{
		Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	return module.String()
}

// Intel SDM Vol. 2A, Table 2-50 and the PACK chapters classify these complete
// memory tuples as E4NF/E4NF.nb: a zero output mask does not suppress the read.
// No AVX/AVX512 original instruction is executed by this software LLVM oracle.
func TestCrossLinuxRuntimeMatrixX86PackedNarrowIndependentE4NF(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, table strings.Builder
	declarations.WriteString("package narroworacle\n")
	count := 0
	for _, family := range x86NarrowOracleFamilies {
		for widthIndex, bank := range []string{"X", "Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && family.inputBytes != 4 {
					continue
				}
				for _, zero := range []bool{false, true} {
					name := fmt.Sprintf("fault%d", count)
					count++
					op := family.vector
					bytes := 16 << widthIndex
					if broadcast {
						op += ".BCST"
						bytes = 4
					}
					if zero {
						op += ".Z"
					}
					fmt.Fprintf(&declarations, "func %s(input *byte)\n", name)
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-8\nMOVQ input+0(FP),AX\nVPXORD %s0,%s0,%s0\nMOVL $0,CX\nKMOVQ CX,K1\n%s (AX),%s0,K1,%s1\nRET\n",
						name, bank, bank, bank, op, bank, bank)
					fmt.Fprintf(&table, "{observe%d, %d, %d},\n", count-1, bytes, bytes-1)
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	var main strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&main, "extern void fault%d(const uint8_t*);\n", index)
		fmt.Fprintf(&main, `static int observe%d(const uint8_t *input) {
    fault%d(input);
    return 0;
}
`, index, index)
	}
	driver := x86MemoryFaultDriver(main.String(), table.String())
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := execution.compileLLVM(t, "narrow-independent-e4nf", ir, driver, level)
			x86CheckMemoryFaultMatrix(t, execution, executable, count)
		})
	}
}
