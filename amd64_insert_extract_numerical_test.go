package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86InsertExtractIndependentFPFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	const source = "TEXT fields(SB),4,$0-12\nPXOR X0,X0\nVINSERTPS $0,a+0(FP),X0,X1\nVEXTRACTPS $0,X1,ret+8(FP)\nRET\n" +
		"TEXT stores(SB),4,$0-12\nMOVL $0x87654321,CX\nMOVD CX,X1\nVEXTRACTPS $0,X1,a+0(FP)\nMOVBLZX a+0(FP),AX\nMOVBLZX b+1(FP),BX\nSHLL $8,BX\nORL BX,AX\nMOVBLZX c+2(FP),BX\nSHLL $16,BX\nORL BX,AX\nMOVBLZX d+3(FP),BX\nSHLL $24,BX\nORL BX,AX\nMOVL AX,ret+8(FP)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	pkg := mustGoPackage(t, "oracle", "package oracle\nfunc fields(a,b,c,d byte) uint32\nfunc stores(a,b,c,d byte) uint32\n")
	sigs := map[string]FuncSig{}
	for _, name := range []string{"fields", "stores"} {
		decl := pkg.Types.Scope().Lookup(name).(*types.Func)
		sig, err := DeriveGoFuncABI0Signature(name, decl, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Frame.Params) != 4 || len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 8 {
			t.Fatalf("actual AMD64 ABI0 four-byte fields/result layout changed: %+v", sig.Frame)
		}
		sigs[name] = sig
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <stdio.h>
extern uint32_t fields(uint8_t,uint8_t,uint8_t,uint8_t);
extern uint32_t stores(uint8_t,uint8_t,uint8_t,uint8_t);
int main(void) {
 for(unsigned i=0;i<256;i++) {
  uint8_t a=i,b=i*37,c=i*59,d=i*71;
  uint32_t want=(uint32_t)a|((uint32_t)b<<8)|((uint32_t)c<<16)|((uint32_t)d<<24);
  uint32_t got=fields(a,b,c,d);
  if(got!=want){fprintf(stderr,"independent FP fields got=%x want=%x\n",got,want);return 1;}
  got=stores(a,b,c,d);
  if(got!=UINT32_C(0x87654321)){fprintf(stderr,"independent FP stores got=%x\n",got);return 2;}
 }
 return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "insert-extract-independent-fp", triple, ir, reference, prefix)
}

func x86InsertExtractNumericalRows() []string {
	rows := x86InsertExtractFormats()
	// Actual source/destination aliases plus every imm8 selector bit for the
	// PS forms. Chunk immediates ignore their high bits, independently tested.
	for _, row := range x86InsertExtractFormats() {
		if strings.Contains(row, "(BX)") || strings.Contains(row, "K1") || strings.Contains(row, "PS ") {
			continue
		}
		if strings.HasPrefix(row, "VINSERT") {
			rows = append(rows, strings.TrimSuffix(row, "2")+"1", strings.TrimSuffix(row, "2")+"0")
		} else {
			rows = append(rows, strings.TrimSuffix(row, "0")+"1")
		}
		rows = append(rows, strings.Replace(row, "$255", "$0", 1))
	}
	for _, imm := range []int{0, 16, 32, 48, 64, 128, 192, 1, 2, 4, 8, 15, 255} {
		rows = append(rows, fmt.Sprintf("VINSERTPS $%d,X0,X1,X2", imm), fmt.Sprintf("VINSERTPS $%d,(BX),X1,X1", imm), fmt.Sprintf("VEXTRACTPS $%d,X1,R8", imm))
		rows = append(rows, fmt.Sprintf("INSERTPS $%d,X0,X1", imm), fmt.Sprintf("INSERTPS $%d,(BX),X1", imm))
	}
	for lane := 0; lane < 4; lane++ {
		rows = append(rows, fmt.Sprintf("EXTRACTPS $%d,X1,R8", lane))
	}
	rows = append(rows, "INSERTPS $128,X1,X1", "INSERTPS $192,X1,X0", "INSERTPS $64,X0,X0")
	return rows
}

func x86InsertExtractRuntimeCheck(name string, parameters ...int) string {
	var call strings.Builder
	fmt.Fprintf(&call, "if(check(%s", name)
	for _, parameter := range parameters {
		fmt.Fprintf(&call, ",%d", parameter)
	}
	// Preserve the case identity in text; a process exit status must never
	// wrap a large generated index to zero on Unix.
	fmt.Fprintf(&call, ")) { fprintf(stderr, %q); return 1; }\n", name+" numerical/canary failure\n")
	return call.String()
}

func TestCrossLinuxRuntimeMatrixX86InsertExtractByteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	rows := x86InsertExtractNumericalRows()
	for index, row := range rows {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		op := strings.Fields(row)[0]
		insert, scalar, memory, masked := strings.Contains(op, "INSERT"), strings.HasSuffix(op, "PS"), strings.Contains(row, "(BX)"), strings.Contains(row, "K1")
		if !insert && memory && masked {
			continue // physical native E6NF objects are checked separately; AVX512 execution is not available here
		}
		chunk, width, laneBytes := 16, 32, 4
		if strings.Contains(op, "X8") || strings.Contains(op, "64X4") {
			chunk = 32
		}
		if strings.Contains(op, "64X") {
			laneBytes = 8
		}
		if strings.Contains(row, ",Z") {
			width = 64
		}
		if scalar {
			chunk, width = 4, 16
		}
		destination := ins.Args[len(ins.Args)-1]
		store := ""
		if destination.Kind == OpReg {
			if scalar && !insert {
				// AX is the output address, so choose a non-address GP result.
				row = strings.TrimSuffix(row, string(destination.Reg)) + "R8"
				store = "MOVQ R8,(AX)\n"
			} else {
				store = fmt.Sprintf("VMOVUPS %s,(AX)\n", x86CallerVectorRoot(destination.Reg))
			}
		} else {
			row = strings.Replace(row, "(BX)", "(AX)", 1)
		}
		name := fmt.Sprintf("transfer%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),R9\nKMOVQ R9,K1\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nSTC\n%s\n%sSETCS 64(AX)\nRET\n", name, row, store)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*,uint64_t);\n", name)
		checks.WriteString(x86InsertExtractRuntimeCheck(name,
			x86FloatAddSubBoolInt(insert), x86FloatAddSubBoolInt(scalar), chunk, width, laneBytes, int(ins.Args[0].Imm),
			x86FloatAddSubBoolInt(memory), x86FloatAddSubBoolInt(masked), x86FloatAddSubBoolInt(strings.Contains(op, ".Z")), x86FloatAddSubBoolInt(destination.Kind == OpReg), x86FloatAddSubBoolInt(!strings.HasPrefix(op, "V")),
			x86FloatAddSubBoolInt(ins.Args[1].Reg == "X1"), x86FloatAddSubBoolInt(!strings.HasPrefix(op, "V") && destination.Reg == "X0")))
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const reference = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef void(*transfer)(void*,const void*,const void*,uint64_t);
__attribute__((noinline)) static int check(transfer fn,int insert,int scalar,int chunk,int width,int laneBytes,unsigned imm,int memory,int masked,int zero,int reg,int legacy,int sourceB,int baseA) {
 const uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0xffffffffffffffff),UINT64_C(0xffff000000000000)};
 for(unsigned vector=0;vector<8;vector++)for(unsigned m=0;m<5;m++) {
  uint8_t as[67],bs[67],out[67],want[64],aCopy[67],bCopy[67];uint8_t *a=as+1,*b=bs+1;
  memset(as,0xa7,67);memset(bs,0xb9,67);memset(out,0xc3,67);
  for(unsigned i=0;i<64;i++){a[i]=(i*31+vector*17)^0x81;b[i]=(i*13+vector*29)^0x27;}
  memcpy(aCopy,as,67);memcpy(bCopy,bs,67);memset(want,reg&&!(scalar&&!insert)?0:0xc3,64);
  const uint8_t *base=baseA?a:b,*insertSource=sourceB?b:a;
  if(legacy&&insert)memcpy(want,base,64);
  unsigned offset=(imm&(width/chunk-1))*chunk;
  if(insert) {
   memcpy(want,base,width);
   if(scalar){offset=((imm>>4)&3)*4;memcpy(want+offset,insertSource+(memory?0:((imm>>6)&3)*4),4);
    for(unsigned lane=0;lane<4;lane++)if(imm&(1u<<lane))memset(want+lane*4,0,4);
   } else memcpy(want+offset,insertSource,chunk);
  } else {memcpy(want,b+offset,chunk);if(scalar&&reg)memset(want+4,0,4);}
  unsigned result=insert?width:chunk;
  if(masked)for(unsigned lane=0;lane<result/laneBytes;lane++)if(!(masks[m]&(UINT64_C(1)<<lane))) {
   if(zero)memset(want+lane*laneBytes,0,laneBytes);else memcpy(want+lane*laneBytes,(insert?b:a)+lane*laneBytes,laneBytes);
  }
  unsigned csr=0x9fc5,observed;__asm__ volatile("ldmxcsr %0"::"m"(csr));
  fn(out+1,a,b,masks[m]);__asm__ volatile("stmxcsr %0":"=m"(observed));
  for(unsigned i=0;i<64;i++)if(out[i+1]!=want[i]){fprintf(stderr,"transfer byte %u got=%x want=%x insert=%d scalar=%d chunk=%d width=%d imm=%u mask=%llx\n",i,out[i+1],want[i],insert,scalar,chunk,width,imm,(unsigned long long)masks[m]);return 1;}
  if(out[0]!=0xc3||out[65]!=1||out[66]!=0xc3||memcmp(as,aCopy,67)||memcmp(bs,bCopy,67)||observed!=csr)return 2;
 }
 return 0;
}
`
	main := reference + declarations.String() + "int main(void){\n" + checks.String() + "unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "insert-extract-byte-semantics", triple, ir, main, prefix)
	t.Logf("%d independent original-Go forms/aliases/immediates x40 byte/MXCSR/CF/upper-zero/input-output canary vectors", len(sigs))
}

func x86InactiveInsertFaultSource(name, row string) string {
	// Legacy INSERTPS preserves wider aliases even if all four X lanes are
	// zeroed. The following complete Z store must not observe unknown bytes.
	return fmt.Sprintf("TEXT %s(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ input+8(FP),BX\nMOVQ $0,CX\nKMOVQ CX,K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\nVMOVUPS Z2,(AX)\nRET\n", name, row)
}

func TestX86LegacyInsertCannotInventObservedUpperBytes(t *testing.T) {
	source := x86InactiveInsertFaultSource("fault", "INSERTPS $15,(BX),X2")
	const seed = "VPXORD Z2,Z2,Z2\n"
	if strings.Count(source, seed) != 1 {
		t.Fatal("complete legacy fault fixture lost its unique wide source definition")
	}
	source = strings.Replace(source, seed, "", 1)
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func fault(out,input *byte)", "amd64", target.triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("legacy X zeroing manufactured initialized Y/Z aliases", err)
				}
			})
		}
	}
}

func TestX86InactiveInsertFaultSourceDefinesEveryObservedVectorByte(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, row := range []string{
		"VINSERTF32X4.Z $1,(BX),Y1,K1,Y2", "VINSERTI64X4.Z $1,(BX),Z1,K1,Z2", "VINSERTPS $15,(BX),X1,X2", "INSERTPS $15,(BX),X2",
	} {
		source := x86InactiveInsertFaultSource("fault", row)
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
		for _, target := range x86RawReturnTargets {
			if target.arch != "amd64" {
				continue // These original fixture rows include AMD64 EVEX forms.
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func fault(out,input *byte)", "amd64", target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("original fault fixture observes undefined vector bytes", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86InsertInactiveMemoryStillFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, rows strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range []string{
		"VINSERTF32X4.Z $1,(BX),Y1,K1,Y2", "VINSERTI64X4.Z $1,(BX),Z1,K1,Z2", "VINSERTPS $15,(BX),X1,X2", "INSERTPS $15,(BX),X2",
	} {
		name := fmt.Sprintf("fault%d", index)
		source.WriteString(x86InactiveInsertFaultSource(name, row))
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*);\n", name)
		fmt.Fprintf(&declarations, `static int observe%d(const uint8_t *input) {
    uint8_t output[66];
    memset(output, 0xc3, sizeof(output));
    %s(output + 1, input);
    return output[0] != 0xc3 || output[65] != 0xc3;
}
`, index, name)
		width := []int{16, 32, 4, 4}[index]
		fmt.Fprintf(&rows, "{observe%d, %d, %d},\n", index, width, width/2)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := x86MemoryFaultDriver(declarations.String(), rows.String())
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := execution.compileLLVM(t, "insert-inactive-memory-fault", ir, main, level)
			x86CheckMemoryFaultMatrix(t, execution, executable, 4)
		})
	}
}
