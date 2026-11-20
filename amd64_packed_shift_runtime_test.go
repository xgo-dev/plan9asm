package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type x86PackedShiftNumericalCase struct {
	name, row                                                        string
	width, bits, countMode, immediate, memory, maskMode, destination int
	left, legacy, broadcast                                          bool
}

// This oracle registration is derived from the mnemonic spelling, not the
// production mode/width map. All bits, inactive lanes and upper aliases matter.
func x86PackedShiftNumericalCases() []x86PackedShiftNumericalCase {
	var cases []x86PackedShiftNumericalCase
	for _, op := range x86PackedShiftNames() {
		legacy := !strings.HasPrefix(op, "V")
		byteShift := strings.HasSuffix(op, "DQ") || op == "PSLLO" || op == "PSRLO"
		perLane := strings.Contains(op, "LLV") || strings.Contains(op, "RLV")
		bits := 32
		if strings.HasSuffix(op, "W") {
			bits = 16
		}
		if strings.HasSuffix(op, "Q") {
			bits = 64
		}
		if byteShift {
			bits = 8
		}
		widths := []int{16, 32, 64}
		if legacy {
			widths = widths[:1]
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, memory := range []int{0, 1, 2} {
				if legacy && byteShift && memory != 0 {
					continue
				}
				if memory == 2 && (legacy || byteShift || bits == 16) {
					continue
				}
				for _, mask := range []int{0, 1, 2} {
					if mask != 0 && (legacy || byteShift) {
						continue
					}
					counts := []int{-1, 0, 1, bits - 1, bits, bits + 1, 255}
					if perLane {
						counts = []int{-1}
					}
					if byteShift {
						counts = []int{0, 1, 15, 16, 17, 255}
					}
					for _, immediate := range counts {
						if legacy && memory != 0 && immediate >= 0 {
							continue
						}
						if legacy && immediate == 255 {
							continue
						}
						if immediate < 0 && memory == 2 && !perLane {
							continue
						}
						for _, destination := range []int{0, 1, 2} {
							if legacy && destination != 0 {
								continue
							}
							// Boundary immediates need not multiply every mask/alias
							// combination; dynamic counts cover all boundaries below.
							if !legacy && !perLane && immediate != 1 && immediate != -1 && (mask != 0 || destination != 2) {
								continue
							}
							name := fmt.Sprintf("shift%d", len(cases))
							operation := op
							if memory == 2 {
								operation += ".BCST"
							}
							if mask == 2 {
								operation += ".Z"
							}
							count := "$" + fmt.Sprint(immediate)
							data := bank + "0"
							mode := 0
							if immediate < 0 {
								count = "X1"
								if perLane {
									count, mode = bank+"1", 1
								}
								if memory != 0 {
									count = "(CX)"
								}
							} else if memory != 0 {
								data = "(BX)"
							}
							if byteShift {
								mode = 2
							}
							row := operation + " " + count + "," + data
							if !legacy {
								if mask != 0 {
									row += ",K1"
								}
								row += fmt.Sprintf(",%s%d", bank, destination)
							}
							cases = append(cases, x86PackedShiftNumericalCase{
								name: name, row: row, width: width, bits: bits, countMode: mode,
								immediate: immediate, memory: memory, maskMode: mask, destination: destination,
								left: strings.Contains(op, "SLL"), legacy: legacy, broadcast: memory == 2,
							})
						}
					}
				}
			}
		}
	}
	return cases
}

func x86PackedShiftNumericalAssembly(cases []x86PackedShiftNumericalCase) (string, map[string]FuncSig) {
	var assembly strings.Builder
	sigs := map[string]FuncSig{}
	for _, test := range cases {
		fmt.Fprintf(&assembly, `TEXT %s(SB),4,$0-40
MOVQ out+0(FP),AX
MOVQ data+8(FP),BX
MOVQ count+16(FP),CX
MOVQ mask+24(FP),DX
MOVQ seed+32(FP),SI
VMOVUPS (BX),Z0
VMOVUPS (CX),Z1
VMOVUPS (CX),Z2
KMOVQ DX,K1
CMPQ SI,$0
JE carry
CMPQ SI,$1
JE overflow
MOVQ $1,SI
CMPQ SI,$0
JMP shifted
carry:
MOVQ $-1,SI
ADDQ $1,SI
JMP shifted
overflow:
MOVQ $0x7fffffffffffffff,SI
ADDQ $1,SI
shifted:
%s
VMOVUPS Z%d,(AX)
SETCS 64(AX)
SETOS 65(AX)
SETEQ 66(AX)
SETMI 67(AX)
SETPS 68(AX)
RET
`, test.name, test.row, test.destination)
		sigs[test.name] = FuncSig{Name: test.name, Args: []LLVMType{Ptr, Ptr, Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}}}
	}
	return assembly.String(), sigs
}

const x86PackedShiftIndependentC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*shift_fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint64_t);
struct shift_case { shift_fn fn; const char *row; int width,bits,mode,immediate,memory,mask,destination,left,legacy,broadcast; };
static uint64_t read_le(const uint8_t *p,int bytes) {
 uint64_t value=0;
 for(int i=0;i<bytes;++i) value|=(uint64_t)p[i]<<(8*i);
 return value;
}
static void expected(uint8_t *out,const uint8_t *a,const uint8_t *counts,uint64_t mask,const struct shift_case *c) {
 const uint8_t *old=c->destination==0?a:counts;
 memcpy(out,old,64);
 if(!c->legacy) memset(out+c->width,0,64-c->width);
 if(c->mode==2) {
  for(int i=0;i<c->width;++i) {
   int offset=i%16, from=c->left ? offset-c->immediate : offset+c->immediate;
   out[i]=from>=0 && from<16 ? a[i-offset+from] : 0;
  }
  return;
 }
 int bytes=c->bits/8;
 for(int i=0;i<c->width;i+=bytes) {
  if(c->mask && !((mask>>(i/bytes))&1)) {
   if(c->mask==2) memset(out+i,0,bytes);
   continue;
  }
  uint64_t count=c->immediate>=0?(uint64_t)c->immediate:read_le(counts+(c->mode==1 && !c->broadcast?i:0),c->mode==1?bytes:8);
  uint64_t value=read_le(a+(c->broadcast && c->immediate>=0?0:i),bytes);
  uint64_t result=0;
  if(count<(uint64_t)c->bits) result=c->left?value<<count:value>>count;
  for(int b=0;b<bytes;++b) out[i+b]=(uint8_t)(result>>(8*b));
 }
}
static int check_case(const struct shift_case *c,int index) {
 const uint64_t limits[]={0,1,7,15,16,17,31,32,33,63,64,65,255,256,UINT64_C(1)<<32,UINT64_MAX};
 const uint64_t masks[]={0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
 const uint8_t flags[3][5]={{1,0,1,0,1},{0,1,0,1,1},{0,0,0,0,0}};
 for(unsigned round=0;round<16;++round) for(unsigned m=0;m<4;++m) for(unsigned seed=0;seed<3;++seed) {
  uint8_t aStorage[66],storage[71],beforeA[66],want[64];
  _Alignas(16) uint8_t countStorage[96],beforeCount[96];
  uint8_t *a=aStorage+1,*counts=countStorage+(c->legacy?16:3),*out=storage+1;
  memset(aStorage,0xa7,sizeof(aStorage)); memset(countStorage,0xb9,sizeof(countStorage)); memset(storage,0xc3,sizeof(storage));
  for(int i=0;i<64;++i) { a[i]=(uint8_t)(i*71+round*97+13); counts[i]=(uint8_t)(i*43+19); }
  int bytes=c->bits/8;
  for(int i=0;i<64;i+=bytes) {
   uint64_t count=limits[(round+i/bytes)%16];
   if(c->mode!=1) count=limits[round];
   for(int b=0;b<bytes;++b) counts[i+b]=(uint8_t)(count>>(8*b));
  }
  if(c->mode==0) for(int b=0;b<8;++b) counts[b]=(uint8_t)(limits[round]>>(8*b));
  memcpy(beforeA,aStorage,sizeof(beforeA)); memcpy(beforeCount,countStorage,sizeof(beforeCount));
  expected(want,a,counts,masks[m],c);
  c->fn(out,a,counts,masks[m],seed);
  if(memcmp(want,out,64) || memcmp(flags[seed],out+64,5) || storage[0]!=0xc3 || storage[70]!=0xc3 ||
     memcmp(aStorage,beforeA,sizeof(beforeA)) || memcmp(countStorage,beforeCount,sizeof(beforeCount))) {
   for(int i=0;i<69;++i) if(out[i]!=(i<64?want[i]:flags[seed][i-64])) {
    fprintf(stderr,"case=%d %s round=%u mask=%u seed=%u byte=%d actual=%02x expected=%02x\n",index,c->row,round,m,seed,i,out[i],i<64?want[i]:flags[seed][i-64]); break;
   }
   return 1;
  }
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86PackedLogicalShiftCompleteSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires Linux/amd64 runtime counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	cases := x86PackedShiftNumericalCases()
	assembly, sigs := x86PackedShiftNumericalAssembly(cases)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	var driver strings.Builder
	driver.WriteString(x86PackedShiftIndependentC)
	for _, c := range cases {
		fmt.Fprintf(&driver, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint64_t);\n", c.name)
	}
	driver.WriteString("static const struct shift_case cases[]={\n")
	for _, c := range cases {
		fmt.Fprintf(&driver, "{%s,%q,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", c.name, c.row, c.width, c.bits, c.countMode, c.immediate, c.memory, c.maskMode, c.destination, x86ShiftBoolean(c.left), x86ShiftBoolean(c.legacy), x86ShiftBoolean(c.broadcast))
	}
	driver.WriteString("};\nint main(void) { for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) if(check_case(cases+i,i)) return 1; return 0; }\n")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_shift_complete", triple, ir, driver.String(), prefix)
	t.Logf("%d exact opcode/width/count/memory/mask/alias programs, 192 whole-byte/flags/canary inputs each; Rosetta=%t", len(cases), crossRosetta)
}

func x86ShiftBoolean(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestX86PackedShiftActualGoLegacyNumericalOracle(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires Linux/amd64 native Go counterpart")
	}
	var source, assembly, tests strings.Builder
	source.WriteString("package original\nimport \"unsafe\"\n")
	tests.WriteString(`package original
import ("testing"; "unsafe")
func TestNumeric(t *testing.T) {
 counts:=[]uint64{0,1,7,15,16,17,31,32,33,63,64,65,255,256,1<<32,^uint64(0)}
 flags:=[3][5]byte{{1,0,1,0,1},{0,1,0,1,1},{0,0,0,0,0}}
`)
	for _, op := range []string{"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ", "PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ"} {
		name := strings.ToLower(op)
		bits := 32
		if strings.HasSuffix(op, "W") {
			bits = 16
		}
		if strings.HasSuffix(op, "Q") {
			bits = 64
		}
		byteShift := strings.HasSuffix(op, "DQ") || strings.HasSuffix(op, "O")
		fmt.Fprintf(&source, "func %s(out,data,count unsafe.Pointer,seed uint64)\n", name)
		row := op + " X1,X0"
		if byteShift {
			row = op + " $7,X0"
		}
		fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-32
MOVQ out+0(FP),AX
MOVQ data+8(FP),BX
MOVQ count+16(FP),CX
MOVQ seed+24(FP),DX
MOVOU (BX),X0
MOVOU (CX),X1
CMPQ DX,$0
JE carry
CMPQ DX,$1
JE overflow
MOVQ $1,DX
CMPQ DX,$0
JMP shifted
carry:
MOVQ $-1,DX
ADDQ $1,DX
JMP shifted
overflow:
MOVQ $0x7fffffffffffffff,DX
ADDQ $1,DX
shifted:
%s
MOVOU X0,(AX)
SETCS 16(AX)
SETOS 17(AX)
SETEQ 18(AX)
SETMI 19(AX)
SETPS 20(AX)
RET
`, name, row)
		fmt.Fprintf(&tests, `for round,count:=range counts {
 for seed:=0;seed<3;seed++ {
 var data,countData [18]byte
 var out [23]byte
 for i:=range data { data[i]=byte(i*71+round*97+13); countData[i]=0xb9 }
 for i:=range out { out[i]=0xc3 }
 for i:=0;i<8;i++ { countData[i+1]=byte(count>>(8*i)) }
 %s(unsafe.Pointer(&out[1]),unsafe.Pointer(&data[1]),unsafe.Pointer(&countData[1]),uint64(seed))
 if out[0]!=0xc3 || out[22]!=0xc3 { t.Fatal("canary") }
 for i:=0;i<5;i++ { if out[17+i]!=flags[seed][i] { t.Fatalf("flags seed=%%d bit=%%d got=%%d",seed,i,out[17+i]) } }
 for i:=0;i<16;i++ {
  var want byte
`, name)
		if byteShift {
			from := "i-7"
			if strings.Contains(op, "SRL") {
				from = "i+7"
			}
			fmt.Fprintf(&tests, "from:=%s\nif from>=0 && from<16 { want=data[from+1] }\n", from)
		} else {
			operator := "<<"
			if strings.Contains(op, "SRL") {
				operator = ">>"
			}
			fmt.Fprintf(&tests, "offset:=(i/%d)*%d\nvar value uint64\nfor b:=0;b<%d;b++ { value|=uint64(data[offset+b+1])<<(8*b) }\nif count<%d { want=byte((value %s count)>>(8*(i%%%d))) }\n", bits/8, bits/8, bits/8, bits, operator, bits/8)
		}
		tests.WriteString("if out[i+1]!=want { t.Fatalf(\"byte %d got=%x want=%x\",i,out[i+1],want) }\n}\n}\n}\n")
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, bytes := range map[string]string{"go.mod": "module original\n\ngo 1.20\n", "original.go": source.String(), "original_amd64.s": assembly.String(), "original_test.go": tests.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(bytes), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go legacy shift: %v\n%s", err, output)
	}
	t.Logf("10 original Go SSE2 mnemonic/alias programs ×48 initialized/flags/canary inputs; Rosetta=%t", crossRosetta)
}
