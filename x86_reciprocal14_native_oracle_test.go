package plan9asm

// Original Go executes the same initialized source later sent to each public
// API. Its processor's approximation bits are the reference; independent
// projections, Intel special cases/error bound and MXCSR invariants still
// validate that reference. There is no exact-division replacement oracle.
const x86Reciprocal14NativeOriginalGo = `package oracle
import (
    "bytes"
    "encoding/binary"
    "math"
    "os"
    "runtime"
    "testing"
)
type kernel struct {
    id,member,bits,width,source,mode,low,upper,dynamic int
    run func(*[160]byte,*[64]byte,*[64]byte,*[64]byte,uint64,uint32,uint32)
}
type sample struct {row,pattern int; mask uint64; first,second uint32}
var kernels=[]kernel{@ROWS@}
var cases=[]sample{@CASES@}
var patterns32=[]uint64{
    0,0x80000000,0x7f800000,0xff800000,1,0x80000001,0x007fffff,0x807fffff,
    0x00800000,0x80800000,0x3f800000,0xbf800000,0x40800000,0xc0800000,
    0x3f123456,0xbf123456,0x7f7fffff,0xff7fffff,0x7e800000,0xfe800000,
    0x7fc12345,0xffc12345,0x7f812345,0xff812345,
}
var patterns64=[]uint64{
    0,0x8000000000000000,0x7ff0000000000000,0xfff0000000000000,1,0x8000000000000001,
    0x000fffffffffffff,0x800fffffffffffff,0x0010000000000000,0x8010000000000000,
    0x3ff0000000000000,0xbff0000000000000,0x4010000000000000,0xc010000000000000,
    0x3fe2468ace13579b,0xbfe2468ace13579b,0x7fefffffffffffff,0xffefffffffffffff,
    0x7fd0000000000000,0xffd0000000000000,0x7ff8123456789abc,0xfff8123456789abc,
    0x7ff0123456789abc,0xfff0123456789abc,
}
func put(p []byte,bits int,value uint64) {
    if bits==32 {binary.LittleEndian.PutUint32(p,uint32(value))} else {binary.LittleEndian.PutUint64(p,value)}
}
func get(p []byte,bits int) uint64 {
    if bits==32 {return uint64(binary.LittleEndian.Uint32(p))};return binary.LittleEndian.Uint64(p)
}
func buffers(k kernel,s int) (input,upper,old [64]byte) {
    for i:=range input {input[i]=byte(i*19+s*31+0xa5);upper[i]=byte(i*43+s*13+0x5a);old[i]=byte(i*53+s*17+0x69)}
    patterns:=patterns32;if k.bits==64 {patterns=patterns64}
    for lane:=0;lane<64/(k.bits/8);lane++ {put(input[lane*(k.bits/8):],k.bits,patterns[(s+lane)%24])}
    return
}
func valid(k kernel,input,output uint64,csr uint32) bool {
    fraction,exponent:=23,8
    if k.bits==64 {fraction,exponent=52,11}
    sign:=uint64(1)<<uint(k.bits-1)
    infinity:=(uint64(1)<<uint(exponent)-1)<<uint(fraction)
    magnitude:=input&^sign
    if magnitude&infinity==0 && csr&0x40!=0 {input&=sign;magnitude=0}
    if magnitude>infinity {return output&infinity==infinity && output&(uint64(1)<<uint(fraction-1))!=0}
    if magnitude==0 {return output==input&sign|infinity}
    rsqrt:=k.member>=4
    if rsqrt && input&sign!=0 {return output==sign|infinity|uint64(1)<<uint(fraction-1)}
    if magnitude==infinity {return output==input&sign}
    x,y:=math.Float64frombits(input),math.Float64frombits(output)
    smallest,largest:=math.SmallestNonzeroFloat64,math.MaxFloat64
    if k.bits==32 {x,y=float64(math.Float32frombits(uint32(input))),float64(math.Float32frombits(uint32(output)));smallest,largest=math.SmallestNonzeroFloat32,math.MaxFloat32}
    expected:=1/x;if rsqrt {expected=1/math.Sqrt(x)}
    if math.IsInf(expected,0) || math.Abs(expected)>largest {return output&^sign==infinity}
    if !rsqrt && csr&0x8000!=0 && math.Abs(expected)<smallest*float64(uint64(1)<<uint(fraction)) {return output==input&sign}
    if output&infinity==0 && magnitude&infinity==0 && expected==0 {return output==input&sign}
    return !math.IsNaN(y) && math.Abs((y-expected)/expected)<1.0/16384
}
func check(t *testing.T,k kernel,c sample,input,upper,old [64]byte,out [160]byte,ambient uint32) {
    t.Helper()
    registers:=[3][64]byte{input,upper,old}
    if k.source==0 {registers[k.low-16]=input}
    scalar:=k.member%4>=2
    for half:=0;half<=k.dynamic;half++ {
        csr:=c.first;if half==1 {csr=c.second}
        value:=out[half*64:(half+1)*64]
        lanes:=k.width*8/k.bits;if scalar {lanes=1}
        for lane:=0;lane<lanes;lane++ {
            offset:=lane*k.bits/8
            active:=k.mode==0 || c.mask&(uint64(1)<<uint(lane))!=0
            if active {
                source:=offset;if k.source==2 || scalar {source=0}
                if !valid(k,get(input[source:],k.bits),get(value[offset:],k.bits),csr) {t.Fatalf("native estimate outside specification row=%d lane=%d sample=%d csr=%x input=%x output=%x",k.id,lane,c.pattern,csr,get(input[source:],k.bits),get(value[offset:],k.bits))}
            } else {
                expected:=uint64(0);if k.mode==1 {expected=get(registers[2][offset:],k.bits)}
                if get(value[offset:],k.bits)!=expected {t.Fatal("native mask projection",k.id,lane)}
            }
        }
        end:=k.width
        if scalar {
            end=16
            if !bytes.Equal(value[k.bits/8:16],registers[k.upper-16][k.bits/8:16]) {t.Fatal("native scalar upper copy",k.id)}
        }
        for _,b:=range value[end:] {if b!=0 {t.Fatal("native wider alias was not zero",k.id)}}
    }
    if binary.LittleEndian.Uint32(out[128:])!=ambient || binary.LittleEndian.Uint32(out[132:])!=0xc95 || binary.LittleEndian.Uint32(out[136:])!=c.first {t.Fatal("native first FLAGS/MXCSR",k.id)}
    if k.dynamic!=0 {
        if binary.LittleEndian.Uint32(out[140:])!=c.second || binary.LittleEndian.Uint32(out[144:])!=0xc95 {t.Fatal("native second FLAGS/MXCSR",k.id)}
    } else {
        for _,b:=range out[64:128] {if b!=0xc3 {t.Fatal("native output canary",k.id)}}
        for _,b:=range out[140:148] {if b!=0xc3 {t.Fatal("native control canary",k.id)}}
    }
    for _,b:=range out[148:] {if b!=0xc3 {t.Fatal("native tail canary",k.id)}}
}
func TestOriginal(t *testing.T) {
    runtime.LockOSThread();defer runtime.UnlockOSThread()
    saved:=MXCSR(0x1f80);defer MXCSR(saved)
    byID:=map[int]kernel{};for _,k:=range kernels {if _,exists:=byID[k.id];exists {t.Fatal("duplicate row")};byID[k.id]=k}
    trace:=[]byte("R14TRACE")
    append32:=func(x uint32) {var b [4]byte;binary.LittleEndian.PutUint32(b[:],x);trace=append(trace,b[:]...)}
    append32(1);append32(uint32(len(cases)))
    rounding:=map[[4]uint64][64]byte{}
    for index,c:=range cases {
        k,exists:=byID[c.row];if !exists {t.Fatal("foreign case row")}
        input,upper,old:=buffers(k,c.pattern)
        beforeInput,beforeUpper,beforeOld:=input,upper,old
        var out [160]byte;for i:=range out {out[i]=0xc3}
        ambient:=uint32(0x1f80);if index%2!=0 {ambient=0x3f80}
        MXCSR(ambient);k.run(&out,&input,&upper,&old,c.mask,c.first,c.second)
        if after:=MXCSR(0x1f80);after!=ambient {t.Fatal("ambient MXCSR not restored",after,ambient)}
        if input!=beforeInput || upper!=beforeUpper || old!=beforeOld {t.Fatal("source canary changed")}
        check(t,k,c,input,upper,old,out,ambient)
        key:=[4]uint64{uint64(k.id),uint64(c.pattern),c.mask,uint64(c.first&0x8040)}
        var first [64]byte;copy(first[:],out[:64])
        if previous,seen:=rounding[key];seen && previous!=first {t.Fatal("native estimate changed with RC/status/exception masks",key)}
        rounding[key]=first
        append32(uint32(c.row));append32(uint32(c.pattern))
        append32(uint32(c.mask));append32(uint32(c.mask>>32));append32(c.first);append32(c.second)
        trace=append(trace,out[:]...)
    }
    if err:=os.WriteFile(@TRACE@,trace,0600);err!=nil {t.Fatal(err)}
    t.Logf("actual original Go RCP14 rows=%d cases=%d complete bits/aliases/FLAGS/MXCSR/canaries",len(kernels),len(cases))
}
`

// The original-Go trace is read-only and identity checked before and after
// every candidate. This C fixture uses the existing compile/run process owner.
const x86Reciprocal14NativeValuesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
@PROTOTYPES@
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t,uint32_t,uint32_t);
static const struct {unsigned id;Kernel run;unsigned bits;} rows[]={@ROWS@};
static const uint64_t patterns[2][24]={
 {0,0x80000000,0x7f800000,0xff800000,1,0x80000001,0x007fffff,0x807fffff,
  0x00800000,0x80800000,0x3f800000,0xbf800000,0x40800000,0xc0800000,
  0x3f123456,0xbf123456,0x7f7fffff,0xff7fffff,0x7e800000,0xfe800000,
  0x7fc12345,0xffc12345,0x7f812345,0xff812345},
 {0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),1,UINT64_C(0x8000000000000001),
  UINT64_C(0x000fffffffffffff),UINT64_C(0x800fffffffffffff),UINT64_C(0x0010000000000000),UINT64_C(0x8010000000000000),
  UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x4010000000000000),UINT64_C(0xc010000000000000),
  UINT64_C(0x3fe2468ace13579b),UINT64_C(0xbfe2468ace13579b),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),
  UINT64_C(0x7fd0000000000000),UINT64_C(0xffd0000000000000),UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff8123456789abc),
  UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff0123456789abc)}
};
static uint32_t u32(const uint8_t *p) {return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t u64(const uint8_t *p) {return u32(p)|(uint64_t)u32(p+4)<<32;}
int main(void) {
    FILE *f=fopen(@TRACE@,"rb");uint8_t header[16];
    if (!f || fread(header,1,16,f)!=16 || memcmp(header,"R14TRACE",8) || u32(header+8)!=1 || u32(header+12)!=@COUNT@) return 1;
    for (unsigned caseID=0;caseID<@COUNT@;caseID++) {
        uint8_t record[184],input[64],upper[64],old[64],out[160];
        if (fread(record,1,sizeof(record),f)!=sizeof(record)) return 2;
        unsigned id=u32(record),sample=u32(record+4),index=0;
        while(index<sizeof(rows)/sizeof(rows[0]) && rows[index].id!=id) index++;
        if (index==sizeof(rows)/sizeof(rows[0]) || sample>=24) return 3;
        if (rows[index].bits!=32 && rows[index].bits!=64) return 4;
        unsigned precision=rows[index].bits==64,bytes=precision?8:4;
        for(unsigned i=0;i<64;i++) {input[i]=(uint8_t)(i*19+sample*31+0xa5);upper[i]=(uint8_t)(i*43+sample*13+0x5a);old[i]=(uint8_t)(i*53+sample*17+0x69);}
        for(unsigned lane=0;lane<64/bytes;lane++) {uint64_t value=patterns[precision][(sample+lane)%24];memcpy(input+lane*bytes,&value,bytes);}
        uint8_t beforeInput[64],beforeUpper[64],beforeOld[64];
        memcpy(beforeInput,input,64);memcpy(beforeUpper,upper,64);memcpy(beforeOld,old,64);memset(out,0xc3,160);
        unsigned ambient=caseID%2?0x3f80:0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(ambient):"memory");
        rows[index].run(out,input,upper,old,u64(record+8),u32(record+16),u32(record+20));
        unsigned after;__asm__ volatile("stmxcsr %0":"=m"(after));
        if (memcmp(out,record+24,160) || memcmp(input,beforeInput,64) || memcmp(upper,beforeUpper,64) || memcmp(old,beforeOld,64)) {
            fprintf(stderr,"RCP14 original-Go bit mismatch case=%u row=%u sample=%u\n",caseID,id,sample);
            return 5;
        }
        if (after!=ambient) return 7;
    }
    if (fgetc(f)!=EOF || ferror(f) || fclose(f)) return 6;
    printf("RCP14 native original-Go bits cases=%u failures=0\n",(unsigned)@COUNT@);
    return 0;
}
`

const x86Reciprocal14NativeFaultsC = `
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t,uint32_t,uint32_t);
static const struct {unsigned id;Kernel run;unsigned extent,lane,lanes,mode;} rows[]={@ROWS@};
__attribute__((target("@FEATURES@")))
static void original(unsigned row,const uint8_t *input,unsigned mask) {
    switch(row) {@ORIGINAL@ default:exit(86);}
}
int main(int argc,char **argv) {
    unsigned row,probe,native;char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&row,&tail)!=1 || sscanf(argv[2],"%u%c",&probe,&tail)!=1 ||
            sscanf(argv[3],"%u%c",&native,&tail)!=1 || row>=sizeof(rows)/sizeof(rows[0]) || probe>=10 || native>1) return 80;
    if (memory_fault_setup(0)) return 81;
    unsigned extent=rows[row].extent,lane=rows[row].lane,lanes=rows[row].lanes;
    const uint8_t *input=NULL;uint64_t mask=0;
    switch(probe) {
    case 0:break;
    case 1:mask=UINT64_C(1)<<lanes;break;
    case 2:mask=1;break;
    case 3:input=guard+page-extent;mask=0xffff;break;
    case 4:input=guard+page-extent+1;mask=0xffff;break;
    case 5:input=guard+page-lane;mask=1;break;
    case 6:input=guard+page-lane+1;mask=1;break;
    case 7:mask=UINT64_C(1)<<(lanes-1);break;
    case 8:input=guard+1;mask=0xffff;break;
    case 9:input=guard+page-extent;mask=0xffff;if(mprotect(guard,page,PROT_READ)) return 82;break;
    }
    uint8_t out[160],upper[64]={0},old[64]={0};memset(out,0xc3,sizeof(out));
    printf("memory enter %u %u %u\n",row,probe,native);
    if (fflush(stdout)) return 83;
    if (native) original(rows[row].id,input,(unsigned)mask);
    else rows[row].run(out,input,upper,old,mask,0x1f80,0x1f80);
    if (free_guard()) return 84;
    puts("memory complete");return fflush(stdout)?85:0;
}
`
