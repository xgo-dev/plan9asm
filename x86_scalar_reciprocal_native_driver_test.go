package plan9asm

// The C reference executes the actual scalar opcode, then separately checks
// IEEE special classes and Intel's 1.5*2^-12 relative error bound. It is not a
// packed estimate, exact division/sqrt implementation, or translator helper.
const x86ScalarReciprocalNativeValuesC = `
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
%s
struct kernel {
    void (*run)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint32_t);
    int kind,source,base,dst;
};
static const struct kernel kernels[]={%s};
static const uint32_t patterns[]={
    0x00000000,0x80000000,0x7f800000,0xff800000,
    0x00000001,0x80000001,0x007fffff,0x807fffff,
    0x00800000,0x80800000,0x3f800000,0xbf800000,
    0x40800000,0xc0800000,0x3f123456,0xbf123456,
    0x7f7fffff,0xff7fffff,0x7e800000,0xfe800000,
    0x7fc12345,0xffc12345,0x7f812345,0xff812345,
};
static uint32_t reference(unsigned kind,uint32_t bits) {
    float source,result;
    memcpy(&source,&bits,4);
    switch (kind) {
    case 0: __asm__ volatile("rcpss %%1,%%0":"=x"(result):"x"(source));break;
    case 1: __asm__ volatile("rsqrtss %%1,%%0":"=x"(result):"x"(source));break;
    case 2: __asm__ volatile("vrcpss %%1,%%1,%%0":"=x"(result):"x"(source));break;
    default: __asm__ volatile("vrsqrtss %%1,%%1,%%0":"=x"(result):"x"(source));break;
    }
    memcpy(&bits,&result,4);
    return bits;
}
static int valid_estimate(unsigned kind,uint32_t input,uint32_t output) {
    uint32_t magnitude=input&0x7fffffff,sign=input&0x80000000;
    unsigned exponent=magnitude>>23;
    if (!exponent) return output==(sign|0x7f800000);
    if (magnitude>0x7f800000) return (output&0x7fc00000)==0x7fc00000;
    if ((kind&1) && sign) return output==0xffc00000;
    if (magnitude==0x7f800000) return output==sign;
    float source,result;
    memcpy(&source,&input,4);memcpy(&result,&output,4);
    double expected=(kind&1)?1.0/sqrt((double)source):1.0/(double)source;
    const double bound=1.5/4096.0;
    if (!(output&0x7fffffff))
        return !(kind&1) && (output&0x80000000)==sign && fabs(expected)<=FLT_MIN/(1.0-bound);
    if (!(output&0x7f800000) || (output&0x7f800000)==0x7f800000) return 0;
    return fabs(((double)result-expected)/expected)<=bound;
}
int main(void) {
    unsigned count=0,saved=_mm_getcsr();
    _mm_setcsr(0x1f80);
    for (unsigned row=0;row<sizeof(kernels)/sizeof(kernels[0]);row++) {
        struct kernel k=kernels[row];
        for (unsigned sample=0;sample<24;sample++) for (unsigned control=0;control<64;control++) {
            uint8_t storage[64],upper[32],old[32],out[64],expected[64],registers[3][32];
            uint8_t *input=storage+sample%%16;
            for (unsigned i=0;i<sizeof(storage);i++) storage[i]=(uint8_t)(i*19+sample*31+0xa5);
            for (unsigned i=0;i<32;i++) {
                upper[i]=(uint8_t)(i*43+sample*13+0x5a);
                old[i]=(uint8_t)(i*53+sample*17+0x69);
            }
            uint32_t bits=patterns[sample];memcpy(input,&bits,4);
            uint8_t beforeStorage[64],beforeUpper[32],beforeOld[32];
            memcpy(beforeStorage,storage,64);memcpy(beforeUpper,upper,32);memcpy(beforeOld,old,32);
            memcpy(registers[0],input,32);memcpy(registers[1],upper,32);memcpy(registers[2],old,32);
            if (k.source>=0) {
                memcpy(registers[k.source],&bits,4);
                memset(registers[k.source]+4,0,12); // Actual legacy MOVSS m32 setup.
            }
            memset(out,0xc3,64);memset(expected,0xc3,64);
            memcpy(expected+8,registers[k.dst],32);
            memcpy(expected+12,registers[k.base]+4,12);
            if (k.kind>=2) memset(expected+24,0,16);
            uint32_t scalar=reference(k.kind,bits),flags=0xc95,ambient=0x1f80;
            memcpy(expected+8,&scalar,4);memcpy(expected+40,&ambient,4);memcpy(expected+44,&flags,4);
            uint32_t profile=((control&3)<<13)|((control&4)<<4)|((control&8)<<12)|
                ((control&16)?0x3f:0)|((control&32)?0x1f80:0);
            memcpy(expected+48,&profile,4);
            _mm_setcsr(ambient);
            k.run(out,input,upper,old,profile);
            unsigned after=_mm_getcsr();_mm_setcsr(ambient);
            if (memcmp(out,expected,64) || after!=ambient || memcmp(storage,beforeStorage,64) ||
                    memcmp(upper,beforeUpper,32) || memcmp(old,beforeOld,32) || !valid_estimate(k.kind,bits,scalar)) {
                fprintf(stderr,"scalar estimate row=%%u sample=%%u control=%%u MXCSR=%%x expected=%%x scalar=%%x\n",
                    row,sample,control,after,ambient,scalar);
                for (unsigned i=0;i<64;i++) if (out[i]!=expected[i])
                    fprintf(stderr,"byte %%u got %%02x want %%02x\n",i,out[i],expected[i]);
                _mm_setcsr(saved);
                return 1;
            }
            count++;
        }
    }
    _mm_setcsr(saved);
    printf("scalar estimates whole32/FLAGS/DF/MXCSR/canary outcomes %%u failures 0\n",count);
    return 0;
}
`

const x86ScalarReciprocalNativeOriginalGo = `package oracle
import (
    "encoding/binary"
    "math"
    "runtime"
    "testing"
    "unsafe"
)
type kernel struct {
    run func(*[64]byte,*[32]byte,*[32]byte,*[32]byte,uint32)
    kind,source,base,dst int
}
var kernels=[]kernel{%s}
var references=[]func(uint32)uint32{Reference0,Reference1,Reference2,Reference3}
func validEstimate(kind int,input,output uint32) bool {
    sign,magnitude:=input&0x80000000,input&0x7fffffff
    switch {
    case magnitude<0x00800000:
        return output==sign|0x7f800000
    case magnitude>0x7f800000:
        return output&0x7fc00000==0x7fc00000
    case kind&1!=0 && sign!=0:
        return output==0xffc00000
    case magnitude==0x7f800000:
        return output==sign
    }
    inputValue:=float64(math.Float32frombits(input))
    expected:=1/inputValue
    if kind&1!=0 {expected=1/math.Sqrt(inputValue)}
    const bound=1.5/4096
    if output&0x7fffffff==0 {
        return kind&1==0 && output&0x80000000==sign && math.Abs(expected)<=0x1p-126/(1-bound)
    }
    if output&0x7f800000==0 || output&0x7f800000==0x7f800000 {return false}
    return math.Abs((float64(math.Float32frombits(output))-expected)/expected)<=bound
}
func TestOriginal(t *testing.T) {
    runtime.LockOSThread();defer runtime.UnlockOSThread()
    saved:=MXCSR(0x1f80);defer MXCSR(saved)
    patterns:=[]uint32{
        0x00000000,0x80000000,0x7f800000,0xff800000,
        0x00000001,0x80000001,0x007fffff,0x807fffff,
        0x00800000,0x80800000,0x3f800000,0xbf800000,
        0x40800000,0xc0800000,0x3f123456,0xbf123456,
        0x7f7fffff,0xff7fffff,0x7e800000,0xfe800000,
        0x7fc12345,0xffc12345,0x7f812345,0xff812345,
    }
    count:=0
    for row,k:=range kernels {
        for sample,bits:=range patterns {for control:=uint32(0);control<64;control++ {
            var storage [64]byte
            var upper,old [32]byte
            for i:=range storage {storage[i]=byte(i*19+sample*31+0xa5)}
            for i:=range upper {upper[i]=byte(i*43+sample*13+0x5a);old[i]=byte(i*53+sample*17+0x69)}
            input:=(*[32]byte)(unsafe.Pointer(&storage[sample%%16]))
            binary.LittleEndian.PutUint32(input[:],bits)
            beforeStorage,beforeUpper,beforeOld:=storage,upper,old
            registers:=[3][32]byte{*input,upper,old}
            if k.source>=0 {
                binary.LittleEndian.PutUint32(registers[k.source][:],bits)
                for i:=4;i<16;i++ {registers[k.source][i]=0}
            }
            var out,expected [64]byte
            for i:=range out {out[i],expected[i]=0xc3,0xc3}
            copy(expected[8:40],registers[k.dst][:])
            copy(expected[12:24],registers[k.base][4:16])
            if k.kind>=2 {for i:=24;i<40;i++ {expected[i]=0}}
            MXCSR(0x1f80)
            scalar:=references[k.kind](bits)
            binary.LittleEndian.PutUint32(expected[8:],scalar)
            binary.LittleEndian.PutUint32(expected[40:],0x1f80)
            binary.LittleEndian.PutUint32(expected[44:],0xc95)
            profile:=(control&3)<<13|(control&4)<<4|(control&8)<<12
            if control&16!=0 {profile|=0x3f}
            if control&32!=0 {profile|=0x1f80}
            binary.LittleEndian.PutUint32(expected[48:],profile)
            MXCSR(0x1f80)
            k.run(&out,input,&upper,&old,profile)
            after:=MXCSR(0x1f80)
            if out!=expected || after!=0x1f80 || storage!=beforeStorage || upper!=beforeUpper || old!=beforeOld ||
                    !validEstimate(k.kind,bits,scalar) {
                t.Fatalf("actual Go scalar row=%%d sample=%%d control=%%x got=%%x want=%%x MXCSR=%%x scalar=%%x",
                    row,sample,control,out,expected,after,scalar)
            }
            count++
        }}
    }
    if len(kernels)!=20 || count!=30720 {t.Fatal("incomplete original scalar basis",len(kernels),count)}
    t.Logf("actual original Go scalar whole32/FLAGS/DF/MXCSR/canary outcomes %%d failures 0",count)
}
`

const x86ScalarReciprocalNativeFaultsC = `
static void (*const kernels[])(const uint8_t *)={Dead0,Dead1,Dead2,Dead3};
int main(int argc,char **argv) {
    unsigned row,probe,original;char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&row,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 || sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            row>=4 || probe>=5 || original>1) return 80;
    if (memory_fault_setup(0)) return 81;
    const uint8_t *input=NULL;
    if (probe==1) input=guard+page-3;
    else if (probe==2 || probe==3) input=guard+page-4;
    else if (probe==4) input=guard+1;
    if (probe==3 && mprotect(guard,page,PROT_READ)) return 82;
    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 83;
    if (original) {
        switch (row) {
        case 0: __asm__ volatile("rcpss (%0),%%xmm0"::"r"(input):"xmm0","memory");break;
        case 1: __asm__ volatile("rsqrtss (%0),%%xmm0"::"r"(input):"xmm0","memory");break;
        case 2: __asm__ volatile("vrcpss (%0),%%xmm0,%%xmm0"::"r"(input):"xmm0","memory");break;
        case 3: __asm__ volatile("vrsqrtss (%0),%%xmm0,%%xmm0"::"r"(input):"xmm0","memory");break;
        }
    } else kernels[row](input);
    if (free_guard()) return 84;
    puts("memory complete");
    return fflush(stdout)?85:0;
}
`
