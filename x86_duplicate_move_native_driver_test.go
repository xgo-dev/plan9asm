package plan9asm

import "fmt"

func x86DuplicateNativeValuesC(prototypes, rows string) string {
	return fmt.Sprintf(x86DuplicateValuesC, prototypes, rows)
}

const x86DuplicateValuesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
%s
struct kernel {
    void (*run)(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);
    unsigned width,lane,odd,legacy,masked,zeroing;
};
static const struct kernel kernels[]={%s};
static const uint64_t patterns[]={0,UINT64_C(0x8000000000000000),
    UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),
    UINT64_C(0x7ff0000000000001),UINT64_C(0x7ff8000000000001),
    UINT64_C(0x7f8000017fc00001),UINT64_C(0xffffffff11223344)};
static const uint64_t masks[]={0,1,2,UINT64_C(0x5555555555555555),
    UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX};
int main(void) {
    unsigned count=0,saved=_mm_getcsr();
    for (unsigned row=0;row<sizeof(kernels)/sizeof(kernels[0]);row++) {
        struct kernel k=kernels[row];
        for (unsigned sample=0;sample<16;sample++) for (unsigned m=0;m<6;m++) {
            _Alignas(64) uint8_t storage[160],old[64],out[96],expected[96];
            uint8_t *input=storage+(k.legacy&&k.lane==4?0:sample%%16);
            memset(storage,0xa7,sizeof(storage));
            for (unsigned i=0;i<64;i++) old[i]=(uint8_t)(sample*19+i*43+0x5a);
            for (unsigned i=0;i<64;i+=8) {
                uint64_t word=patterns[(sample+i/8)%%8];
                for (unsigned j=0;j<8;j++) input[i+j]=(uint8_t)(word>>(j*8));
            }
            uint8_t beforeStorage[160],beforeOld[64];
            memcpy(beforeStorage,storage,sizeof(storage));memcpy(beforeOld,old,sizeof(old));
            memset(out,0xc3,sizeof(out));memset(expected,0xc3,sizeof(expected));
            memset(expected,0,64);
            if (k.legacy) memcpy(expected,old,64);
            for (unsigned byte=0;byte<k.width;byte++) {
                unsigned lane=byte/k.lane,selected=k.odd?(lane|1):(lane&~1u);
                if (!k.masked || (masks[m]>>lane&1)) expected[byte]=input[selected*k.lane+byte%%k.lane];
                else expected[byte]=k.zeroing?0:old[byte];
            }
            uint32_t flags=0x444,profile=0x1f80|((sample%%4)<<13)|(sample%%64);
            memcpy(expected+64,&flags,4);memcpy(expected+68,&profile,4);
            _mm_setcsr(profile);
            kernels[row].run(out,input,old,masks[m]);
            uint32_t after=_mm_getcsr();_mm_setcsr(saved);
            if (memcmp(out,expected,sizeof(out)) || after!=profile ||
                    memcmp(storage,beforeStorage,sizeof(storage)) || memcmp(old,beforeOld,sizeof(old))) {
                fprintf(stderr,"duplicate row=%%u sample=%%u mask=%%u MXCSR=%%x expected=%%x\n",row,sample,m,after,profile);
                for (unsigned byte=0;byte<sizeof(out);byte++) if (out[byte]!=expected[byte])
                    fprintf(stderr,"byte %%u got %%02x want %%02x\n",byte,out[byte],expected[byte]);
                return 1;
            }
            count++;
        }
    }
    printf("duplicate whole64/FLAGS/DF/MXCSR/canary outcomes %%u failures 0\n",count);
    return 0;
}
`

const x86DuplicateOriginalGo = `package oracle
import (
    "encoding/binary"
    "runtime"
    "testing"
    "unsafe"
)
type kernel struct {
    run func(*[96]byte,*[64]byte,*[64]byte,uint64)
    width,lane,odd,legacy,masked,zeroing int
}
var kernels=[]kernel{%s}
func TestOriginal(t *testing.T) {
    runtime.LockOSThread();defer runtime.UnlockOSThread()
    saved:=MXCSR(0x1f80);defer MXCSR(saved)
    patterns:=[]uint64{0,0x8000000000000000,0x7ff0000000000000,0xfff0000000000000,
        0x7ff0000000000001,0x7ff8000000000001,0x7f8000017fc00001,0xffffffff11223344}
    masks:=[]uint64{0,1,2,0x5555555555555555,0xaaaaaaaaaaaaaaaa,^uint64(0)}
    count:=0
    for row,k:=range kernels {
        for sample:=0;sample<16;sample++ {for _,mask:=range masks {
            var storage [128]byte
            offset:=int((16-uintptr(unsafe.Pointer(&storage[0]))%%16)%%16)
            input:=(*[64]byte)(unsafe.Pointer(&storage[offset]))
            var old [64]byte
            var out,expected [96]byte
            for i:=range old {old[i]=byte(sample*19+i*43+0x5a)}
            for i:=0;i<64;i+=8 {binary.LittleEndian.PutUint64(input[i:],patterns[(sample+i/8)%%8])}
            beforeInput,beforeOld:=*input,old
            for i:=range out {out[i],expected[i]=0xc3,0xc3}
            for i:=0;i<32;i++ {expected[i]=0;if k.legacy!=0 {expected[i]=old[i]}}
            for i:=0;i<k.width;i++ {
                lane:=i/k.lane;selected:=lane&^1;if k.odd!=0 {selected=lane|1}
                expected[i]=input[selected*k.lane+i%%k.lane]
            }
            profile:=uint32(0x1f80|((sample%%4)<<13)|(sample%%64))
            binary.LittleEndian.PutUint32(expected[64:],0x444)
            binary.LittleEndian.PutUint32(expected[68:],profile)
            MXCSR(profile)
            k.run(&out,input,&old,mask)
            after:=MXCSR(saved)
            if out!=expected || after!=profile || *input!=beforeInput || old!=beforeOld {
                t.Fatalf("actual Go duplicate row=%%d sample=%%d got=%%x want=%%x MXCSR=%%x/%%x",row,sample,out,expected,after,profile)
            }
            count++
        }}
    }
    if len(kernels)!=18 || count!=1728 {t.Fatal("incomplete original Go runtime",len(kernels),count)}
    t.Logf("actual original Go duplicate whole32/FLAGS/DF/MXCSR/canary outcomes %%d failures 0",count)
}
`

func x86DuplicateNativeFaultsC(prototypes, rows string) string {
	return x86MemoryFaultSupportC + prototypes + `
struct kernel {
    void (*run)(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);
    unsigned bytes,aligned_kind;
};
static const struct kernel kernels[]={` + rows + `};
int main(int argc,char **argv) {
    unsigned sample,probe,original;char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&sample,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 || sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            sample>=2*sizeof(kernels)/sizeof(kernels[0]) || probe>18 || original>1) return 80;
    struct kernel k=kernels[sample/2];
    uint64_t mask=sample%2?UINT64_MAX:0;
    if (memory_fault_setup(0)) return 81;
    const uint8_t *input=NULL;
    if (probe==1) input=guard+page-k.bytes+1;
    else if (probe==2 || probe==3) input=guard+page-k.bytes;
    else if (probe>=4) input=guard+probe-3;
    if (probe==3) {
#ifdef _WIN32
        DWORD old;if (!VirtualProtect(guard,page,PAGE_READONLY,&old)) return 82;
#else
        if (mprotect(guard,page,PROT_READ)) return 82;
#endif
    }
    _Alignas(64) uint8_t out[96],old[64];
    memset(out,0xc3,sizeof(out));memset(old,0x5a,sizeof(old));
    printf("memory enter %u %u %u\n",sample,probe,original);
    if (fflush(stdout)) return 83;
    if (original) {
        if (k.aligned_kind==1) __asm__ volatile("movshdup (%0),%%xmm0"::"r"(input):"xmm0","memory");
        else if (k.aligned_kind==2) __asm__ volatile("movsldup (%0),%%xmm0"::"r"(input):"xmm0","memory");
        else for (unsigned i=0;i<k.bytes;i++) (void)((const volatile uint8_t *)input)[i];
    } else k.run(out,input,old,mask);
    for (unsigned i=0;i<sizeof(out);i++) if (out[i]!=0xc3) return 84;
    for (unsigned i=0;i<sizeof(old);i++) if (old[i]!=0x5a) return 85;
    if (free_guard()) return 86;
    puts("memory complete");
    return fflush(stdout)?87:0;
}
`
}
