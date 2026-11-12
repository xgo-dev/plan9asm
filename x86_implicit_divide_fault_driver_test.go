package plan9asm

// The reference executes the actual ISA opcode, independently of translated
// object code. Setup, normal exits and missing exact entry receipts never count
// as a fault. No signal handler converts #DE into an ordinary successful exit.
func x86DivideNativeFaultsC(prototypes, rows, samples string) string {
	return x86MemoryFaultSupportC + prototypes + `
struct kernel {
    void (*run)(uint64_t *,uint64_t,uint64_t,uint64_t);
    unsigned bits,signed_division,memory;
};
static const struct kernel kernels[]={
` + rows + `};
struct sample {unsigned row; uint64_t low,high,divisor,operand;};
static const struct sample samples[]={
` + samples + `};
` + x86DivideNativeFaultMainC
}

const x86DivideNativeFaultMainC = `
#define BYTE_DIV(operation) do { \
    uint16_t a=(uint16_t)s.low; \
    uint8_t divisor=(uint8_t)s.operand; \
    if (k.memory) __asm__ volatile("std; " #operation " (%[input]); cld" \
        : "+&a"(a) : [input]"r"(input) : "cc","memory"); \
    else __asm__ volatile("std; " #operation " %[divisor]; cld" \
        : "+&a"(a) : [divisor]"q"(divisor) : "cc","memory"); \
} while (0)

#define WIDE_DIV(operation,type) do { \
    type a=(type)s.low,b=(type)s.high,divisor=(type)s.operand; \
    if (k.memory) __asm__ volatile("std; " #operation " (%[input]); cld" \
        : "+&a"(a),"+&d"(b) : [input]"r"(input) : "cc","memory"); \
    else __asm__ volatile("std; " #operation " %[divisor]; cld" \
        : "+&a"(a),"+&d"(b) : [divisor]"r"(divisor) : "cc","memory"); \
} while (0)

int main(int argc,char **argv) {
    if (argc!=4) return 80;
    unsigned sample,probe,original;
    char tail;
    if (sscanf(argv[1],"%u%c",&sample,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 ||
            sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            sample>=sizeof(samples)/sizeof(samples[0]) || probe>4 || original>1) return 80;
    struct sample s=samples[sample];
    if (s.row>=sizeof(kernels)/sizeof(kernels[0])) return 80;
    struct kernel k=kernels[s.row];
    if (probe && !k.memory) return 80;
    if (memory_fault_setup(0)) return 81;
    uint64_t out[4]={s.divisor,0,0,0};
    uint8_t *input=(uint8_t *)out;
    unsigned bytes=k.bits/8;
    if (probe==1) input=NULL;
    else if (probe>=2) {
        unsigned accessible=probe==2?bytes-1:bytes;
        input=guard+page-accessible;
        for (unsigned i=0;i<accessible;i++) input[i]=(uint8_t)(s.divisor>>(8*i));
        if (probe==4) {
#ifdef _WIN32
            DWORD old;
            if (!VirtualProtect(guard,page,PAGE_READONLY,&old)) return 82;
#else
            if (mprotect(guard,page,PROT_READ)) return 82;
#endif
        }
    }
    printf("memory enter %u %u %u\n",sample,probe,original);
    if (fflush(stdout)) return 83;
    if (original) {
        switch (k.bits) {
        case 8:
            if (k.signed_division) BYTE_DIV(idivb); else BYTE_DIV(divb);
            break;
        case 16:
            if (k.signed_division) WIDE_DIV(idivw,uint16_t); else WIDE_DIV(divw,uint16_t);
            break;
        case 32:
            if (k.signed_division) WIDE_DIV(idivl,uint32_t); else WIDE_DIV(divl,uint32_t);
            break;
#ifndef __i386__
        case 64:
            if (k.signed_division) WIDE_DIV(idivq,uint64_t); else WIDE_DIV(divq,uint64_t);
            break;
#endif
        default: return 84;
        }
    } else k.run((uint64_t *)input,s.low,s.high,s.divisor);
    if (free_guard()) return 85;
    puts("memory complete");
    return fflush(stdout)?86:0;
}
`
