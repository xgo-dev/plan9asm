#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>

@PROTOTYPES@
@ORIGINALS@

typedef void (*Program)(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint32_t);
typedef struct {
    Program translated, original;
    unsigned bits, width;
    int source, second, destination;
    bool legacy, scalar, dead, minimum;
} Kernel;

static const Kernel kernels[] = {@KERNELS@};

static const uint64_t edges32[] = {
    0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f800000, 0xff800000,
    0x7fc12345, 0xffc54321, 0x7f812345, 0xff812345,
    1, 0x80000001, 0x007fffff, 0x807fffff, 0x00800000, 0x80800000
};

static const uint64_t edges64[] = {
    0, UINT64_C(0x8000000000000000), UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
    UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
    UINT64_C(0x7ff8123456789abc), UINT64_C(0xfff8fedcba987654),
    UINT64_C(0x7ff0123456789abc), UINT64_C(0xfff0123456789abc),
    1, UINT64_C(0x8000000000000001), UINT64_C(0x000fffffffffffff),
    UINT64_C(0x800fffffffffffff), UINT64_C(0x0010000000000000), UINT64_C(0x8010000000000000)
};

static uint64_t lane(const uint8_t *input, unsigned bytes) {
    uint64_t value = 0;
    memcpy(&value, input, bytes);
    return value;
}

// Integer-only IEEE ordering avoids contaminating the observed MXCSR with
// comparisons in the reference. MIN/MAX returns the second Intel operand
// for equality and either NaN, retaining its sign and payload bits.
static uint64_t reference(uint64_t a, uint64_t b, unsigned bits, bool minimum, uint32_t csr) {
    uint64_t sign = UINT64_C(1) << (bits - 1);
    uint64_t mask = bits == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    uint64_t exponent = bits == 64 ? UINT64_C(0x7ff0000000000000) : UINT64_C(0x7f800000);
    uint64_t fraction = mask & ~(sign | exponent);
    if (csr & 64) {
        if (!(a & exponent) && (a & fraction)) a &= sign;
        if (!(b & exponent) && (b & fraction)) b &= sign;
    }
    if (((a & exponent) == exponent && (a & fraction)) ||
        ((b & exponent) == exponent && (b & fraction)) ||
        a == b || (!(a & ~sign) && !(b & ~sign))) return b;
    uint64_t ak = a & sign ? (~a & mask) : a ^ sign;
    uint64_t bk = b & sign ? (~b & mask) : b ^ sign;
    return ((ak < bk) == minimum) ? a : b;
}

static uint32_t get_csr(void) {
    uint32_t result;
    __asm__ volatile("stmxcsr %0" : "=m"(result));
    return result;
}

static void set_csr(uint32_t value) {
    __asm__ volatile("ldmxcsr %0" : : "m"(value));
}

static int signal_at(Program run, const uint8_t *a, const uint8_t *b, const uint8_t *old, uint32_t csr) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        _Alignas(32) uint8_t out[64] = {0};
        run(out, a, b, old, csr);
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -2;
    if (WIFEXITED(status)) return WEXITSTATUS(status) ? -3 : 0;
    if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS)) return 1;
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGFPE) return 2;
    return -4;
}

static int fault(Program run, const uint8_t *a, const uint8_t *b, const uint8_t *old) {
    return signal_at(run, a, b, old, 0x1f80);
}

static void missing_read(uint8_t *out, const uint8_t *a, const uint8_t *b,
                         const uint8_t *old, uint32_t csr) {
    (void)out; (void)a; (void)b; (void)old; (void)csr;
}

static void too_wide(uint8_t *out, const uint8_t *a, const uint8_t *b,
                     const uint8_t *old, uint32_t csr) {
    (void)out; (void)a; (void)old; (void)csr;
    volatile uint64_t result = *(volatile const uint64_t *)b;
    (void)result;
}

int main(void) {
    const uint32_t original_csr = get_csr();
    long page = sysconf(_SC_PAGESIZE);
    if (page < 128) return 1;
    uint8_t *memory = mmap(0, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED || mprotect(memory + page, page, PROT_NONE)) return 2;
    memset(memory, 0xa5, page);
    _Alignas(32) uint8_t inputs[3][32];
    if (fault(missing_read, inputs[0], NULL, inputs[2]) != 0 ||
        fault(too_wide, inputs[0], memory + page - 4, inputs[2]) != 1) return 3;

    unsigned numerical = 0, faults = 0, exceptions = 0;
    for (unsigned index = 0; index < sizeof(kernels) / sizeof(kernels[0]); index++) {
        Kernel k = kernels[index];
        unsigned bytes = k.bits / 8;
        const uint64_t *edges = k.bits == 32 ? edges32 : edges64;
        for (unsigned ai = 0; ai < 16; ai++) for (unsigned bi = 0; bi < 16; bi++) {
            for (unsigned n = 0; n < 32 / bytes; n++) {
                uint64_t values[] = {edges[(ai + n) % 16], edges[(bi + 3 * n) % 16],
                                     edges[(ai + 2 * bi + n + 5) % 16]};
                for (unsigned v = 0; v < 3; v++) memcpy(inputs[v] + n * bytes, &values[v], bytes);
            }
            uint8_t before[sizeof(inputs)];
            memcpy(before, inputs, sizeof(inputs));
            for (unsigned controls = 0; controls < 8; controls++) {
                uint32_t csr = 0x1f80 | ((controls & 1) ? 64 : 0) |
                               ((controls & 2) ? 0x8000 : 0) | ((controls & 4) ? 63 : 0);
                uint32_t ambient = 0x1f80 | ((ai & 3) << 13);
                set_csr(ambient);
                _Alignas(32) uint8_t original[64] = {0}, translated[64] = {0};
                k.original(original, inputs[0], inputs[1], inputs[2], csr);
                if (get_csr() != ambient) return 4;
                k.translated(translated, inputs[0], inputs[1], inputs[2], csr);
                uint8_t want[32];
                memcpy(want, inputs[k.destination], sizeof(want));
                if (k.legacy) memset(want + 16, 0, 16);
                if (!k.dead) {
                    if (!k.legacy) {
                        memset(want, 0, sizeof(want));
                        if (k.scalar) memcpy(want, inputs[k.second], 16);
                    }
                    unsigned active = k.scalar ? bytes : k.width;
                    const uint8_t *first = inputs[k.source < 0 ? 1 : k.source];
                    const uint8_t *second = inputs[k.second];
                    for (unsigned offset = 0; offset < active; offset += bytes) {
                        uint64_t value = reference(lane(second + offset, bytes), lane(first + offset, bytes),
                                                   k.bits, k.minimum, csr);
                        memcpy(want + offset, &value, bytes);
                    }
                }
                if (memcmp(original, want, 32) || memcmp(translated, original, 48) ||
                    lane(original + 32, 4) != ambient || lane(original + 40, 4) != 0xc95 ||
                    (lane(original + 48, 4) & 0xcd5) != 0xc95 ||
                    lane(original + 44, 4) != csr || get_csr() != ambient ||
                    memcmp(inputs, before, sizeof(inputs))) {
                    fprintf(stderr, "MIN/MAX kernel=%u bits=%u width=%u pair=%u/%u controls=%x source=%d second=%d dead=%d\n",
                            index, k.bits, k.width, ai, bi, csr, k.source, k.second, k.dead);
                    fprintf(stderr, "original:");
                    for (unsigned n = 0; n < sizeof(original); n++) fprintf(stderr, " %02x", original[n]);
                    fprintf(stderr, "\ntranslated:");
                    for (unsigned n = 0; n < sizeof(translated); n++) fprintf(stderr, " %02x", translated[n]);
                    fprintf(stderr, "\ninteger reference:");
                    for (unsigned n = 0; n < sizeof(want); n++) fprintf(stderr, " %02x", want[n]);
                    fprintf(stderr, "\nambient CSR %x expected %x; inputs changed %d\n", get_csr(), ambient,
                            memcmp(inputs, before, sizeof(inputs)) != 0);
                    return 5;
                }
                numerical += 2;
            }
        }
        if (k.source < 0) {
            unsigned width = k.scalar ? bytes : k.width;
            const uint8_t *addresses[] = {NULL, memory + page - width + 1,
                                         memory + page - width, memory + page - width - 1, memory + 1};
            for (unsigned address = 0; address < 5; address++) {
                int want = address < 2 || (k.legacy && !k.scalar && address >= 3);
                if (fault(k.original, inputs[0], addresses[address], inputs[2]) != want ||
                    fault(k.translated, inputs[0], addresses[address], inputs[2]) != want) {
                    fprintf(stderr, "MIN/MAX fault kernel=%u address=%u width=%u expected=%d\n", index, address, width, want);
                    return 6;
                }
                faults += 2;
            }
        }
        // MIN/MAX signals invalid for both quiet and signaling NaNs. A
        // denormal input signals unless DAZ is enabled. Dead results retain
        // the same exception contract; status flags are not pure values.
        const uint32_t controls[] = {0x1f00, 0x1f00, 0x1e80, 0x1ec0};
        for (unsigned kind = 0; kind < 4; kind++) {
            uint64_t value = kind < 2 ? edges[6 + 2 * kind] : 1;
            for (unsigned v = 0; v < 3; v++) {
                for (unsigned offset = 0; offset < 32; offset += bytes) {
                    memcpy(inputs[v] + offset, &value, bytes);
                }
            }
            int want = kind < 3 ? 2 : 0;
            int original = signal_at(k.original, inputs[0], inputs[1], inputs[2], controls[kind]);
            int translated = signal_at(k.translated, inputs[0], inputs[1], inputs[2], controls[kind]);
            if (original != want || translated != want) {
                fprintf(stderr, "MIN/MAX exception kernel=%u kind=%u expected=%d original=%d translated=%d\n",
                        index, kind, want, original, translated);
                return 8;
            }
            exceptions += 2;
        }
    }
    set_csr(original_csr);
    if (munmap(memory, 2 * page)) return 7;
    printf("%zu MIN/MAX kernels: numerical %u, faults %u, exceptions %u, tripwires 2; failures 0\n",
           sizeof(kernels) / sizeof(kernels[0]), numerical, faults, exceptions);
    return 0;
}
