package plan9asm

const x86Timestamp386OriginalDriver = `package main

import (
    "fmt"
    "runtime"
)

func main() {
    runtime.LockOSThread()
    observations := 0
    expectedFlags := []uint32{0x8c5, 0x10, 0x8c5, 0x10}
    for index, sample := range []func(*[8]uint32){rdtsc, rdtsc_af, rdtscp, rdtscp_af} {
        for iteration := 0; iteration < 64; iteration++ {
            out := [8]uint32{0, 0, 0, 0, 0, 0, 0x23456789, 0x2468ace0}
            sample(&out)
            if uint64(out[0]) | uint64(out[1]) << 32 == 0 ||
                    out[3] != 0x3a291807 || out[4] & 0x8d5 != expectedFlags[index] ||
                    out[6] != 0x23456789 || out[7] != 0x2468ace0 ||
                    index < 2 && out[2] != 0x5f60718 {
                panic(fmt.Sprintf("original IA32 timestamp %d: %x", index, out))
            }
            observations++
        }
    }
    fmt.Printf("original IA32 timestamp observations %d\n", observations)
}
`

const x86Timestamp386IndependentC = `
#include <stdint.h>
#include <stdio.h>

extern void rdtsc(uint32_t *);
extern void rdtsc_af(uint32_t *);
extern void rdtscp(uint32_t *);
extern void rdtscp_af(uint32_t *);

static uint64_t read_counter(unsigned *aux) {
    unsigned low, high, native_aux;
    __asm__ volatile("lfence; rdtscp; lfence" : "=a"(low), "=d"(high), "=c"(native_aux) :: "memory");
    *aux = native_aux;
    return (uint64_t)low | (uint64_t)high << 32;
}

int main(void) {
    void (*samples[])(uint32_t *) = { rdtsc, rdtsc_af, rdtscp, rdtscp_af };
    const uint32_t expected_flags[] = { 0x8c5, 0x10, 0x8c5, 0x10 };
    unsigned observations = 0, stable_aux_observations = 0;
    for (unsigned index = 0; index < 4; index++) {
        for (unsigned iteration = 0; iteration < 64; iteration++) {
            unsigned before_csr, after_csr, before_aux, after_aux;
            uint32_t out[8] = {0, 0, 0, 0, 0, 0, 0x23456789, 0x2468ace0};
            __asm__ volatile("stmxcsr %0" : "=m"(before_csr));
            uint64_t before = read_counter(&before_aux);
            samples[index](out);
            uint64_t after = read_counter(&after_aux);
            __asm__ volatile("stmxcsr %0" : "=m"(after_csr));
            uint64_t got = (uint64_t)out[0] | (uint64_t)out[1] << 32;
            if (!got || got < before || got > after ||
                    out[3] != 0x3a291807 || (out[4] & 0x8d5) != expected_flags[index] ||
                    out[5] != before_csr || after_csr != before_csr ||
                    out[6] != 0x23456789 || out[7] != 0x2468ace0 ||
                    (index < 2 && out[2] != 0x5f60718)) {
                fprintf(stderr, "IA32 timestamp %u counter=%llx window=%llx..%llx flags=%x\n",
                    index, (unsigned long long)got, (unsigned long long)before,
                    (unsigned long long)after, out[4]);
                return 1;
            }
            if (index >= 2 && before_aux == after_aux) {
                if (out[2] != before_aux) {
                    fprintf(stderr, "IA32 timestamp AUX=%x reference=%x\n", out[2], before_aux);
                    return 2;
                }
                stable_aux_observations++;
            }
            observations++;
        }
    }
    if (!stable_aux_observations) {
        fprintf(stderr, "no stable independent IA32 AUX window observed\n");
        return 3;
    }
    printf("IA32 timestamp observations %u\n", observations);
    return 0;
}
`
