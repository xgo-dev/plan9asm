#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct { uint64_t ax, dx; } pair;
typedef pair (*operation)(uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t, uint64_t, uint64_t);
extern pair Raw(uint64_t, uint64_t, uint64_t, uint64_t,
                uint64_t, uint64_t, uint64_t);
int cliteErrno(void) { return errno; }

/* Independent register-addressed kernel oracle, including the actual DX
 * output. It does not assume DX preservation from the C source variable. */
static pair original(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6) {
    register uint64_t r10 __asm__("r10") = a4;
    register uint64_t r8 __asm__("r8") = a5;
    register uint64_t r9 __asm__("r9") = a6;
    pair output;
    __asm__ volatile("syscall"
        : "=a"(output.ax), "=d"(output.dx)
        : "0"(number), "D"(a1), "S"(a2), "1"(a3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "cc", "memory");
    return output;
}

static int check(const char *name, operation call) {
    const uint64_t sentinel = UINT64_C(0x123456789abcdef);
    int failures = 0;
    errno = EDOM;
    pair result = call(39, 0, 0, sentinel, 0, 0, 0);
    if (result.ax != (uint64_t)getpid() || result.dx != sentinel || errno != EDOM) {
        fprintf(stderr, "%s getpid ax=%llu dx=%llx errno=%d\n", name,
                (unsigned long long)result.ax, (unsigned long long)result.dx, errno);
        failures++;
    }
    errno = EDOM;
    result = call(UINT64_MAX, 0, 0, sentinel, 0, 0, 0);
    if (result.ax != (uint64_t)-ENOSYS || result.dx != sentinel || errno != EDOM) {
        fprintf(stderr, "%s invalid ax=%lld dx=%llx errno=%d\n", name,
                (long long)result.ax, (unsigned long long)result.dx, errno);
        failures++;
    }
    int pipes[2];
    if (pipe(pipes) != 0) return failures + 1;
    const char message[] = "raw-syscall-io";
    const size_t length = sizeof(message) - 1;
    errno = EDOM;
    result = call(1, pipes[1], (uintptr_t)message, length, 0, 0, 0);
    if (result.ax != length || result.dx != length || errno != EDOM) {
        fprintf(stderr, "%s write ax=%llu dx=%llu errno=%d\n", name,
                (unsigned long long)result.ax, (unsigned long long)result.dx, errno);
        failures++;
    }
    close(pipes[1]); /* A failed write must produce EOF, never hang this oracle. */
    unsigned char buffer[32];
    memset(buffer, 0xa5, sizeof(buffer));
    errno = EDOM;
    result = call(0, pipes[0], (uintptr_t)(buffer + 3), length, 0, 0, 0);
    if (result.ax != length || result.dx != length || errno != EDOM ||
        memcmp(buffer + 3, message, length) != 0) {
        fprintf(stderr, "%s read ax=%llu dx=%llu errno=%d\n", name,
                (unsigned long long)result.ax, (unsigned long long)result.dx, errno);
        failures++;
    }
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if ((i < 3 || i >= 3 + length) && buffer[i] != 0xa5) failures++;
    }
    close(pipes[0]);
    printf("RAW_SYSCALL_%s calls=4 failures=%d\n", name, failures);
    return failures;
}

int main(void) {
    int reference = check("REFERENCE", original);
    int translated = check("TRANSLATED", Raw);
    return reference != 0 || translated != 0;
}
