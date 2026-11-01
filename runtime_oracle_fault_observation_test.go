package plan9asm

// Consume expected hardware faults in the guest, rather than asking nested
// emulators to core-dump or relay an unhandled signal through fork/waitpid.
// The handler admits only a synchronous memory fault inside the exact protected
// region. A normal return, user-raised signal or fault at another address fails.
// Keep these C bytes shared across current-source and Go20-compatible oracles.
const numericalRuntimeFaultObservationC = `
#include <stdatomic.h>
static _Atomic(uintptr_t) numerical_fault_first, numerical_fault_last;
static void numerical_fault_observe(int signal_number, siginfo_t *info, void *context) {
    (void)context;
    uintptr_t address = info ? (uintptr_t)info->si_addr : 0;
    if (!info || info->si_signo != signal_number || info->si_code <= 0 ||
        (signal_number != SIGSEGV && signal_number != SIGBUS) ||
        address < atomic_load_explicit(&numerical_fault_first,memory_order_relaxed) ||
        address >= atomic_load_explicit(&numerical_fault_last,memory_order_relaxed)) _exit(121);
    _exit(123);
}
static void numerical_fault_begin(void *region, size_t bytes) {
    uintptr_t first=(uintptr_t)region, last=first+bytes;
    if (!bytes || last<first || !atomic_is_lock_free(&numerical_fault_first) ||
        !atomic_is_lock_free(&numerical_fault_last)) _exit(122);
    atomic_store_explicit(&numerical_fault_first,first,memory_order_relaxed);
    atomic_store_explicit(&numerical_fault_last,last,memory_order_relaxed);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = numerical_fault_observe;
    action.sa_flags = SA_SIGINFO;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGSEGV, &action, 0) ||
        sigaction(SIGBUS, &action, 0)) _exit(122);
}
static int numerical_fault_status(int status) {
    return WIFEXITED(status) && WEXITSTATUS(status) == 123;
}
`
