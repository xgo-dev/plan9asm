package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func emitX86GoEncodedTestInstruction(t *testing.T, source *strings.Builder, line string, raw bool) {
	t.Helper()
	if !raw {
		source.WriteString(line + "\n")
		return
	}
	code := assembleX87ControlBytes(t, "amd64", "TEXT instruction(SB),4,$0-0\n"+line+"\nRET\n")
	if len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("Go encoding lacks final RET")
	}
	for _, b := range code[:len(code)-1] {
		fmt.Fprintf(source, "BYTE $%#x\n", b)
	}
}

// Shared by native semantic oracles. A single accessible page followed by
// an inaccessible page detects eager loads from masked-off vector lanes.
const x86TestGuardPagesC = `
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

static uint8_t *guard;
static size_t page;

static int setup_guard(void) {
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    page = info.dwPageSize;

    guard = VirtualAlloc(NULL, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old;
    if (!guard || !VirtualProtect(guard + page, page, PAGE_NOACCESS, &old)) {
        return 1;
    }
#else
    long p = sysconf(_SC_PAGESIZE);
    if (p <= 0) {
        return 1;
    }
    page = (size_t)p;

    guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED || mprotect(guard + page, page, PROT_NONE)) {
        return 1;
    }
#endif
    return 0;
}

static int free_guard(void) {
#ifdef _WIN32
    return !VirtualFree(guard, 0, MEM_RELEASE);
#else
    return munmap(guard, page * 2);
#endif
}
`
