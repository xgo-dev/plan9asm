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
static uint8_t *guard_mapping;
static size_t guard_pages;

static int free_guard(void);

static int setup_guard_before(unsigned leading) {
    if (leading > 1) return 1;
    guard_pages = 2 + leading;
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    page = info.dwPageSize;

    guard_mapping = VirtualAlloc(NULL, page * guard_pages, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!guard_mapping) return 1;
    guard = guard_mapping + leading * page;
    DWORD old;
    if ((leading && !VirtualProtect(guard_mapping, page, PAGE_NOACCESS, &old)) ||
            !VirtualProtect(guard + page, page, PAGE_NOACCESS, &old)) {
        free_guard();
        return 1;
    }
#else
    long p = sysconf(_SC_PAGESIZE);
    if (p <= 0) {
        return 1;
    }
    page = (size_t)p;

    guard_mapping = mmap(NULL, page * guard_pages, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard_mapping == MAP_FAILED) return 1;
    guard = guard_mapping + leading * page;
    if ((leading && mprotect(guard_mapping, page, PROT_NONE)) ||
            mprotect(guard + page, page, PROT_NONE)) {
        free_guard();
        return 1;
    }
#endif
    return 0;
}

static int setup_guard(void) {
    return setup_guard_before(0);
}

static int free_guard(void) {
#ifdef _WIN32
    return !VirtualFree(guard_mapping, 0, MEM_RELEASE);
#else
    return munmap(guard_mapping, page * guard_pages);
#endif
}
`
