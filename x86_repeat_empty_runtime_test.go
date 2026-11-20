package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type repeatEmptyRuntimeRow struct {
	name                                    string
	width, cmps, backward, repeatEQ, jumpEQ int
}

func repeatEmptyRuntimeRows(t *testing.T, arch string) []repeatEmptyRuntimeRow {
	t.Helper()
	widths := []int{1, 2, 4, 8}
	if arch == "386" {
		widths = widths[:3]
	}
	var rows []repeatEmptyRuntimeRow
	for cmps := 0; cmps < 2; cmps++ {
		for _, width := range widths {
			for _, repeatEQ := range []int{1, 0} { // Original source order: REP, REPN.
				for backward := 0; backward < 2; backward++ {
					for _, jumpEQ := range []int{1, 1, 0, 0} { // JE/JZ/JNE/JNZ.
						rows = append(rows, repeatEmptyRuntimeRow{
							fmt.Sprint("RepeatEmpty", len(rows)), width, cmps, backward, repeatEQ, jumpEQ})
					}
				}
			}
		}
	}
	_, _, count := repeatEmptyGuardCompleteSource(t, arch, false)
	if len(rows) != count {
		t.Fatal("independent executed form directory disagrees with whole source", len(rows), count)
	}
	return rows
}

func repeatEmptyRuntimeC(t *testing.T, arch string) string {
	t.Helper()
	var prototypes, rows strings.Builder
	for _, row := range repeatEmptyRuntimeRows(t, arch) {
		fmt.Fprintf(&prototypes, "extern uintptr_t %s(const uint8_t*,const uint8_t*,uintptr_t,uintptr_t);\n", row.name)
		fmt.Fprintf(&rows, "    {%s,%d,%d,%d,%d,%d},\n", row.name, row.width, row.cmps, row.backward, row.repeatEQ, row.jumpEQ)
	}
	return `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
struct row {
    uintptr_t (*run)(const uint8_t*,const uint8_t*,uintptr_t,uintptr_t);
    unsigned width,cmps,backward,repeat_eq,jump_eq;
};
static const struct row rows[] = {
` + rows.String() + `};
static uint64_t load(const uint8_t *p,unsigned width) {
    uint64_t v=0;
    for(unsigned b=0;b<width;b++) v|=(uint64_t)p[b]<<(8*b);
    return v;
}
static uintptr_t expected(struct row row,const uint8_t *p,const uint8_t *q,
        uintptr_t n,uintptr_t needle) {
    if(n==0) return UINTPTR_MAX; /* No pointer arithmetic/access for NULL. */
    uintptr_t done=0;
    unsigned equal=0;
    while(done<n) {
        intptr_t delta=(row.backward?-1:1)*(intptr_t)(done*row.width);
        uint64_t a=row.cmps?load(p+delta,row.width):needle;
        if(row.width<8) a&=(UINT64_C(1)<<(8*row.width))-1;
        equal=a==load(q+delta,row.width);
        done++;
        if(equal!=row.repeat_eq) break;
    }
    if(equal!=row.jump_eq) return UINTPTR_MAX;
    uintptr_t distance=done*row.width;
    return (row.backward?(uintptr_t)0-distance:distance)-1;
}
int main(void) {
    const uintptr_t counts[]={0,1,2,4,8};
    const unsigned offsets[]={0,1,7};
    unsigned checks=0;
    for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++)
    for(unsigned pattern=0;pattern<4;pattern++)
    for(unsigned off=0;off<3;off++)
    for(unsigned c=0;c<5;c++) {
        uint8_t p[256],q[256],p_before[256],q_before[256];
        for(unsigned i=0;i<256;i++) {
            p[i]=q[i]=pattern<2?0:(pattern==2?0x5a:(uint8_t)(i*37+11));
        }
        if(pattern>=2) p[128]^=0xa5;
        memcpy(p_before,p,256); memcpy(q_before,q,256);
        unsigned start=(rows[r].backward?128:16)+offsets[off];
        uintptr_t n=counts[c];
        const uint8_t *left=n?p+start:NULL,*right=n?q+start:NULL;
        uintptr_t needle=pattern==1?1:(uintptr_t)load(q+start,rows[r].width);
        uintptr_t want=expected(rows[r],left,right,n,needle);
        uintptr_t got=rows[r].run(left,right,n,needle);
        if(got!=want||memcmp(p,p_before,256)||memcmp(q,q_before,256)) {
            fprintf(stderr,"row=%u pattern=%u offset=%u n=%llu got=%llx want=%llx\n",
                r,pattern,offsets[off],(unsigned long long)n,
                (unsigned long long)got,(unsigned long long)want);
            return 1;
        }
        checks++;
    }
    printf("repeat-empty LLVM checks=%u\n",checks);
    return 0;
}
`
}

func TestX86RepeatEmptyGuardCompleteLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _ := repeatEmptyGuardCompleteSource(t, target.arch, false)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "repeat-empty.ll", "repeat-empty.o", ir)
				})
			}
		})
	}
}

func TestX86RepeatEmptyGuardPortableLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, count := repeatEmptyGuardCompleteSource(t, arch, false)
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete source lost portable numerical translation", err)
					}
					if strings.Contains(ir, "asm sideeffect") {
						t.Fatal("portable strings retained an x86-only direction instruction")
					}
					for index := 0; index < count; index++ {
						body := x86StringMemoryFunction(t, ir, fmt.Sprint("RepeatEmpty", index))
						for _, flag := range []string{"z", "slt", "cf", "pf", "af", "of"} {
							// These implementation defaults prevent LLVM poison/undef;
							// they are never entry FLAGS facts in the source proof.
							if !strings.Contains(body, "store i1 false, ptr %flags_"+flag) {
								t.Fatal("old status value has no concrete initialization", index, flag)
							}
						}
					}
					compileLLVMToObject(t, llc, triple, "portable-repeat.ll", "portable-repeat.o", ir)
				})
			}
		}
	}
}

func repeatEmptyExecuteLLVM(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	source, declarations, count := repeatEmptyGuardCompleteSource(t, arch, false)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86MulDivRoundOptimize(t, ir)
					}
					output := execution.compileAndRunLLVM(t, "repeat-empty", input, repeatEmptyRuntimeC(t, arch), level)
					want := fmt.Sprintf("repeat-empty LLVM checks=%d", count*4*3*5)
					if strings.TrimSpace(string(output)) != want {
						t.Fatalf("incomplete portable independent numerical oracle: %q", output)
					}
				})
			}
		})
	}
}

func TestX86RepeatEmptyGuardPortableNumericalExecution(t *testing.T) {
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	repeatEmptyExecuteLLVM(t, arch, x86ScalarCountHostExecution(t))
	t.Log("actual-host LLVM comparison/cursor values, zero-count NULL, unaligned B/W/L/Q and both directions; not original x86 execution")
}

func repeatEmptyExecuteOriginal(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	source, declarations, _ := repeatEmptyGuardCompleteSource(t, arch, false)
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var assembly, entries, callers strings.Builder
	assembly.WriteString(source)
	entries.WriteString("package oracle\n" + declarations)
	for index, row := range repeatEmptyRuntimeRows(t, arch) {
		for zf := 0; zf < 2; zf++ {
			name := fmt.Sprintf("Observe%dZF%d", index, zf)
			fmt.Fprintf(&entries, "func %s(p,q *byte,n,needle uintptr) uintptr\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$%d-%d\n", name, 5*word, 5*word)
			for argument, parameter := range []string{"p", "q", "n", "needle"} {
				fmt.Fprintf(&assembly, "%s %s+%d(FP),AX\n%s AX,%d(SP)\n", move, parameter, argument*word, move, argument*word)
			}
			// Set both actual incoming ZF states immediately before CALL. No
			// test initialization is added to the independently translated body.
			fmt.Fprintf(&assembly, "MOVL $0,AX\nCMPL AX,$%d\nCALL ·%s(SB)\n", 1-zf, row.name)
			fmt.Fprintf(&assembly, "%s %d(SP),AX\n%s AX,ret+%d(FP)\nRET\n", move, 4*word, move, 4*word)
			fmt.Fprintf(&callers, "    {%s,%d,%d,%d,%d,%d},\n", name, row.width, row.cmps, row.backward, row.repeatEQ, row.jumpEQ)
		}
	}
	oracle := `package oracle
import (
    "testing"
    "unsafe"
)
type row struct {
    run func(*byte,*byte,uintptr,uintptr) uintptr
    width,cmps,backward,repeatEQ,jumpEQ int
}
var rows=[]row{
` + callers.String() + `}
func load(p *byte,width int) uint64 {
    var value uint64
    for b:=0;b<width;b++ { value|=uint64(*(*byte)(unsafe.Add(unsafe.Pointer(p),b)))<<uint(8*b) }
    return value
}
func expected(r row,p,q *byte,n,needle uintptr) uintptr {
    if n==0 { return ^uintptr(0) }
    var done uintptr
    equal:=0
    for done<n {
        delta:=int(done)*r.width
        if r.backward!=0 { delta=-delta }
        a:=uint64(needle)
        if r.cmps!=0 { a=load((*byte)(unsafe.Add(unsafe.Pointer(p),delta)),r.width) }
        if r.width<8 { a&=(uint64(1)<<uint(8*r.width))-1 }
        equal=0
        if a==load((*byte)(unsafe.Add(unsafe.Pointer(q),delta)),r.width) { equal=1 }
        done++
        if equal!=r.repeatEQ { break }
    }
    if equal!=r.jumpEQ { return ^uintptr(0) }
    distance:=uintptr(done)*uintptr(r.width)
    if r.backward!=0 { distance=0-distance }
    return distance-1
}
func TestOriginal(t *testing.T) {
    checks:=0
    for index,r:=range rows {
    for pattern:=0;pattern<4;pattern++ {
    for _,offset:=range []int{0,1,7} {
    for _,n:=range []uintptr{0,1,2,4,8} {
        var p,q [256]byte
        for i:=range p {
            if pattern==2 { p[i]=0x5a }
            if pattern==3 { p[i]=byte(i*37+11) }
            q[i]=p[i]
        }
        if pattern>=2 { p[128]^=0xa5 }
        beforeP,beforeQ:=p,q
        start:=16+offset
        if r.backward!=0 { start=128+offset }
        left,right:=&p[start],&q[start]
        if n==0 { left,right=nil,nil }
        needle:=uintptr(load(&q[start],r.width))
        if pattern==1 { needle=1 }
        want:=expected(r,left,right,n,needle)
        got:=r.run(left,right,n,needle)
        if got!=want||p!=beforeP||q!=beforeQ {
            t.Fatalf("row=%d pattern=%d offset=%d n=%d got=%x want=%x",index,pattern,offset,n,got,want)
        }
        checks++
    }}}}
    if checks!=len(rows)*4*3*5 { t.Fatal("incomplete actual original-Go directory",checks) }
    t.Logf("repeat-empty original checks=%d; both incoming ZF states, complete unchanged bodies",checks)
}
`
	x86RunOriginalGoNativeSource(t, execution, arch, entries.String(), assembly.String(), oracle)
}
