//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const x86PolynomialFoldOriginalGo = `package main
import ("encoding/binary"; "fmt")

func multiply(a,b uint64) (lo,hi uint64) {
    for bit:=uint(0);bit<64;bit++ {
        if b>>bit&1==0 { continue }
        lo^=a<<bit
        if bit!=0 { hi^=a>>(64-bit) }
    }
    return
}
func reference(p *[128]byte,n,seed uint32) uint32 {
    low,high:=uint64(seed),uint64(0)
    for block:=uint32(0);block<n;block++ {
        a:=low^binary.LittleEndian.Uint64(p[block*16:])
        b:=high^binary.LittleEndian.Uint64(p[block*16+8:])
        lo,hi:=multiply(a,0x1f123bb5a7c9d001)
        _,fold:=multiply(b,0xa7c1e305f1b692d3)
        low,high=lo^fold,hi
        if (n-block)&1!=0 {
            low^=low>>7
            high^=high>>7
        } else {
            low^=low<<3
            high^=high<<3
        }
    }
    return uint32((low^high)>>11)
}
func main() {
    seeds:=[]uint32{0,1,0xffffffff,0x89abcdef}
    for sample:=0;sample<8;sample++ {
        var storage [144]byte
        for i:=range storage { storage[i]=byte(i*71+sample*97+(i*sample)%251) }
        before:=storage
        for offset:=0;offset<4;offset++ {
            p:=(*[128]byte)(storage[offset:offset+128])
            for n:=uint32(0);n<=8;n++ {
                for _,seed:=range seeds {
                    got,want:=fold(p,n,seed),reference(p,n,seed)
                    if got!=want || storage!=before {
                        panic(fmt.Sprintf("original Go sample=%d offset=%d n=%d seed=%x got=%x want=%x",sample,offset,n,seed,got,want))
                    }
                    fmt.Println(got)
                }
            }
        }
    }
    for _,seed:=range seeds {
        got,want:=fold(nil,0,seed),reference(nil,0,seed)
        if got!=want { panic("nil/zero-length control") }
        fmt.Println(got)
    }
}
`

func TestCrossLinuxRuntimeMatrixX86PolynomialFoldOriginalGoThreeAPIs(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	goos := "linux"
	if strings.Contains(execution.triple, "apple") {
		goos = "darwin"
	}
	source := x86PolynomialFoldSource("amd64")
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module polynomial_fold_oracle\n\ngo 1.20\n",
		"main.go": x86PolynomialFoldOriginalGo + x86PolynomialFoldDeclaration,
		"fold.s":  source,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(directory, "original")
	environment := []string{"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS=" + goos}
	dataGlobalAlignmentCommand(t, directory, environment, "go", "build", "-p=2", "-o", original, ".")
	results := strings.Fields(string(execution.run(t, original)))
	const samples = 8*4*9*4 + 4
	if len(results) != samples {
		t.Fatalf("actual linked Go executed %d results, want %d", len(results), samples)
	}
	var values strings.Builder
	for _, result := range results {
		value, err := strconv.ParseUint(result, 10, 32)
		if err != nil {
			t.Fatal("original Go result is not uint32", err)
		}
		fmt.Fprintf(&values, "UINT32_C(%d),\n", value)
	}
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern uint32_t fold(const uint8_t*,uint32_t,uint32_t);
static const uint32_t original[]={
` + values.String() + `};
int main(void) {
    const uint32_t seeds[]={0,1,0xffffffff,0x89abcdef};
    unsigned index=0;
    for(unsigned sample=0;sample<8;sample++) {
        uint8_t storage[144],before[144];
        for(unsigned i=0;i<144;i++) storage[i]=(uint8_t)(i*71+sample*97+(i*sample)%251);
        memcpy(before,storage,sizeof(storage));
        for(unsigned offset=0;offset<4;offset++)
        for(unsigned n=0;n<=8;n++)
        for(unsigned seed=0;seed<4;seed++) {
            uint32_t got=fold(storage+offset,n,seeds[seed]);
            if(got!=original[index] || memcmp(storage,before,sizeof(storage))) {
                fprintf(stderr,"LLVM sample=%u offset=%u n=%u seed=%x got=%x original=%x\n",
                    sample,offset,n,seeds[seed],got,original[index]);
                return 1;
            }
            index++;
        }
    }
    for(unsigned seed=0;seed<4;seed++) if(fold(0,0,seeds[seed])!=original[index++]) return 2;
    return index!=sizeof(original)/sizeof(original[0]);
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, x86PolynomialFoldDeclaration, "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(api+"/"+level, func(t *testing.T) {
				text := ir
				if level == "-O2" {
					text = x86MulDivRoundOptimize(t, text)
				}
				execution.compileAndRunLLVM(t, "polynomial-fold", text, main, level)
			})
		}
	}
	t.Logf("%d actual Go linked loop/join results, independently checked polynomial reference, three LLVM APIs O0/O2; source identical, inputs unchanged", samples)
}
