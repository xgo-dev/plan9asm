//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x87EncodedRuntimePrograms(t *testing.T) (string, string, string, string) {
	t.Helper()
	source, declarations := x87EncodedTenByteProgram(t, "amd64")
	type sample struct {
		kind int
		data [10]byte
	}
	var samples []sample
	for _, negative := range []bool{false, true} {
		for _, value := range []uint64{0, 1, 9007199254740993, 999999999999999999, 123456789012345678} {
			var data [10]byte
			for index := 0; index < 9; index++ {
				data[index] = byte(value % 10)
				value /= 10
				data[index] |= byte(value%10) << 4
				value /= 10
			}
			if negative {
				data[9] = 0x80
			}
			samples = append(samples, sample{data: data})
		}
		for _, value := range []struct {
			sig uint64
			se  uint16
		}{
			{0, 0}, {0x8000000000000000, 0x3fff},
			{0x8000000000000001, 0x3fff}, {0xc90fdaa22168c235, 0x4000},
			{1, 0}, {0x8000000000000000, 0},
			{0x8000000000000000, 0x7fff}, {0xc000000000000001, 0x7fff},
			{0x8000000000000001, 0x7fff}, {1, 0x4000},
		} {
			var data [10]byte
			for index := 0; index < 8; index++ {
				data[index] = byte(value.sig >> uint(8*index))
			}
			if negative {
				value.se |= 0x8000
			}
			data[8], data[9] = byte(value.se), byte(value.se>>8)
			samples = append(samples, sample{kind: 1, data: data})
		}
	}
	var goRows, cRows strings.Builder
	for _, row := range samples {
		fmt.Fprintf(&goRows, "{%d,[10]byte{", row.kind)
		fmt.Fprintf(&cRows, "{%d,{", row.kind)
		for _, value := range row.data {
			fmt.Fprintf(&goRows, "%d,", value)
			fmt.Fprintf(&cRows, "%d,", value)
		}
		goRows.WriteString("}},\n")
		cRows.WriteString("}},\n")
	}
	return source, declarations,
		strings.ReplaceAll(x87EncodedOriginalDriver, "SAMPLE_ROWS", goRows.String()),
		strings.ReplaceAll(x87EncodedTranslatedDriver, "SAMPLE_ROWS", cRows.String())
}

func x87EncodedRuntime(t *testing.T, execute bool) {
	t.Helper()
	execution := fixedLocalPackedCompileOnlyTools(t)
	if execute {
		execution = x86FloatCompareExecutionTools(t)
	}
	source, declarations, goDriver, cDriver := x87EncodedRuntimePrograms(t)
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, source, goDriver)
	var reference []byte
	if execute {
		reference = execution.run(t, original)
		if bytes.Count(reference, []byte{'\n'}) != 60 {
			t.Fatal("original Go did not execute all thirty patterns at both memory edges")
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, "amd64", execution.triple, api, X87Hardware)
			if err != nil || ir == "" {
				t.Fatal("complete ten-byte runtime source", err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					if !execute {
						execution.compileLLVM(t, "encoded-x87", ir, cDriver, level)
						return
					}
					actual := execution.compileAndRunLLVM(t, "encoded-x87", ir, cDriver, level)
					if !bytes.Equal(actual, reference) {
						t.Fatal("binary80/BCD payload or canaries differ from original Go")
					}
					t.Log("60 original-Go comparisons PASS, including exact guard-page ten-byte reads and writes")
				})
			}
		})
	}
}

func TestX86X87EncodedTenByteRuntimeObjects(t *testing.T) {
	x87EncodedRuntime(t, false)
}

const x87EncodedOriginalDriver = `package main
import (
    "fmt"
    "os"
    "syscall"
    "unsafe"
)
var samples = []struct {
    kind int
    data [10]byte
}{ SAMPLE_ROWS }
var kernels = []func(*[10]byte, *[10]byte){CopyBCD, CopyExtended}

func buffer(edge int, fill byte) ([]byte,int,func()) {
    data := make([]byte,32)
    start := 8
    release := func() {}
    if edge != 0 {
        page := os.Getpagesize()
        mapped, err := syscall.Mmap(-1,0,2*page,syscall.PROT_READ|syscall.PROT_WRITE,syscall.MAP_PRIVATE|syscall.MAP_ANON)
        if err != nil {
            panic(err)
        }
        if err := syscall.Mprotect(mapped[page:],syscall.PROT_NONE); err != nil {
            panic(err)
        }
        data, start = mapped[:page], page-10
        release = func() {
            if err := syscall.Munmap(mapped); err != nil {
                panic(err)
            }
        }
    }
    for index := range data {
        data[index] = fill
    }
    return data,start,release
}

func main() {
    for row,sample := range samples {
        for edge:=0; edge<2; edge++ {
            input, in, releaseInput := buffer(edge,0x5a)
            output, out, releaseOutput := buffer(edge,0xa5)
            copy(input[in:in+10],sample.data[:])
            kernels[sample.kind]((*[10]byte)(unsafe.Pointer(&input[in])),(*[10]byte)(unsafe.Pointer(&output[out])))
            fmt.Printf("%d %d %x %x\n",row,edge,input[in-8:],output[out-8:])
            releaseInput()
            releaseOutput()
        }
    }
}
`

const x87EncodedTranslatedDriver = `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
extern void CopyBCD(uint8_t *,uint8_t *);
extern void CopyExtended(uint8_t *,uint8_t *);
static const struct { unsigned kind; uint8_t data[10]; } samples[] = { SAMPLE_ROWS };
static void (*kernels[])(uint8_t *,uint8_t *) = {CopyBCD,CopyExtended};

static uint8_t *buffer(unsigned edge, uint8_t fill, size_t *length, size_t *start) {
    *length = edge ? (size_t)sysconf(_SC_PAGESIZE) : 32;
    *start = edge ? *length-10 : 8;
    uint8_t *data = edge ? mmap(NULL,2*(*length),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) : malloc(*length);
    if (data == MAP_FAILED || !data) {
        exit(2);
    }
    if (edge && mprotect(data+*length,*length,PROT_NONE)) {
        exit(2);
    }
    memset(data,fill,*length);
    return data;
}

static void print_bytes(const uint8_t *data, size_t length) {
    for (size_t index=0; index<length; index++) {
        printf("%02x",data[index]);
    }
}

int main(void) {
    for (unsigned row=0; row<sizeof(samples)/sizeof(samples[0]); row++) {
        for (unsigned edge=0; edge<2; edge++) {
            size_t inputLength, outputLength, in, out;
            uint8_t *input = buffer(edge,0x5a,&inputLength,&in);
            uint8_t *output = buffer(edge,0xa5,&outputLength,&out);
            memcpy(input+in,samples[row].data,10);
            kernels[samples[row].kind](input+in,output+out);
            printf("%u %u ",row,edge);
            print_bytes(input+in-8,inputLength-in+8);
            putchar(' ');
            print_bytes(output+out-8,outputLength-out+8);
            putchar('\n');
            if (edge) {
                if (munmap(input,2*inputLength) || munmap(output,2*outputLength)) return 2;
            } else {
                free(input);
                free(output);
            }
        }
    }
    return 0;
}
`
