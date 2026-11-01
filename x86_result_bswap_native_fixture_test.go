package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86ByteSwapNativeRow struct {
	name, op, register string
	role               int // Complete translated value, sparse byte, or saved FLAGS.
}

var x86ByteSwapNativeValues = []uint64{
	0, 1, 128, 255, 256, 65536, 0x1000000, 0x100000000,
	0x10000000000, 0x1000000000000, 0x100000000000000,
	0x8000000000000000, 0x1122334455667788, 0xffffffff,
	0xffffffff00000000, ^uint64(0),
}

func x86ByteSwapNativeRows(t *testing.T, arch string) (string, string, []x86ByteSwapNativeRow) {
	t.Helper()
	source, declarations := x86ByteSwapObjectFixture(t, arch)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	var rows []x86ByteSwapNativeRow
	for _, fn := range file.Funcs {
		row := x86ByteSwapNativeRow{name: strings.TrimPrefix(fn.Sym, "·")}
		count := 0
		for _, ins := range fn.Instrs {
			if _, known := x86ByteSwapSpecs[ins.Op]; !known {
				continue
			}
			if _, _, err := x86ByteSwapProperties(ins.Op, ins, arch); err != nil {
				t.Fatal(err)
			}
			if count != 0 && (row.op != string(ins.Op) || row.register != string(ins.Args[0].Reg)) {
				t.Fatal("complete native fixture changed its byte-permutation sequence")
			}
			row.op, row.register = string(ins.Op), string(ins.Args[0].Reg)
			count++
		}
		if strings.HasPrefix(row.name, "Sparse") {
			row.role = 1
		} else if strings.HasPrefix(row.name, "Status") {
			row.role = 2
		}
		if count != 1+row.role%2 {
			t.Fatal("complete original/translated native fixture lost an instruction", row)
		}
		rows = append(rows, row)
	}
	return source, declarations, rows
}

func x86ByteSwapNativeKernel(row x86ByteSwapNativeRow) string {
	count := 1 + row.role%2
	return "TEXT kernel(SB),4,$0-0\n" + strings.Repeat(row.op+" "+row.register+"\n", count) + "RET\n"
}

// This test-only encoder expectation checks the complete standalone Go kernel,
// including RET. It is not a source admission or an executable-entry capability.
func x86ByteSwapNativeKernelBytes(row x86ByteSwapNativeRow) []byte {
	registers := strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15")
	index := -1
	for i, register := range registers {
		if register == row.register {
			index = i
		}
	}
	if index < 0 || row.op != "BSWAPL" && row.op != "BSWAPQ" {
		return nil
	}
	var instruction []byte
	if row.op == "BSWAPQ" {
		instruction = append(instruction, 0x48|byte(index/8))
	} else if index >= 8 {
		instruction = append(instruction, 0x41)
	}
	instruction = append(instruction, 0x0f, 0xc8+byte(index%8))
	code := bytes.Repeat(instruction, 1+row.role%2)
	return append(code, 0xc3)
}

// The explicit Linux C adapter supplies only a numerical register and safe
// status seed to the complete original Go opcode kernel. It is NOT native Go
// ABI0 execution. All callee-saved registers and the real stack are restored;
// DF is observed before being cleared for the C ABI. No translator role follows.
func x86ByteSwapNativeAdapter(arch string, row x86ByteSwapNativeRow, index int, code []byte) (string, error) {
	registers := map[string]string{"AX": "ax", "CX": "cx", "DX": "dx", "BX": "bx", "BP": "bp", "SI": "si", "DI": "di"}
	for i := 8; i < 16; i++ {
		registers[fmt.Sprintf("R%d", i)] = fmt.Sprintf("r%d", i)
	}
	destination, valid := registers[row.register]
	if !valid || row.register == "BP" && arch != "386" || row.role < 0 || row.role > 2 ||
		arch != "amd64" && arch != "386" || arch == "386" && (row.op == "BSWAPQ" || strings.HasPrefix(row.register, "R")) ||
		!bytes.Equal(code, x86ByteSwapNativeKernelBytes(row)) {
		return "", fmt.Errorf("unbound original BSWAP kernel/bank/mode")
	}
	word, suffix, sp, accumulator, pointer, temporary := 8, "q", "%rsp", "%rax", "%rdx", "%r11"
	saved := []string{"%rbx", "%rbp", "%r12", "%r13", "%r14", "%r15"}
	if arch == "386" {
		word, suffix, sp, accumulator, pointer, temporary = 4, "l", "%esp", "%eax", "%edx", "%ecx"
		saved = []string{"%ebx", "%ebp", "%esi", "%edi"}
		destination = "%e" + destination
	} else if strings.HasPrefix(destination, "r") {
		destination = "%" + destination
	} else {
		destination = "%r" + destination
	}
	var assembly strings.Builder
	fmt.Fprintf(&assembly, ".text\nBSwapOriginalBody%d:\n.byte ", index)
	for i, value := range code {
		if i != 0 {
			assembly.WriteByte(',')
		}
		fmt.Fprintf(&assembly, "0x%02x", value)
	}
	fmt.Fprintf(&assembly, "\n.globl BSwapOriginal%d\nBSwapOriginal%d:\n", index, index)
	for _, register := range saved {
		fmt.Fprintf(&assembly, "push%s %s\n", suffix, register)
	}
	fmt.Fprintf(&assembly, "sub%s $%d,%s\n", suffix, 7*word, sp)
	if arch == "amd64" {
		fmt.Fprintf(&assembly, "movq %%rdi,%d(%s)\nmovq %%rsi,%d(%s)\nmovq %%rdx,%d(%s)\n", word, sp, 2*word, sp, 3*word, sp)
	} else {
		for argument := 0; argument < 3; argument++ {
			fmt.Fprintf(&assembly, "movl %d(%s),%%ecx\nmovl %%ecx,%d(%s)\n", (12+argument)*word, sp, (1+argument)*word, sp)
		}
	}
	for i, slot := range []int{0, 4, 5, 6} {
		move := "movl"
		constant := []uint64{0x5a5a5a5a, 0x6b6b6b6b, 0x13579bdf, 0x2468ace}[i]
		if arch == "amd64" {
			move, constant = "movabsq", constant|constant<<32
		}
		fmt.Fprintf(&assembly, "%s $0x%x,%s\nmov%s %s,%d(%s)\n", move, constant, temporary, suffix, temporary, slot*word, sp)
	}
	fmt.Fprintf(&assembly, "mov%s %d(%s),%s\npush%s %d(%s)\npopf%s\ncall BSwapOriginalBody%d\n", suffix, word, sp, destination, suffix, 2*word, sp, suffix, index)
	// Capture the destination before using any scratch register. PUSH/MOV/POP
	// do not disturb status; the complete original kernel also includes RET.
	fmt.Fprintf(&assembly, "push%s %s\npushf%s\npop%s %s\nmov%s %d(%s),%s\nmov%s %s,0(%s)\npop%s %s\ncld\n", suffix, destination, suffix, suffix, accumulator, suffix, 4*word, sp, pointer, suffix, accumulator, pointer, suffix, accumulator)
	for i, slot := range []int{0, 4, 5, 6} {
		fmt.Fprintf(&assembly, "mov%s %d(%s),%s\nmov%s %s,%d(%s)\n", suffix, slot*word, sp, temporary, suffix, temporary, (i+1)*word, pointer)
	}
	fmt.Fprintf(&assembly, "add%s $%d,%s\n", suffix, 7*word, sp)
	for i := len(saved) - 1; i >= 0; i-- {
		fmt.Fprintf(&assembly, "pop%s %s\n", suffix, saved[i])
	}
	assembly.WriteString("ret\n")
	return fmt.Sprintf("__asm__(%q);\nextern word BSwapOriginal%d(word,word,word*);\n", assembly.String(), index), nil
}

func x86ByteSwapNativeDriver(t *testing.T, arch string, rows []x86ByteSwapNativeRow, adapters string) string {
	t.Helper()
	typ, stack := "uint64_t", "movq %%rsp,%0"
	if arch == "386" {
		typ, stack = "uint32_t", "movl %%esp,%0"
	}
	var declarations, registrations, values strings.Builder
	for index, row := range rows {
		functions := [3]string{"NULL", "NULL", "NULL"}
		functions[row.role] = row.name
		declaration := "extern word %s(word);\n"
		if row.role == 1 {
			declaration = "extern uint8_t %s(uint8_t);\n"
		} else if row.role == 2 {
			declaration = "extern word %s(word,word);\n"
		}
		fmt.Fprintf(&declarations, declaration, row.name)
		width := 4
		if row.op == "BSWAPQ" {
			width = 8
		}
		fmt.Fprintf(&registrations, "{BSwapOriginal%d,%s,%s,%s,%d,%d},\n", index, functions[0], functions[1], functions[2], width, row.role)
	}
	for _, value := range x86ByteSwapNativeValues {
		fmt.Fprintf(&values, "UINT64_C(0x%x),", value)
	}
	return `#include <stdint.h>
#include <stdio.h>
typedef ` + typ + ` word;
` + adapters + declarations.String() + `
static const struct {
    word (*original)(word,word,word*);
    word (*value)(word);
    uint8_t (*sparse)(uint8_t);
    word (*status)(word,word);
    unsigned bytes,role;
} rows[]={
` + registrations.String() + `};
static __attribute__((always_inline)) inline uintptr_t stack_pointer(void) {
    uintptr_t value;
    __asm__ volatile("` + stack + `" : "=r"(value) : : "memory");
    return value;
}
static word reverse_bytes(word value,unsigned bytes) {
    volatile uint8_t input[8],output[8];
    for(unsigned byte=0;byte<bytes;byte++)input[byte]=(uint8_t)(value>>(8*byte));
    for(unsigned byte=0;byte<bytes;byte++)output[byte]=input[bytes-1-byte];
    word result=0;
    for(unsigned byte=0;byte<bytes;byte++)result|=(word)output[byte]<<(8*byte);
    return result;
}
int main(void) {
    const uint64_t values[]={` + values.String() + `};
    unsigned checks=0;
    for(unsigned value=0;value<sizeof(values)/sizeof(values[0]);value++)
        for(unsigned status=0;status<128;status++) {
            word seed=2;
            const unsigned positions[]={0,2,4,6,7,11,10};
            for(unsigned bit=0;bit<7;bit++)seed|=(word)(status>>bit&1)<<positions[bit];
            for(unsigned row=0;row<sizeof(rows)/sizeof(rows[0]);row++) {
                const word input=(word)values[value],left=(word)0x31415926,right=(word)0x27182818;
                word observed[]={left,0,0,0,0,0,right};
                const uintptr_t before=stack_pointer();
                word raw=rows[row].original(input,seed,observed+1);
                if(stack_pointer()!=before||observed[0]!=left||observed[6]!=right)return 1;
                const word mask=(word)0x8d5|1024;
                if((observed[1]&mask)!=(seed&mask))return 2;
                const uint32_t canaries[]={0x5a5a5a5a,0x6b6b6b6b,0x13579bdf,0x2468ace};
                for(unsigned i=0;i<4;i++) {
                    uint64_t want=canaries[i];
                    if(sizeof(word)==8)want|=want<<32;
                    if(observed[i+2]!=(word)want)return 3;
                }
                word expected=reverse_bytes(input,rows[row].bytes);
                if(rows[row].role==1)expected=reverse_bytes(expected,rows[row].bytes);
                if(raw!=expected)return 4;
                word actual=rows[row].role==0?rows[row].value(input):
                    rows[row].role==1?rows[row].sparse((uint8_t)input):rows[row].status(input,seed);
                word want=rows[row].role==1?(uint8_t)input:expected;
                if(rows[row].role==2){actual&=mask;want=seed&mask;}
                if(stack_pointer()!=before||actual!=want) {
                    fprintf(stderr,"row=%u value=%llx status=%x raw=%llx LLVM=%llx want=%llx\n",
                        row,(unsigned long long)input,status,(unsigned long long)raw,
                        (unsigned long long)actual,(unsigned long long)want);
                    return 5;
                }
                checks++;
            }
        }
    printf("BSWAP original-Go opcode bytes and complete LLVM fixture: %u checks, six FLAGS/DF and stack canaries\n",checks);
    return 0;
}
`
}

func TestX86ByteSwapNativeFixtureKeepsCompleteSourceAndBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source, declarations, rows := x86ByteSwapNativeRows(t, arch)
		want := 32
		if arch == "386" {
			want = 9
		}
		if len(rows) != want || len(x86ByteSwapNativeValues) != 16 {
			t.Fatal("complete native fixture denominator changed")
		}
		var adapters strings.Builder
		for index, row := range rows {
			code := x86ByteSwapNativeKernelBytes(row)
			adapter, err := x86ByteSwapNativeAdapter(arch, row, index, code)
			if err != nil || !strings.Contains(adapter, "\\ncld\\n") || strings.Contains(adapter, "blockaddress") {
				t.Fatal("test-only adapter lost its restore boundary", err)
			}
			adapters.WriteString(adapter)
			if got, err := x86ByteSwapNativeAdapter(arch, row, index, code[:len(code)-1]); err == nil || got != "" {
				t.Fatal("incomplete original Go kernel accepted")
			}
		}
		for _, register := range []string{"SP", "R16"} {
			row := x86ByteSwapNativeRow{op: "BSWAPL", register: register}
			if got, err := x86ByteSwapNativeAdapter(arch, row, 0, x86ByteSwapNativeKernelBytes(row)); err == nil || got != "" {
				t.Fatal("test adapter borrowed a physical stack/unknown bank", register)
			}
		}
		driver := x86ByteSwapNativeDriver(t, arch, rows, adapters.String())
		if strings.Count(driver, "extern word BSwapOriginal") != want ||
			!strings.Contains(driver, "status<128") || !strings.Contains(driver, "stack_pointer()!=before") {
			t.Fatal("native six-status/DF/original/canary axes incomplete")
		}
		// All three ordinary consumers still receive the complete original
		// fixture, not the standalone opcode adapter or a cropped function.
		x86ResultGPSIMDAdmissionAPIs(t, arch, source, declarations, true)
	}
}

func TestX86ByteSwapNativeOpcodeObserverDoesNotAuthorizeRawSource(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		source, declarations := x86ByteSwapObjectFixture(t, target.arch)
		var raw strings.Builder
		for _, line := range strings.Split(source, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && (fields[0] == "BSWAPL" || fields[0] == "BSWAPQ") {
				code := x86ByteSwapNativeKernelBytes(x86ByteSwapNativeRow{op: fields[0], register: fields[1]})
				for _, value := range code[:len(code)-1] {
					fmt.Fprintf(&raw, "BYTE $%d\n", value)
				}
			} else {
				fmt.Fprintln(&raw, line)
			}
		}
		if strings.Count(raw.String(), "TEXT ·") != strings.Count(source, "TEXT ·") {
			t.Fatal("raw observer negative cropped the complete fixture")
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, raw.String(), declarations, target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("test-only original opcode observer granted physical raw result authority", err)
				}
			})
		}
	}
}
