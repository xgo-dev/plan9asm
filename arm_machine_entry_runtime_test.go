package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Snapshots are source instructions, not observations made by the private LLVM
// bridge. The independent Go object and native call sites expose every incoming
// and restored register, including registers unused by the source computation.
func armMachineEntryRegisterSource() string {
	var source strings.Builder
	source.WriteString("TEXT oracleEntry(SB),516,$0-0\n")
	for i := 0; i < 13; i++ {
		reg := fmt.Sprintf("R%d", i)
		if i == 10 {
			reg = "g"
		}
		fmt.Fprintf(&source, " MOVW %s,%d(R0)\n", reg, 40+i*4)
	}
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&source, " MOVD F%d,%d(R0)\n", i, 96+i*8)
	}
	source.WriteString(" MOVW FPCR,R3\n MOVW R3,224(R0)\n MOVW -8(R13),R3\n MOVW R3,440(R0)\n")
	source.WriteString(strings.SplitN(armMachineEntrySource, "\n", 2)[1])
	return strings.Replace(source.String(), " RET\n", " MOVD $2.0,F7\n RET\n", 1)
}

func armMachineEntryGoCaller() string {
	var source strings.Builder
	source.WriteString("TEXT oracle(SB),4,$16-16\n MOVW out+12(FP),R0\n")
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&source, " MOVD $%d.0,F%d\n", i+1, i)
	}
	source.WriteString(" MOVW fpscr+8(FP),R4\n MOVW R4,FPCR\n MOVW R13,R12\n MOVW R12,28(R0)\n MOVW g,228(R0)\n MOVW $0x13579bdf,R12\n MOVW R12,-8(R13)\n")
	source.WriteString(" MOVW value+0(FP),R1\n MOVW $77,R2\n MOVW status+4(FP),R3\n")
	for i := 4; i < 13; i++ {
		if i != 10 {
			fmt.Fprintf(&source, " MOVW $%d,R%d\n", i, i)
		}
	}
	source.WriteString(" MOVW R3,CPSR\n BL oracleEntry(SB)\n")
	for i := 0; i < 13; i++ {
		reg := fmt.Sprintf("R%d", i)
		if i == 10 {
			reg = "g"
		}
		fmt.Fprintf(&source, " MOVW %s,%d(R0)\n", reg, 240+i*4)
	}
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&source, " MOVD F%d,%d(R0)\n", i, 304+i*8)
	}
	source.WriteString(" MOVW R14,R4\n MOVW R4,32(R0)\n MOVW CPSR,R4\n MOVW R4,36(R0)\n MOVW FPCR,R4\n MOVW R4,432(R0)\n MOVW R13,R4\n MOVW R4,436(R0)\n MOVW -8(R13),R4\n MOVW R4,444(R0)\n MOVW $0,R4\n MOVW R4,FPCR\n RET\n")
	return source.String()
}

func armMachineEntryNativeCaller(fourAligned bool) string {
	assembly := []string{".syntax unified", ".text", ".arm", ".global runOracle", ".type runOracle,%function", "runOracle:", "push {r4-r11,r12,lr}"}
	if fourAligned {
		assembly = append(assembly, "sub sp,sp,#4")
	}
	for i := 0; i < 16; i++ {
		assembly = append(assembly, fmt.Sprintf("vmov.f64 d%d,#%d.0", i, i+1))
	}
	assembly = append(assembly, "vmsr fpscr,r3", "mov r12,sp", "str r12,[r0,#28]", "adr r12,1f", "str r12,[r0,#32]", "ldr r12,=0x13579bdf", "str r12,[sp,#-8]", "mov r3,r2", "mov r2,#77")
	for i := 4; i < 13; i++ {
		assembly = append(assembly, fmt.Sprintf("mov r%d,#%d", i, i))
	}
	assembly = append(assembly, "str r10,[r0,#228]", "msr APSR_nzcvq,r3", "bl oracleEntry", "1:")
	for i := 0; i < 13; i++ {
		assembly = append(assembly, fmt.Sprintf("str r%d,[r0,#%d]", i, 240+i*4))
	}
	for i := 0; i < 16; i++ {
		assembly = append(assembly, fmt.Sprintf("vstr d%d,[r0,#%d]", i, 304+i*8))
	}
	assembly = append(assembly, "mrs r4,cpsr", "str r4,[r0,#36]", "vmrs r4,fpscr", "str r4,[r0,#432]", "mov r4,sp", "str r4,[r0,#436]", "ldr r4,[sp,#-8]", "str r4,[r0,#444]", "mov r4,#0", "vmsr fpscr,r4")
	if fourAligned {
		assembly = append(assembly, "add sp,sp,#4")
	}
	assembly = append(assembly, "pop {r4-r11,r12,pc}")
	return fmt.Sprintf("__asm__(%q);\n", strings.Join(assembly, "\n")+"\n")
}

func TestCrossLinuxRuntimeMatrixARMMachineEntryPhysicalState(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	entrySource := armMachineEntryRegisterSource()
	for _, profile := range []struct {
		name       string
		writesNZCV bool
	}{
		{"preserved", false}, {"source_nzcv_writer", true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			source := entrySource
			if profile.writesNZCV {
				source = strings.Replace(source, " RET\n", " ADD.S $1,R5\n RET\n", 1)
			}
			runARMMachineEntryPhysicalState(t, llc, source, profile.writesNZCV)
		})
	}
}

func runARMMachineEntryPhysicalState(t *testing.T, llc, entrySource string, writesNZCV bool) {
	t.Helper()
	goSource := armMachineEntryGoCaller() + entrySource
	goMain := `package main
import (
 "fmt"
 "math"
 "unsafe"
)
func oracle(value, status, fpscr uint32, out *[112]uint32)
func main() {
 for flags := uint32(0); flags < 32; flags++ {
  for rounding := uint32(0); rounding < 4; rounding++ {
   var out [112]uint32
   status := (flags&15)<<28 | (flags>>4)<<27
   fpscr := rounding<<22
   oracle(0x89abcdef, status, fpscr, &out)
   want := uint32(77)
   if flags&4 != 0 { want = 7 }
   exitStatus := status
   if WRITES_NZCV { exitStatus &= 0x08000000 }
   if out[0]&0xf8000000 != status || out[1] != out[7] || out[1] != out[109] ||
    out[2] != out[8] || out[3] != 0x89abcdef || out[4] != 0 || out[5] != 0x3ff00000 ||
    out[6] != want || out[9]&0xf8000000 != exitStatus || out[56] != fpscr || out[108] != fpscr ||
    out[110] != 0x13579bdf || out[111] != 0x13579bdf {
    panic(fmt.Sprintf("Go physical core flags=%x fpscr=%x out=%x", flags, fpscr, out))
   }
   for i := 0; i < 13; i++ {
    initial := uint32(i)
    switch i {
    case 0: initial = uint32(uintptr(unsafe.Pointer(&out)))
    case 1: initial = 0x89abcdef
    case 2: initial = 77
    case 3: initial = status
    case 10: initial = out[57]
    }
    final := initial
    if i == 2 { final = want }
    if i == 3 { final = 0x89abcdef }
    if i == 5 && WRITES_NZCV { final = 6 }
    if out[10+i] != initial || out[60+i] != final {
     panic(fmt.Sprintf("Go R%d flags=%x entry=%x want=%x exit=%x want=%x", i, flags, out[10+i], initial, out[60+i], final))
    }
   }
   for i := 0; i < 16; i++ {
    initial := math.Float64bits(float64(i+1))
    final := initial
    if i == 7 { final = math.Float64bits(2) }
    got := uint64(out[24+i*2]) | uint64(out[25+i*2])<<32
    exit := uint64(out[76+i*2]) | uint64(out[77+i*2])<<32
    if got != initial || exit != final {
     panic(fmt.Sprintf("Go D%d entry=%x want=%x exit=%x want=%x", i, got, initial, exit, final))
    }
   }
  }
 }
 fmt.Println("128 Go physical GP0..12/D0..15/FPSCR/NZCVQ/SP/LR vectors passed")
}
`
	runARMGoSourceOracle(t, goSource, strings.ReplaceAll(goMain, "WRITES_NZCV", fmt.Sprint(writesNZCV)))
	file, err := Parse(ArchARM, entrySource)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, armMachineEntryOptions("armv7-unknown-linux-gnueabihf"))
	if err != nil {
		t.Fatal(err)
	}
	// This native assembly call site supplies the physical contract. No C call
	// pretends the address-only carrier has a guessed zero-argument signature.
	cMain := `#include <stdint.h>
#include <stdio.h>
extern void runOracle(uint32_t*,uint32_t,uint32_t,uint32_t);
CALL_SITE
int main(void) {
 for(unsigned f=0; f<32; f++) {
  for(unsigned rounding=0; rounding<4; rounding++) {
   uint32_t out[112]={0}, status=((f&15)<<28)|((f>>4)<<27), fpscr=rounding<<22;
   runOracle(out,0x89abcdefu,status,fpscr);
   uint32_t want=(f&4)?7:77;
   uint32_t exitStatus=WRITES_NZCV ? status&0x08000000u : status;
   if((out[0]&0xf8000000u)!=status || out[1]!=out[7] || out[1]!=out[109] ||
    out[2]!=out[8] || out[3]!=0x89abcdefu || out[4]!=0 || out[5]!=0x3ff00000 ||
    out[6]!=want || (out[9]&0xf8000000u)!=exitStatus || out[56]!=fpscr || out[108]!=fpscr ||
    out[110]!=0x13579bdfu || out[111]!=0x13579bdfu) {
    fprintf(stderr,"LLVM physical core flags=%x fpscr=%x entryStatus=%x exitStatus=%x sp=%x/%x/%x lr=%x/%x stack=%x fp=%x:%x pred=%x entryFpscr=%x exitFpscr=%x\n",
     f,fpscr,out[0],out[9],out[1],out[7],out[109],out[2],out[8],out[3],out[5],out[4],out[6],out[56],out[108]);
    return 1;
   }
   for(unsigned i=0; i<13; i++) {
    uint32_t initial=i;
    switch(i) {
    case 0: initial=(uintptr_t)out; break;
    case 1: initial=0x89abcdefu; break;
    case 2: initial=77; break;
    case 3: initial=status; break;
    case 10: initial=out[57]; break;
    }
    uint32_t final=initial;
    if(i==2) final=want;
    if(i==3) final=0x89abcdefu;
    if(i==5 && WRITES_NZCV) final=6;
    if(out[10+i]!=initial || out[60+i]!=final) {
     fprintf(stderr,"LLVM R%u flags=%x entry=%x want=%x exit=%x want=%x\n",i,f,out[10+i],initial,out[60+i],final);
     return 1;
    }
   }
   for(unsigned i=0; i<16; i++) {
    union { double d; uint64_t bits; } expected={(double)(i+1)}, final=expected;
    if(i==7) final.d=2.0;
    uint64_t initial=(uint64_t)out[24+i*2]|(uint64_t)out[25+i*2]<<32;
    uint64_t exit=(uint64_t)out[76+i*2]|(uint64_t)out[77+i*2]<<32;
    if(initial!=expected.bits || exit!=final.bits) {
     fprintf(stderr,"LLVM D%u entry=%llx want=%llx exit=%llx want=%llx\n",i,(unsigned long long)initial,(unsigned long long)expected.bits,(unsigned long long)exit,(unsigned long long)final.bits);
     return 1;
    }
   }
  }
 }
 return 0;
}
`
	writerValue := "0"
	if writesNZCV {
		writerValue = "1"
	}
	cMain = strings.ReplaceAll(cMain, "WRITES_NZCV", writerValue)
	for _, alignment := range []string{"eight", "four"} {
		t.Run(alignment, func(t *testing.T) {
			main := strings.Replace(cMain, "CALL_SITE", armMachineEntryNativeCaller(alignment == "four"), 1)
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "machine_entry", "armv7-unknown-linux-gnueabihf", ir, main,
				[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
		})
	}
}
