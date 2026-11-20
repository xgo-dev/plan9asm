package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARMRegisterAddressCompleteForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT registeraddresses(SB),$0-0\nCMP R0,R0\n")
	for _, offset := range []int64{0, 255, -255, 4096, -4096, 4097, -4097, 0x12345678, -0x12345678} {
		for _, suffix := range []string{"", ".S", ".EQ", ".NE.S"} {
			for _, registers := range [][2]string{{"R0", "R1"}, {"R11", "R1"}, {"R0", "R11"}, {"R13", "R14"}} {
				fmt.Fprintf(&source, "MOVW%s $%d(%s),%s\n", suffix, offset, registers[0], registers[1])
			}
		}
	}
	source.WriteString("RET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple,
			Sigs: map[string]FuncSig{"registeraddresses": {Name: "registeraddresses", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "register-addresses.ll", "register-addresses.o", ir)
	}
}

func TestARMRegisterAddressRejectsNonGoForms(t *testing.T) {
	var instructions []string
	for _, op := range []string{"MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		instructions = append(instructions, op+" $4(R0),R1")
	}
	for _, suffix := range []string{".P", ".W", ".U", ".S.P"} {
		instructions = append(instructions, "MOVW"+suffix+" $4(R0),R1")
	}
	instructions = append(instructions, "MOVW $4(R0),PC", "MOVW $4(R0),SP", "MOVW $4(PC),R1")
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT invalidaddress(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"invalidaddress": {Name: "invalidaddress", Ret: Void}},
			}); err == nil {
				t.Fatalf("accepted Go-illegal register address: %s", instruction)
			}
		})
	}
}

// Reference the actual ADD/SUB expansion, not a second translation or an
// encode/decode roundtrip. Large constants use Go's literal-R11 + ADD row.
func armRegisterAddressExpected(input, scratch uint32, offset int64, flags, execute bool, base, destination string) [3]uint32 {
	result, status, newScratch := uint32(0x89abcdef), uint32(6), scratch
	if destination == "R11" {
		result = scratch
	}
	if !execute {
		return [3]uint32{result, status, newScratch}
	}
	left := input
	if base == "R11" {
		left = scratch
	}
	// These fixture classes are independently witnessed by Go's object: the
	// four irregular constants use literal/MVN R11 + ADD, the others ADD/SUB.
	large := offset == 4097 || offset == -4097 || offset == 0x12345678 || offset == -0x12345678
	if large {
		newScratch = uint32(offset)
		if base == "R11" {
			left = newScratch
		}
	}
	right := uint32(offset)
	subtract := !large && offset < 0
	if subtract {
		right = uint32(-offset)
		result = left - right
	} else {
		result = left + right
	}
	if flags {
		status = 0
		if int32(result) < 0 {
			status |= 8
		}
		if result == 0 {
			status |= 4
		}
		if subtract && left >= right || !subtract && uint64(left)+uint64(right) > 0xffffffff {
			status |= 2
		}
		signed := int64(int32(left)) + int64(int32(right))
		if subtract {
			signed = int64(int32(left)) - int64(int32(right))
		}
		if signed < -2147483648 || signed > 2147483647 {
			status |= 1
		}
	}
	if destination == "R11" {
		newScratch = result
	}
	return [3]uint32{result, status, newScratch}
}

func armRegisterAddressFixture() (string, map[string]FuncSig, string, string) {
	var source, cDecls, cChecks, goDecls, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, offset := range []int64{0, 255, -255, 4096, -4096, 4097, -4097, 0x12345678, -0x12345678} {
		for _, flags := range []bool{false, true} {
			for _, condition := range []string{"", ".EQ", ".NE"} {
				for _, registers := range [][2]string{{"R0", "R1"}, {"R11", "R1"}, {"R0", "R11"}} {
					name := fmt.Sprintf("register_address_%d", len(sigs))
					suffix := condition
					if flags {
						suffix += ".S"
					}
					fmt.Fprintf(&source, "TEXT %s(SB),$0-12\nMOVW input+0(FP),R0\nMOVW scratch+4(FP),R11\nMOVW $0x89abcdef,R1\nCMP R3,R3\nMOVW%s $%d(%s),%s\nMOVW out+8(FP),R4\nMOVW %s,0(R4)\nMOVW $0,R2\nORR.MI $8,R2\nORR.EQ $4,R2\nORR.CS $2,R2\nORR.VS $1,R2\nMOVW R2,4(R4)\nMOVW R11,8(R4)\nRET\n", name, suffix, offset, registers[0], registers[1], registers[1])
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{I32, I32, Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: I32, Index: 0, Field: -1},
							{Offset: 4, Type: I32, Index: 1, Field: -1},
							{Offset: 8, Type: Ptr, Index: 2, Field: -1},
						}},
					}
					fmt.Fprintf(&cDecls, "extern void %s(uint32_t,uint32_t,uint32_t*);\n", name)
					fmt.Fprintf(&goDecls, "func %s(input,scratch uint32,out *[3]uint32)\n", name)
					for _, input := range []uint32{0, 1, 0xffffffff, 0x7fffffff, 0x80000000} {
						const scratch = uint32(0x13579bdf)
						want := armRegisterAddressExpected(input, scratch, offset, flags, condition != ".NE", registers[0], registers[1])
						fmt.Fprintf(&cChecks, "%s(UINT32_C(%d),UINT32_C(%d),out);\nif(out[0]!=UINT32_C(%d)||out[1]!=UINT32_C(%d)||out[2]!=UINT32_C(%d)) { fprintf(stderr,\"%s input=%d got=%%x/%%x/%%x\\n\",out[0],out[1],out[2]); return 1; }\n", name, input, scratch, want[0], want[1], want[2], name, input)
						fmt.Fprintf(&goChecks, "%s(%d,%d,&out)\nif out != [3]uint32{%d,%d,%d} { panic(\"%s Go oracle\") }\n", name, input, scratch, want[0], want[1], want[2], name)
					}
				}
			}
		}
	}
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDecls.String() + "int main(void) { uint32_t out[3];\n" + cChecks.String() + "return 0;\n}\n"
	goMain := "package main\n" + goDecls.String() + "func main() { var out [3]uint32\n" + goChecks.String() + "}\n"
	return source.String(), sigs, cMain, goMain
}

func TestCrossLinuxRuntimeMatrixARMRegisterAddress(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("actual ARM register-address execution is required by the Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM runtime oracle requires a Linux driver")
	}
	for _, tool := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	source, sigs, cMain, goMain := armRegisterAddressFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source = strings.ReplaceAll(source, "TEXT register_", "TEXT ·register_")
	for name, data := range map[string]string{
		"go.mod":  "module armregisteraddressoracle\n\ngo 1.20\n",
		"main.go": goMain, "oracle_arm.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=2", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM register-address oracle: %v\n%s", err, output)
	}
	t.Log("native Go ARM register-address value/NZCV/R11 oracle passed")
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "register_address", triple, ir, cMain,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
