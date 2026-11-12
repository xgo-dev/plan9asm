package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestARMStatusMoveMatchesGoFieldsAndConditions(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	conditions := []string{"", ".AL", ".EQ", ".NE", ".CS", ".CC", ".HS", ".LO", ".MI", ".PL", ".VS", ".VC", ".HI", ".LS", ".GE", ".LT", ".GT", ".LE"}
	for _, condition := range conditions {
		for _, operands := range []string{"CPSR,R1", "R1,CPSR", "$0xff,CPSR", "$0xff000000,CPSR"} {
			instruction := "MOVW" + condition + " " + operands
			source := "TEXT status(SB),4,$0-0\n MOVW $0,R0\n MOVW $0x60000000,R1\n CMP R0,R0\n " + instruction + "\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{
					"status": {Name: "status", Ret: Void},
				}})
				if err != nil {
					t.Fatalf("%s %s: %v", triple, instruction, err)
				}
				if !strings.HasPrefix(operands, "CPSR,") && (!strings.Contains(ir, "msr cpsr_fs, $0") || strings.Contains(ir, "cpsr_fsxc")) {
					t.Fatalf("Go asm5 type36/37 selects fields fs (0xc), not fsxc: %s", instruction)
				}
				compileLLVMToObject(t, llc, triple, "status-move.ll", "status-move.o", ir)
			}
		}
	}
}

func TestARMStatusMoveGoObjectAndLLVMEncoderWitness(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "status.s")
	const assembly = `TEXT status(SB),4,$0-0
 MOVW CPSR,R1
 MOVW R1,CPSR
 MOVW $0xff,CPSR
 MOVW $0xff000000,CPSR
 MOVW.EQ $0xff000000,CPSR
 RET
`
	if err := os.WriteFile(source, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-S", "-p", "status", "-o", filepath.Join(dir, "status.o"), source)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm")
	listing, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(listing), "00 10 0f e1 01 f0 2c e1 ff f0 2c e3 ff f4 2c e3") || !strings.Contains(string(listing), "ff f4 2c 03") {
		t.Fatalf("actual Go MRS/MSR and EQ masks differ: %v\n%s", err, listing)
	}
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc not found")
	}
	cmd = exec.Command(mc, "-triple=armv7-unknown-linux-gnueabihf", "-show-encoding")
	cmd.Stdin = strings.NewReader("mrs r1,cpsr\nmsr cpsr_fs,r1\nmsr cpsr_fs,#255\nmsr cpsr_fs,#0xff000000\nmsreq cpsr_fs,#0xff000000\nmrs r1,spsr\nmsr spsr_fs,r1\n")
	encoding, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM22 ARM PSR encoder: %v\n%s", err, encoding)
	}
	for _, bytes := range []string{"[0x00,0x10,0x0f,0xe1]", "[0x01,0xf0,0x2c,0xe1]", "[0xff,0xf0,0x2c,0xe3]", "[0xff,0xf4,0x2c,0xe3]", "[0xff,0xf4,0x2c,0x03]", "[0x00,0x10,0x4f,0xe1]", "[0x01,0xf0,0x6c,0xe1]"} {
		if !strings.Contains(string(encoding), bytes) {
			t.Fatalf("LLVM22 PSR encoding lacks %s:\n%s", bytes, encoding)
		}
	}
	t.Logf("actual Go status object encodings:\n%s\nLLVM22 independent MC encoding (SPSR is compile-only, not user-mode execution):\n%s", listing, encoding)
}

func TestARMStatusMoveRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"MOVW SPSR,R0", "MOVW R0,SPSR", "MOVW $0,SPSR", "MOVW APSR,R0", "MOVW CPSR_f,R0", "MOVW CS,R0",
		"MOVW CPSR,R10", "MOVW R10,CPSR", "WORD $3775856640.0",
		"MOVW.S CPSR,R0", "MOVW.F CPSR,R0", "MOVW.W CPSR,R0", "MOVW.P CPSR,R0", "MOVW.U CPSR,R0",
		"MOVW.S R0,CPSR", "MOVW.F R0,CPSR", "MOVW.W R0,CPSR", "MOVW.P R0,CPSR", "MOVW.U R0,CPSR",
		"MOVW $0x12345678,CPSR", "MOVW $0.0,CPSR", "MOVW CPSR,(R0)", "MOVW (R0),CPSR", "MOVW value+0(FP),CPSR", "MOVB CPSR,R0",
	} {
		t.Run(strings.ReplaceAll(instruction, "/", "_"), func(t *testing.T) {
			source := "TEXT status(SB),4,$0-0\n MOVW $0,R0\n CMP R0,R0\n " + instruction + "\n RET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"status": {Name: "status", Ret: Void},
			}})
			if err == nil || ir != "" {
				t.Fatalf("invalid Go status form became LLVM success: %s: %v; actual parsed instructions: %+v", instruction, err, file.Funcs[0].Instrs)
			}
		})
	}
}

func TestARMStatusMoveKeepsConditionalSaveAndClobberFailures(t *testing.T) {
	for _, body := range []string{
		"MOVW $0,R0\n CMP R0,R0\n MOVW.EQ CPSR,R7\n MOVW R7,CPSR",
		"MOVW $0,R0\n CMP R0,R0\n WORD $0x010f7000\n MOVW R7,CPSR",
		"MOVW $0,R0\n CMP R0,R0\n MOVW CPSR,R7\n WORD $0xffffffff\n MOVW R7,CPSR",
		"B done\n MOVW.F R0,CPSR\ndone:",
	} {
		source := "TEXT status(SB),4,$0-0\n " + body + "\n RET\n"
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
			"status": {Name: "status", Ret: Void},
		}})
		if err == nil || ir != "" {
			t.Fatalf("conditional save/unknown machine effect/dead invalid grammar invented status: %s: %v", body, err)
		}
	}
}

func TestARMStatusMoveRawFieldsAndSourceProof(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, word := range []uint32{0xe10f1000, 0xe12cf001, 0xe128f001, 0xe32cf0ff, 0xe328f4ff, 0x012cf001, 0x010f1000} {
		source := fmt.Sprintf("TEXT status(SB),4,$0-0\n MOVW $0,R0\n MOVW $0x60000000,R1\n CMP R0,R0\n WORD $%#x\n MOVW CPSR,R0\n RET\n", word)
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{
				"status": {Name: "status", Ret: Void},
			}})
			if err != nil {
				t.Fatalf("typed raw PSR word %#x: %v", word, err)
			}
			compileLLVMToObject(t, llc, triple, "raw-status-move.ll", "raw-status-move.o", ir)
		}
	}
	for _, instruction := range []string{
		"MOVW CPSR,R0", "MOVW R7,CPSR", "MOVW CPSR,R15", "MOVW R15,CPSR",
		"WORD $0xe14f0000", "WORD $0xe16cf001", "WORD $0xe36cf0ff", // SPSR requires privileged exception state.
		"WORD $0xe121f001", "WORD $0xe122f001", "WORD $0xe12ff001", // CPSR control/extension fields.
		"WORD $0xe10ff000", "WORD $0xe12cf00f", // Architectural PC is not a zero GPR.
	} {
		setup := " MOVW $0,R0\n CMP R0,R0\n"
		if instruction == "MOVW CPSR,R0" {
			setup = ""
		}
		source := "TEXT status(SB),4,$0-0\n" + setup + " " + instruction + "\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
			"status": {Name: "status", Ret: Void},
		}})
		if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
			t.Fatalf("unproved native/privileged status became success: %s: %v", instruction, err)
		}
	}
}

func TestARMPreemptOriginalSourceRetainsIncomingStatusContext(t *testing.T) {
	rootOutput, err := exec.Command("go", "env", "GOROOT").CombinedOutput()
	if err != nil {
		t.Fatalf("Go root: %v: %s", err, rootOutput)
	}
	sourcePath := filepath.Join(strings.TrimSpace(string(rootOutput)), "src", "runtime", "preempt_arm.s")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := ParseWithDefines(ArchARM, string(source), GoAssemblerDefines("linux", "arm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 || file.Funcs[0].FrameSize != 0 || !strings.Contains(string(source), "MOVW CPSR, R0") || !strings.Contains(string(source), "MOVW.P 192(R13), R15") {
		t.Fatal("original incoming status/stack-PC source contract changed")
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", ResolveSym: func(string) string { return "runtime.asyncPreempt" }, Sigs: map[string]FuncSig{
		"runtime.asyncPreempt": {Name: "runtime.asyncPreempt", Ret: Void},
	}})
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "native-entry state bridge") || ir != "" {
		t.Fatalf("original asyncPreempt must retain missing incoming-machine-state failure: %v", err)
	}
	contextFailure := err
	cmd := exec.Command("go", "list", "-export", "-f", "{{.Export}}", "runtime")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	archive, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Go runtime object: %v: %s", err, archive)
	}
	objectBytes, err := exec.Command("go", "tool", "pack", "p", strings.TrimSpace(string(archive)), "preempt_arm.o").CombinedOutput()
	if err != nil {
		t.Fatalf("actual selected Go preempt object extraction: %v: %s", err, objectBytes)
	}
	object := filepath.Join(t.TempDir(), "preempt_arm.o")
	if err := os.WriteFile(object, objectBytes, 0600); err != nil {
		t.Fatal(err)
	}
	listing, err := exec.Command("go", "tool", "objdump", "-s", "^runtime.asyncPreempt$", object).CombinedOutput()
	if err != nil || !strings.Contains(string(listing), "preempt_arm.s") || !strings.Contains(string(listing), "e10f0000") || !strings.Contains(string(listing), "e12cf000") {
		t.Fatalf("actual selected Go preempt status object witness missing: %v\n%s", err, listing)
	}
	t.Logf("actual Go selected runtime object; original LLVM source remains FAILED: %v\n%s", contextFailure, listing)
}
