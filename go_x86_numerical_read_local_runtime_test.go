//go:build go1.27 && unix

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Retain this fixture's actual inputs, outputs and bounded command terminal.
// This is not another process runner: runtimeOracleCombinedOutput still owns
// the fresh group, cancellation, pipe EOF and cleanup under its original budget.
func numericalLocalRuntimeCommand(t *testing.T, command *exec.Cmd, sources ...string) []byte {
	t.Helper()
	paths := append(append([]string(nil), sources...), command.Args[1:]...)
	capture := func() map[string][]byte {
		files := make(map[string][]byte)
		for _, name := range paths {
			if !filepath.IsAbs(name) {
				continue
			}
			if info, err := os.Stat(name); err == nil && info.Mode().IsRegular() {
				data, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				files[name] = data
			}
		}
		return files
	}
	before := capture()
	tool, err := os.ReadFile(command.Path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bounded := exec.CommandContext(ctx, command.Path, command.Args[1:]...)
	bounded.Dir, bounded.Env = command.Dir, command.Env
	started := time.Now()
	output, runErr := runtimeOracleCombinedOutput(ctx, bounded)
	after := capture()
	pid, exitCode, exited, groupGone := 0, -1, false, false
	if bounded.Process != nil {
		pid = bounded.Process.Pid
		groupGone = errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH)
	}
	if bounded.ProcessState != nil {
		exitCode, exited = bounded.ProcessState.ExitCode(), bounded.ProcessState.Exited()
	}
	if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
		folder := filepath.Join(artifact, "numerical-local-runtime", fmt.Sprintf("%x", sha256.Sum256([]byte(t.Name()))))
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.CreateTemp(folder, "command-*.json")
		if err != nil {
			t.Fatal(err)
		}
		data, encodeErr := json.MarshalIndent(struct {
			Binary, Directory, Error string
			Args, Environment        []string
			ToolSHA256               [32]byte
			PID, PGID, ExitCode      int
			Exited, GroupGone        bool
			Started                  time.Time
			ElapsedMS                int64
			Before, After            map[string][]byte
			Output                   []byte
		}{bounded.Path, bounded.Dir, fmt.Sprint(runErr), bounded.Args, bounded.Env, sha256.Sum256(tool),
			pid, pid, exitCode, exited, groupGone, started, time.Since(started).Milliseconds(), before, after, output}, "", "  ")
		if encodeErr == nil {
			_, encodeErr = file.Write(data)
		}
		if closeErr := file.Close(); encodeErr != nil || closeErr != nil {
			t.Fatal("retain actual numerical runtime command", encodeErr, closeErr)
		}
	}
	for name, input := range before {
		if !bytes.Equal(input, after[name]) {
			t.Fatal("runtime command changed an input", name)
		}
	}
	if runErr != nil || !exited || exitCode != 0 || !groupGone {
		t.Fatalf("actual numerical runtime command %q: %v (exit=%d groupGone=%v)\n%s", bounded.Args, runErr, exitCode, groupGone, output)
	}
	return output
}

func numericalLocalRuntimeC(snapshot uint64) string {
	return fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
%s
%s
_Alignas(4096) unsigned char cpu[4096];
NUMERICAL_STORAGE_ALIAS("internal/cpu.X86", cpu);
extern uint64_t numericalLocal(uint64_t,uint64_t,uint64_t,uint64_t);
int main(void) {
    memset(cpu,0xa5,sizeof(cpu));
    uint64_t snapshot=UINT64_C(0x%016x);
    for(unsigned i=0;i<8;i++) cpu[64+i]=(unsigned char)(snapshot>>(8*i));
    const uint64_t values[]={0,UINT64_MAX,UINT64_C(0x8877665544332211)};
    for(unsigned round=0;round<2;round++) {
        cpu[64]=(unsigned char)round;
        uint64_t word=0;
        for(unsigned i=0;i<4;i++) word|=(uint64_t)cpu[64+i]<<(8*i);
        for(unsigned i=0;i<3;i++) {
            uint64_t got=numericalLocal(UINT64_C(0x1122334455667788),17,values[i],29);
            uint64_t want=values[i]+word;
            if(got!=want) {
                fprintf(stderr,"local round/row=%%u/%%u got=%%llx want=%%llx\n",round,i,
                        (unsigned long long)got,(unsigned long long)want);
                return 1;
            }
            printf("%%016llx\n",(unsigned long long)got);
        }
        for(unsigned i=0;i<sizeof(cpu);i++) {
            unsigned char want=0xa5;
            if(i>=64&&i<72) want=(unsigned char)(snapshot>>(8*(i-64)));
            if(i==64) want=(unsigned char)round;
            if(cpu[i]!=want) return 2;
        }
    }
    pid_t child=fork();
    if(child<0) return 3;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        numerical_fault_begin(cpu,sizeof(cpu));
        if(mprotect(cpu,sizeof(cpu),PROT_NONE)) _exit(4);
        (void)numericalLocal(1,2,3,4);
        _exit(5);
    }
    int status=0;
    if(waitpid(child,&status,0)!=child) return 6;
    if(!numerical_fault_status(status)) return 7;
    return 0;
}
`, numericalRuntimeStorageAliases, numericalRuntimeFaultObservationC, snapshot)
}

func numericalLocalOriginalGoRuntime(t *testing.T, pkg GoPackage, options Options, execution x86FloatCompareExecution) (uint64, []byte) {
	t.Helper()
	request := options.NumericalReads.source.request
	dir := t.TempDir()
	main := fmt.Sprintf(`package main
import (
    "fmt"
    frame %q
)
func cpuWord() uint64
func cpuSet(value byte)
func main() {
    snapshot:=cpuWord()
    old:=byte(snapshot)
    defer cpuSet(old)
    fmt.Printf("CPU %%016x\n",snapshot)
    values:=[]uint64{0,^uint64(0),0x8877665544332211}
    for round:=byte(0);round<2;round++ {
        cpuSet(round)
        word:=uint64(uint32(cpuWord()))
        results:=make([]uint64,len(values))
        for i,value:=range values {
            results[i]=frame.Value(0x1122334455667788,17,value,29)
            if results[i]!=value+word { panic("original local numerical oracle mismatch") }
        }
        cpuSet(old)
        for _,value:=range results { fmt.Printf("%%016x\n",value) }
    }
}
`, pkg.Path)
	assembly := "#include \"textflag.h\"\nTEXT ·cpuWord(SB),NOSPLIT,$0-8\nMOVQ internal∕cpu·X86+64(SB),AX\nMOVQ AX,ret+0(FP)\nRET\nTEXT ·cpuSet(SB),NOSPLIT,$0-1\nMOVB value+0(FP),AL\nMOVB AL,internal∕cpu·X86+64(SB)\nRET\n"
	var sources []string
	for name, data := range map[string]string{
		"go.mod":  "module localnumericaloracle\ngo 1.27\nrequire " + pkg.Path + " v0.0.0\nreplace " + pkg.Path + " => " + strconv.Quote(filepath.ToSlash(request.Directory)) + "\n",
		"main.go": main, "cpu_amd64.s": assembly,
	} {
		name = filepath.Join(dir, name)
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, name)
	}
	executable := filepath.Join(dir, "original")
	command := exec.Command(request.GoBinary, "build", "-p=1", "-mod=mod", "-o", executable, ".")
	command.Dir, command.Env = dir, request.Environment
	numericalLocalRuntimeCommand(t, command, sources...)
	args := execution.command(executable)
	output := numericalLocalRuntimeCommand(t, exec.Command(args[0], args[1:]...))
	lines := bytes.SplitN(output, []byte("\n"), 2)
	if len(lines) != 2 || !bytes.HasPrefix(lines[0], []byte("CPU ")) {
		t.Fatal("actual original local oracle did not return CPU snapshot and values")
	}
	snapshot, err := strconv.ParseUint(string(lines[0][4:]), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, lines[1]
}

func numericalLocalMutableRuntime(t *testing.T, execution x86FloatCompareExecution, original bool) {
	t.Helper()
	_, pkg, file, bound, source, frame := numericalLocalJoinedFactory(t)
	ir := numericalFamilyTranslate(t, "context", pkg, file, bound)
	ir += fmt.Sprintf("define i64 @numericalLocal(i64 %%a,i64 %%b,i64 %%c,i64 %%d) {\n %%value=call i64 %s(i64 %%a,i64 %%b,i64 %%c,i64 %%d)\n ret i64 %%value\n}\n", llvmGlobal(pkg.Path+".Value"))
	snapshot, expected := uint64(0), []byte(nil)
	if original {
		snapshot, expected = numericalLocalOriginalGoRuntime(t, pkg, bound, execution)
	}
	opt := findLLVM22Tool("opt")
	if opt == "" || execution.llc == "" {
		t.Fatal("LLVM22 opt and llc required")
	}
	for _, passes := range []string{"none", "O2"} {
		t.Run("IR-"+passes, func(t *testing.T) {
			dir := t.TempDir()
			input, c := filepath.Join(dir, "input.ll"), filepath.Join(dir, "main.c")
			for name, data := range map[string]string{input: ir, c: numericalLocalRuntimeC(snapshot)} {
				if err := os.WriteFile(name, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if passes == "O2" {
				optimized := filepath.Join(dir, "optimized.ll")
				numericalLocalRuntimeCommand(t, exec.Command(opt, "-passes=default<O2>", "-S", input, "-o", optimized))
				input = optimized
			}
			for _, backend := range []string{"-O0", "-O2"} {
				t.Run("backend"+backend, func(t *testing.T) {
					dir := t.TempDir()
					object, executable := filepath.Join(dir, "local.o"), filepath.Join(dir, "local")
					numericalLocalRuntimeCommand(t, exec.Command(execution.llc, backend, "-mtriple="+execution.triple, "-filetype=obj", input, "-o", object))
					args := append(append([]string(nil), execution.compiler...), "-O2", object, c, "-o", executable)
					numericalLocalRuntimeCommand(t, exec.Command(args[0], args[1:]...))
					args = execution.command(executable)
					output := numericalLocalRuntimeCommand(t, exec.Command(args[0], args[1:]...))
					if original && !bytes.Equal(output, expected) {
						t.Fatalf("composed LLVM/C and actual original Go results differ\ngot: %s\nwant: %s", output, expected)
					}
				})
			}
		})
	}
	if err := source.Verify(bound.NumericalReads.context); err != nil {
		t.Fatal("runtime changed original numerical source/owner", err)
	}
	if err := frame.Verify(bound.NumericalReads.context); err != nil {
		t.Fatal("runtime changed independent original frame observation", err)
	}
}
