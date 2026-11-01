package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This certificate describes a generated executable, not a source/ABI grant.
type x87IA32Executable struct {
	path string
	size int64
	hash [32]byte
	info os.FileInfo
}

func x87IA32ArtifactMode(mode os.FileMode, host string) bool {
	// Windows can inspect a cross-compiled ELF but does not expose Unix
	// execute bits. Native Unix runs still require them; ELF PF_X, entry,
	// identity, complete bytes and static linkage are checked on every host.
	return mode.IsRegular() && (host == "windows" || mode&0111 != 0)
}

func x87IA32StaticExecutable(name string) (x87IA32Executable, error) {
	var result x87IA32Executable
	info, err := os.Lstat(name)
	if err != nil || !x87IA32ArtifactMode(info.Mode(), runtime.GOOS) ||
		info.Size() <= 0 || info.Size() > 64<<20 {
		return result, fmt.Errorf("IA32 executable must be a bounded regular file: %v", err)
	}
	// Bind Windows' lazy Lstat file ID while the path still names the original,
	// before comparing it with the independently opened descriptor.
	if !os.SameFile(info, info) {
		return result, fmt.Errorf("IA32 executable physical identity is unavailable")
	}
	physical, err := filepath.EvalSymlinks(name)
	if err != nil {
		return result, err
	}
	physical, err = filepath.Abs(physical)
	if err != nil {
		return result, err
	}
	file, err := os.Open(physical)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return result, fmt.Errorf("IA32 executable identity changed: %v", err)
	}
	object, err := elf.NewFile(file)
	if err != nil {
		return result, err
	}
	if object.Class != elf.ELFCLASS32 || object.Data != elf.ELFDATA2LSB ||
		object.Machine != elf.EM_386 || object.Type != elf.ET_EXEC {
		return result, fmt.Errorf("IA32 direct execution requires a static ELF32 EM_386 executable")
	}
	entry := false
	for _, program := range object.Progs {
		if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
			return result, fmt.Errorf("IA32 executable has an interpreter or dynamic runtime")
		}
		if program.Type == elf.PT_LOAD &&
			(program.Off > uint64(opened.Size()) || program.Filesz > uint64(opened.Size())-program.Off ||
				program.Filesz > program.Memsz || program.Memsz > ^uint64(0)-program.Vaddr) {
			return result, fmt.Errorf("IA32 executable has an unbound load extent")
		}
		if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 &&
			object.Entry >= program.Vaddr && object.Entry-program.Vaddr < program.Filesz {
			entry = true
		}
	}
	for _, section := range object.Sections {
		if section.Type == elf.SHT_DYNAMIC {
			return result, fmt.Errorf("IA32 executable has dynamic dependencies")
		}
	}
	if !entry {
		return result, fmt.Errorf("IA32 executable entry lacks file-backed executable code")
	}
	digest := sha256.New()
	if count, err := io.Copy(digest, io.NewSectionReader(file, 0, opened.Size())); err != nil || count != opened.Size() {
		return result, fmt.Errorf("IA32 executable digest failed: %v", err)
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() ||
		!after.ModTime().Equal(info.ModTime()) {
		return result, fmt.Errorf("IA32 executable changed during inspection: %v", err)
	}
	result.path, result.size = physical, opened.Size()
	result.info = opened
	copy(result.hash[:], digest.Sum(nil))
	return result, nil
}

func (executable x87IA32Executable) verify() error {
	actual, err := x87IA32StaticExecutable(executable.path)
	if err != nil || executable.info == nil || !os.SameFile(actual.info, executable.info) ||
		actual.path != executable.path || actual.size != executable.size || actual.hash != executable.hash {
		return fmt.Errorf("IA32 executable changed or is unbound: %v", err)
	}
	return nil
}

func x87IA32NativeEnvironment(goos, goarch, kernel, cpuinfo, mappings string, host *elf.File) error {
	if goos != "linux" || goarch != "amd64" || strings.TrimSpace(kernel) != "x86_64" ||
		host == nil || host.Class != elf.ELFCLASS64 || host.Machine != elf.EM_X86_64 {
		return fmt.Errorf("required IA32 direct oracle needs an actual Linux/AMD64 host")
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	if fields["vendor_id"] != "GenuineIntel" && fields["vendor_id"] != "AuthenticAMD" {
		return fmt.Errorf("native IA32 CPU identity is not observed")
	}
	flags := " " + fields["flags"] + " "
	if !strings.Contains(flags, " fpu ") || !strings.Contains(flags, " cmov ") {
		return fmt.Errorf("native IA32 x87/P6 capability is not observed")
	}
	lower := strings.ToLower(mappings)
	if strings.TrimSpace(mappings) == "" || strings.Contains(lower, "qemu") || strings.Contains(lower, "rosetta") {
		return fmt.Errorf("native process mappings are missing or contain an emulator")
	}
	return nil
}

func x87IA32Capture(t *testing.T, executable string, args []string, dir string, env []string) ([]byte, error) {
	t.Helper()
	actual, err := exec.LookPath(executable)
	if err != nil {
		return nil, err
	}
	actual, err = filepath.EvalSymlinks(actual)
	if err != nil {
		return nil, err
	}
	actual, err = filepath.Abs(actual)
	if err != nil {
		return nil, err
	}
	originalInfo, err := os.Stat(actual)
	if err != nil {
		return nil, err
	}
	digest := func() ([32]byte, error) {
		var result [32]byte
		file, err := os.Open(actual)
		if err != nil {
			return result, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
			return result, fmt.Errorf("unbound native oracle executable: %v", err)
		}
		hash := sha256.New()
		if count, err := io.Copy(hash, io.LimitReader(file, (512<<20)+1)); err != nil || count != info.Size() {
			return result, fmt.Errorf("native oracle tool digest failed: %v", err)
		}
		copy(result[:], hash.Sum(nil))
		return result, nil
	}
	before, err := digest()
	if err != nil {
		return nil, err
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	// Retain the requested basename: registered tool aliases can dispatch on it.
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir, command.Env = dir, env
	output, runErr := runtimeOracleCombinedOutput(ctx, command)
	after, guardErr := digest()
	afterInfo, statErr := os.Stat(actual)
	resolved, pathErr := exec.LookPath(executable)
	if pathErr == nil {
		resolved, pathErr = filepath.EvalSymlinks(resolved)
	}
	if pathErr == nil {
		resolved, pathErr = filepath.Abs(resolved)
	}
	if guardErr != nil || statErr != nil || pathErr != nil || resolved != actual ||
		!os.SameFile(originalInfo, afterInfo) || before != after {
		return output, fmt.Errorf("native oracle executable changed: run=%v guard=%v", runErr, guardErr)
	}
	t.Logf("actual executable=%s sha256=%x argv=%q", actual, before, args)
	return output, runErr
}

func x87IA32RunDirect(t *testing.T, executable x87IA32Executable, args []string, env []string) []byte {
	t.Helper()
	if err := executable.verify(); err != nil {
		t.Fatal(err)
	}
	output, runErr := x87IA32Capture(t, executable.path, args, "", env)
	guardErr := executable.verify()
	if runErr != nil || guardErr != nil {
		t.Fatalf("required native IA32 execution failed (no emulator fallback): run=%v guard=%v\n%s", runErr, guardErr, output)
	}
	t.Logf("IA32 direct ELF bytes=%d sha256=%x argv=%q", executable.size, executable.hash, args)
	return output
}

func x87IA32BuildOriginalGo(t *testing.T) x87IA32Executable {
	t.Helper()
	dir := x87FlagCompareOriginalDirectory(t, "386")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	env := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOROOT="+runtime.GOROOT(), "GOFLAGS=", "GOEXPERIMENT=", "GOOS=linux",
		"GOARCH=386", "CGO_ENABLED=0", "GOMAXPROCS=2")
	version, err := x87IA32Capture(t, goBinary, []string{"version"}, dir, env)
	if err != nil || !strings.HasPrefix(string(version), "go version "+runtime.Version()+" ") {
		t.Fatalf("native oracle SDK identity mismatch: %v\n%s", err, version)
	}
	executable := filepath.Join(dir, "original.test")
	output, err := x87IA32Capture(t, goBinary,
		[]string{"test", "-c", "-p=2", "-vet=off", "-o", executable, "."}, dir, env)
	if err != nil || len(output) != 0 {
		t.Fatalf("original Go IA32 compile failed: %v\n%s", err, output)
	}
	result, err := x87IA32StaticExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual SDK=%s original Go static IA32 ELF bytes=%d sha256=%x (compile only)",
		runtime.Version(), result.size, result.hash)
	return result
}

func x87IA32OriginalGoDirect(t *testing.T) {
	t.Helper()
	executable := x87IA32BuildOriginalGo(t)
	output := x87IA32RunDirect(t, executable,
		[]string{"-test.run=^TestCompleteStatus$", "-test.count=1", "-test.v"}, os.Environ())
	complete := regexp.MustCompile(`\A=== RUN   TestCompleteStatus\n--- PASS: TestCompleteStatus \([0-9]+\.[0-9]+s\)\nPASS\n\z`)
	if !complete.Match(output) {
		t.Fatalf("original Go complete 7744-sample oracle did not finish:\n%s", output)
	}
	t.Log("32 initialized kernels × 121 IEEE pairs × 2 seeds; all six flags, LAHF, SETcc and byte canaries")
}

func x87IA32CompileAndRunDirect(t *testing.T, llc, ir, main string) {
	t.Helper()
	dir := t.TempDir()
	llPath, object := filepath.Join(dir, "original.ll"), filepath.Join(dir, "original.o")
	mainPath, binaryPath := filepath.Join(dir, "main.c"), filepath.Join(dir, "translated")
	for name, contents := range map[string]string{llPath: ir, mainPath: main} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output, err := x87IA32Capture(t, llc,
		[]string{"-mtriple=i386-unknown-linux-gnu", "-filetype=obj", llPath, "-o", object}, dir, os.Environ())
	if err != nil || len(output) != 0 {
		t.Fatalf("LLVM22 IA32 object failed: %v\n%s", err, output)
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal(err)
	}
	output, err = x87IA32Capture(t, compiler,
		[]string{"-static", "-no-pie", object, mainPath, "-O2", "-o", binaryPath, "-lm"}, dir, os.Environ())
	if err != nil || len(output) != 0 {
		t.Fatalf("static native IA32 C link failed: %v\n%s", err, output)
	}
	executable, err := x87IA32StaticExecutable(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if output := x87IA32RunDirect(t, executable, nil, os.Environ()); len(output) != 0 {
		t.Fatalf("native IA32 C oracle produced unexpected diagnostics: %s", output)
	}
}

func x87IA32PreflightStatus(output []byte) error {
	if len(output) != 64 {
		return fmt.Errorf("native IA32 status preflight requires exactly 8 complete observations")
	}
	for index := 0; index < 8; index++ {
		row := output[index*8 : (index+1)*8]
		flags := binary.LittleEndian.Uint32(row) & 0x8d5
		if flags != 0x40 || row[4] != 0x42 || row[5] != 0 || row[6] != 0 || row[7] != 0 {
			return fmt.Errorf("native IA32 x87 preflight row%d flags=%x LAHF=%x; emulator/ISA mismatch", index, flags, row[4])
		}
	}
	return nil
}

func x87IA32NativePreflight(t *testing.T) {
	t.Helper()
	var source strings.Builder
	source.WriteString(".text\n.globl _start\n_start:\n")
	index := 0
	for _, operation := range []string{"fcomi", "fcomip", "fucomi", "fucomip"} {
		for _, seed := range []uint32{0, 0x8d5} {
			fmt.Fprintf(&source, "fninit\nfldl value\nfldl value\npushl $%d\npopfl\n%s %%st(1),%%st\npushfl\npopl %%eax\nmovl %%eax,result+%d\nlahf\nmovb %%ah,result+%d\n",
				seed, operation, index*8, index*8+4)
			index++
		}
	}
	source.WriteString("movl $4,%eax\nmovl $1,%ebx\nmovl $result,%ecx\nmovl $64,%edx\nint $0x80\nmovl $1,%eax\nxorl %ebx,%ebx\nint $0x80\n.data\n.balign 8\nvalue: .quad 0\nresult: .zero 64\n.section .note.GNU-stack,\"\",@progbits\n")
	dir := t.TempDir()
	input, executable := filepath.Join(dir, "preflight.s"), filepath.Join(dir, "preflight")
	if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if err != nil {
		t.Fatal(err)
	}
	output, err := x87IA32Capture(t, compiler,
		[]string{"-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none,-e,_start", input, "-o", executable}, dir, os.Environ())
	if err != nil || len(output) != 0 {
		t.Fatalf("native IA32 physical preflight build failed: %v\n%s", err, output)
	}
	sealed, err := x87IA32StaticExecutable(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := x87IA32PreflightStatus(x87IA32RunDirect(t, sealed, nil, os.Environ())); err != nil {
		t.Fatal(err)
	}
	t.Log("actual direct IA32 physical preflight: 4 original opcodes × 2 seeds, full six flags and LAHF")
}
