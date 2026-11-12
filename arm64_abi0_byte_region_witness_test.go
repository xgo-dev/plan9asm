package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/format"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// This file records compiler/assembler observations. Nothing captured here is
// an Options input, a source capability, or authority to discard result bytes.
type arm64ABI0RegionCase struct {
	name                  string
	move                  Op
	resultBits, storeBits int
}

func arm64ABI0RegionCases() []arm64ABI0RegionCase {
	var result []arm64ABI0RegionCase
	for _, test := range arm64NativeResultTailCases() {
		result = append(result, arm64ABI0RegionCase{
			name: test.name(), move: test.op,
			resultBits: test.resultBits, storeBits: test.storeBits,
		})
	}
	return append(result, arm64ABI0RegionCase{
		name: "Exact32", move: "MOVW", resultBits: 32, storeBits: 32,
	})
}

func (test arm64ABI0RegionCase) declaration() string {
	return fmt.Sprintf("func %s(input uint64, trace *[4]uint64) (result uint%d)\n",
		test.name, test.resultBits)
}

func (test arm64ABI0RegionCase) callee() string {
	return fmt.Sprintf(`TEXT ·%s(SB),4,$0-%d
	MOVD input+0(FP),R0
	MOVD trace+8(FP),R1
	MOVD $input+0(FP),R2
	MOVD R2,0(R1)
	MOVD $result+16(FP),R2
	MOVD R2,8(R1)
	MOVD RSP,R2
	MOVD R2,16(R1)
	MOVD R30,R2
	MOVD R2,24(R1)
	%s R0,result+16(FP)
	RET
`, test.name, 16+test.resultBits/8, test.move)
}

func (test arm64ABI0RegionCase) observer() string {
	load := map[int]string{8: "MOVBU", 16: "MOVHU", 32: "MOVWU"}[test.resultBits]
	return fmt.Sprintf(`TEXT ·Observe_%s(SB),4,$96-88
	MOVD input+0(FP),R0
	MOVD R0,8(RSP)
	ADD $40,RSP,R1
	MOVD R1,16(RSP)
	MOVD $0xfeedfacecafebeef,R1
	MOVD R1,24(RSP)
	MOVD $0x7ac35ef012345678,R1
	MOVD R1,32(RSP)
	MOVD R1,40(RSP)
	MOVD R1,48(RSP)
	MOVD R1,56(RSP)
	MOVD R1,64(RSP)
	MOVD RSP,R1
	MOVD R1,72(RSP)
	MOVD 0(RSP),R1
	MOVD R1,80(RSP)
	CALL ·%s(SB)
	MOVD R30,R3
	MOVD RSP,R1
	MOVD R1,after+64(FP)
	MOVD R3,returnPC+80(FP)
	%s 24(RSP),R0
	MOVD R0,value+8(FP)
	MOVD 24(RSP),R0
	MOVD R0,native+16(FP)
	MOVD 32(RSP),R0
	MOVD R0,guard+24(FP)
	MOVD 40(RSP),R0
	MOVD R0,incoming+32(FP)
	MOVD 48(RSP),R0
	MOVD R0,resultAddress+40(FP)
	MOVD 56(RSP),R0
	MOVD R0,calleeSP+48(FP)
	MOVD 72(RSP),R0
	MOVD R0,before+56(FP)
	MOVD 64(RSP),R0
	CMP R3,R0
	BNE broken
	MOVD 80(RSP),R0
	MOVD 0(RSP),R1
	CMP R0,R1
	BNE broken
	MOVD R0,savedLink+72(FP)
	RET
broken:
	UNDEF
`, test.name, test.name, load)
}

func arm64ABI0RegionDeclarations(cases []arm64ABI0RegionCase) string {
	var source strings.Builder
	source.WriteString("package main\n\n")
	for _, test := range cases {
		source.WriteString(test.declaration())
		fmt.Fprintf(&source, "func Observe_%s(input uint64) "+
			"(value,native,guard,incoming,resultAddress,calleeSP,before,after,savedLink,returnPC uint64)\n",
			test.name)
		fmt.Fprintf(&source, "func Typed_%s(input uint64, trace *[4]uint64) uint%d {\n"+
			"return %s(input,trace)\n}\n", test.name, test.resultBits, test.name)
	}
	return source.String()
}

func arm64ABI0RegionCode(t *testing.T, listing, name string) []byte {
	t.Helper()
	body := arm64ResultTailAuditSection(t, listing, name)
	var result []byte
	for _, row := range regexp.MustCompile(`(?m)^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`).FindAllStringSubmatch(body, -1) {
		data, err := hex.DecodeString(strings.ReplaceAll(row[1], " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, data...)
	}
	if len(result) == 0 {
		t.Fatalf("actual object listing has no code for %s", name)
	}
	return result
}

func arm64ABI0RegionCommand(t *testing.T, goos, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.CommandContext(ctx, goTool, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64",
		"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
	t.Logf("actual original command=%q cwd=%q target=%s/arm64 SDK=%s CGO=0 GOENV=off GOWORK=off GOFLAGS=empty",
		command.Args, command.Dir, goos, runtime.Version())
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual selected SDK command failed: %v\n%s", err, output)
	}
	return output
}

func arm64ABI0RegionRetain(t *testing.T, dir, role string, names ...string) {
	t.Helper()
	output := os.Getenv("PLAN9ASM_ABI0_REGION_EVIDENCE")
	if output == "" {
		return
	}
	identity := sha256.Sum256([]byte(t.Name() + "/" + role))
	output = filepath.Join(output, fmt.Sprintf("%x", identity[:]))
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatalf("evidence must not overwrite another observation: %v", err)
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("retained %s/%s bytes=%d SHA256=%x", output, name, len(data), sha256.Sum256(data))
	}
}

func TestARM64ABI0ByteRegionActualCompilerAndObjectWitness(t *testing.T) {
	cases := arm64ABI0RegionCases()
	if len(cases) != 10 {
		t.Fatalf("nine wide stores plus exact 4-byte control changed: %d", len(cases))
	}
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			var assembly strings.Builder
			for _, test := range cases {
				assembly.WriteString(strings.ReplaceAll(test.callee(), "·", "main·"))
			}
			for name, source := range map[string]string{
				"decl.go": arm64ABI0RegionDeclarations(cases), "original.s": assembly.String(),
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				t.Logf("first-party source %s bytes=%d SHA256=%x", name, len(source), sha256.Sum256([]byte(source)))
			}
			arm64ABI0RegionCommand(t, goos, dir, "tool", "asm", "-p", "main",
				"-gensymabis", "-o", "symabis", "original.s")
			listing := arm64ABI0RegionCommand(t, goos, dir, "tool", "asm", "-p", "main",
				"-S", "-o", "original.o", "original.s")
			compiled := arm64ABI0RegionCommand(t, goos, dir, "tool", "compile", "-p", "main",
				"-S", "-symabis", "symabis", "-o", "compiler.o", "decl.go")
			for _, test := range cases {
				code := arm64ABI0RegionCode(t, string(listing), "main."+test.name)
				// The final native STR has source R0, base SP and physical +24.
				want := map[int]uint32{16: 0x790033e0, 32: 0xb9001be0, 64: 0xf9000fe0}[test.storeBits]
				if len(code) < 8 || binary.LittleEndian.Uint32(code[len(code)-8:]) != want ||
					binary.LittleEndian.Uint32(code[len(code)-4:]) != 0xd65f03c0 {
					t.Fatalf("original native store/RET identity changed: %s code=%x want=%08x", test.name, code, want)
				}
				for _, name := range []string{"main." + test.name, "main.Typed_" + test.name} {
					body := arm64ResultTailAuditSection(t, string(compiled), name)
					// ABIInternal has two register arguments (16 bytes). Its
					// outgoing ABI0 region is a different, compiler-owned area.
					frame := regexp.MustCompile(`\tTEXT\t` + regexp.QuoteMeta(name) + `\(SB\),[^\n]*\$([0-9]+)-16\n`).FindStringSubmatch(body)
					if frame == nil {
						t.Fatalf("actual wrapper/caller has no typed 16-byte ABIInternal input extent: %s\n%s", name, body)
					}
					bytes, err := strconv.Atoi(frame[1])
					postRestore := strings.Contains(body, fmt.Sprintf("\tMOVD.P\t%d(RSP), R30\n", bytes))
					pairRestore := strings.Contains(body, "\tLDP\t-8(RSP), (R29, R30)\n") &&
						strings.Contains(body, fmt.Sprintf("\tADD\t$%d, RSP\n", bytes))
					if err != nil || bytes < 32 || bytes > 4096 ||
						!strings.Contains(body, fmt.Sprintf("\tMOVD.W\tR30, -%d(RSP)\n", bytes)) ||
						(!postRestore && !pairRestore) ||
						!strings.Contains(body, "\tCALL\tmain."+test.name+"(SB)\n") {
						t.Fatalf("actual caller does not reserve/call the complete native region: %s\n%s", name, body)
					}
					pair := strings.Contains(body, "\tSTP\t(R0, R1), 8(RSP)\n")
					individual := strings.Contains(body, "\tMOVD\tR0, 8(RSP)\n") &&
						strings.Contains(body, "\tMOVD\tR1, 16(RSP)\n")
					if !pair && !individual {
						t.Fatalf("actual arguments do not supply complete outgoing [8,24): %s\n%s", name, body)
					}
					load := map[int]string{8: "MOVBU", 16: "MOVHU", 32: "MOVWU"}[test.resultBits]
					for _, instruction := range []string{load + "\t24(RSP), R0", "RET\t(R30)"} {
						if !strings.Contains(body, "\t"+instruction+"\n") {
							t.Fatalf("actual typed caller mapping missing %q: %s\n%s", instruction, name, body)
						}
					}
					t.Logf("actual compiler source-bound %s:\n%s", name, body)
				}
				t.Logf("actual original code %s=%x; layout is observation, not native backing permission", test.name, code)
			}
			for _, name := range []string{"symabis", "original.o", "compiler.o"} {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || len(data) == 0 {
					t.Fatalf("missing actual artifact %s: %v", name, err)
				}
				t.Logf("actual SDK %s artifact %s bytes=%d SHA256=%x", runtime.Version(), name, len(data), sha256.Sum256(data))
			}
			arm64ABI0RegionRetain(t, dir, goos, "decl.go", "original.s", "symabis", "original.o", "compiler.o")
		})
	}
}

func TestARM64ABI0ByteRegionObservationDoesNotGrantSlots(t *testing.T) {
	for _, test := range arm64ABI0RegionCases() {
		if test.storeBits == test.resultBits {
			// Exact-width positive objects are independently required by
			// TestARM64NativeResultTailExactDeclaredWidthObjects. The trace
			// addresses here do not grant that positive a new pointer role.
			continue
		}
		pkg := mustGoPackage(t, "main", "package main\n"+test.declaration())
		sig, err := DeriveGoFuncABI0Signature("main."+test.name,
			pkg.Types.Scope().Lookup(test.name).(*types.Func), "arm64", types.SizesFor("gc", "arm64"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 16 ||
			frameTypeSize(sig.Frame.Results[0].Type, 8) != int64(test.resultBits/8) {
			t.Fatalf("declared layout acquired a padding slot: %#v", sig.Frame)
		}
		for _, role := range []string{"isolated", "native-caller", "code-address", "data-address"} {
			source := test.callee()
			declaration := test.declaration()
			switch role {
			case "native-caller":
				declaration += "func Observer(input uint64,trace *[4]uint64) uint64\n"
				source += fmt.Sprintf("TEXT ·Observer(SB),4,$48-24\nMOVD input+0(FP),R0\nMOVD R0,8(RSP)\n"+
					"MOVD trace+8(FP),R0\nMOVD R0,16(RSP)\nCALL ·%s(SB)\n"+
					"MOVD 24(RSP),R0\nMOVD R0,ret+16(FP)\nRET\n", test.name)
			case "code-address":
				declaration += "func Address() uintptr\n"
				source += fmt.Sprintf("TEXT ·Address(SB),4,$0-8\nMOVD $·%s(SB),R0\nMOVD R0,ret+0(FP)\nRET\n", test.name)
			case "data-address":
				source += fmt.Sprintf("DATA entry<>+0(SB)/8,$·%s(SB)\nGLOBL entry<>(SB),8,$8\n", test.name)
			}
			t.Run(test.name+"/"+role+"/original-Go-object", func(t *testing.T) {
				dir := t.TempDir()
				original := strings.ReplaceAll(source, "·", "main·")
				if err := os.WriteFile(filepath.Join(dir, "original.s"), []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				listing := arm64ABI0RegionCommand(t, "linux", dir, "tool", "asm",
					"-p", "main", "-S", "-o", "original.o", "original.s")
				object, err := os.ReadFile(filepath.Join(dir, "original.o"))
				if err != nil || len(object) == 0 {
					t.Fatalf("actual source role has no original object: %v", err)
				}
				arm64ABI0RegionRetain(t, dir, role, "original.s", "original.o")
				t.Logf("actual SDK=%s source bytes=%d SHA256=%x; object bytes=%d SHA256=%x; listing:\n%s",
					runtime.Version(), len(original), sha256.Sum256([]byte(original)), len(object), sha256.Sum256(object), listing)
			})
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(test.name+"/"+role+"/"+api, func(t *testing.T) {
					_, err := arm64ResultTailAuditTranslate(t, api, arm64LinuxGNUTriple, declaration, source)
					if test.storeBits > test.resultBits {
						if err == nil || !strings.Contains(err.Error(), "has no slot") {
							t.Fatalf("actual caller/allocation observation granted native padding: %v", err)
						}
						t.Logf("missing real storage/call-effect producer remains F: %v", err)
					}
				})
			}
		}
	}
}

func TestARM64ABI0ByteRegionExactFourByteDeclaredObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	declaration := "func Exact32(input uint64, trace *[4]uint64) (result uint32)\n"
	source := "TEXT ·Exact32(SB),4,$0-20\nMOVD input+0(FP),R0\nMOVW R0,result+16(FP)\nRET\n"
	for _, target := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc", "aarch64-unknown-freebsd"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target+"/"+api, func(t *testing.T) {
				ir, err := arm64ResultTailAuditTranslate(t, api, target, declaration, source)
				if err != nil {
					t.Fatalf("actual exact declared width must retain its ordinary contract: %v", err)
				}
				compileLLVMToObject(t, llc, target, "exact32.ll", "exact32.o", ir)
			})
		}
	}
}

func arm64ABI0ByteRegionOriginalBuild(t *testing.T, goos string) (string, string, []byte) {
	t.Helper()
	cases := arm64ABI0RegionCases()
	var assembly, driver strings.Builder
	driver.WriteString("package main\n\nimport \"fmt\"\n\nfunc main() {\nobservations:=0\n")
	for _, test := range cases {
		assembly.WriteString(test.callee())
		assembly.WriteString(test.observer())
		mask := ^uint64(0) >> uint(64-test.resultBits)
		storeMask := ^uint64(0) >> uint(64-test.storeBits)
		fmt.Fprintf(&driver, `for _, input := range []uint64{0,1,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fffffff,0x80000000,0xffffffff,0x123456789abcdef0,0xffffffffffffffff} {
	value,native,guard,incoming,resultAddress,calleeSP,before,after,savedLink,returnPC:=Observe_%s(input)
	wantNative:=(uint64(0xfeedfacecafebeef)&^uint64(0x%x))|(input&uint64(0x%x))
	if value!=input&uint64(0x%x)||native!=wantNative||guard!=0x7ac35ef012345678||
		incoming!=before+8||resultAddress!=before+24||calleeSP!=before||before!=after||savedLink==0||returnPC==0||returnPC&3!=0 {
		panic(fmt.Sprintf("%s input=%%x value=%%x native=%%x guard=%%x mapping=%%x/%%x SP=%%x/%%x/%%x links=%%x/%%x",input,value,native,guard,incoming,resultAddress,calleeSP,before,after,savedLink,returnPC))
	}
	var trace [4]uint64
	typed:=Typed_%s(input,&trace)
	if uint64(typed)!=input&uint64(0x%x)||trace[0]==0||trace[1]!=trace[0]+16||trace[2]+8!=trace[0]||trace[3]==0 {
		panic("actual typed caller/result mapping changed")
	}
	observations++
}
`, test.name, storeMask, storeMask, mask, test.name, test.name, mask)
	}
	driver.WriteString("fmt.Printf(\"ABI0 original same-call region observations %d\\n\",observations)\n}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module regionwitness\n\ngo 1.20\n",
		"decl.go": arm64ABI0RegionDeclarations(cases), "original_arm64.s": assembly.String(), "main.go": driver.String()} {
		if strings.HasSuffix(name, ".go") {
			formatted, err := format.Source([]byte(source))
			if err != nil {
				t.Fatalf("first-party generated Go source %s: %v", name, err)
			}
			source = string(formatted)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("first-party original source %s bytes=%d SHA256=%x", name, len(source), sha256.Sum256([]byte(source)))
	}
	executable := filepath.Join(dir, "original")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	t.Logf("actual original compiler=%q cwd=%q SDK=%s target=%s/arm64 CGO=0",
		command.Args, command.Dir, runtime.Version(), goos)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual original Go build: %v\n%s", err, output)
	}
	before, err := os.ReadFile(executable)
	if err != nil || len(before) == 0 {
		t.Fatalf("actual executable missing: %v", err)
	}
	return dir, executable, before
}

func TestARM64ABI0ByteRegionOriginalLinuxELFBuild(t *testing.T) {
	dir, _, data := arm64ABI0ByteRegionOriginalBuild(t, "linux")
	image, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if image.Class != elf.ELFCLASS64 || image.Machine != elf.EM_AARCH64 || image.Type != elf.ET_EXEC {
		t.Fatalf("required original Linux execution artifact has another identity: %#v", image.FileHeader)
	}
	for _, segment := range image.Progs {
		if segment.Type == elf.PT_INTERP {
			t.Fatal("CGO-disabled original ARM64 fixture unexpectedly needs an interpreter")
		}
	}
	arm64ABI0RegionRetain(t, dir, "original-Linux-build-only", "go.mod", "decl.go", "original_arm64.s", "main.go", "original")
	t.Logf("actual SDK=%s original Linux/ARM64 static ELF bytes=%d SHA256=%x; BUILD ONLY, no runtime P",
		runtime.Version(), len(data), sha256.Sum256(data))
}

func arm64ABI0ByteRegionOriginalRun(t *testing.T, goos string, runner []string) {
	t.Helper()
	dir, executable, before := arm64ABI0ByteRegionOriginalBuild(t, goos)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := append(append([]string(nil), runner...), executable)
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir = dir
	t.Logf("actual original execution=%q cwd=%q", command.Args, command.Dir)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	want := fmt.Sprintf("ABI0 original same-call region observations %d\n", len(arm64ABI0RegionCases())*13)
	if err != nil || string(output) != want {
		t.Fatalf("original full-region identity/bytes/canary/restoration: %v\n%s", err, output)
	}
	after, err := os.ReadFile(executable)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatalf("executed original artifact changed: %v", err)
	}
	arm64ABI0RegionRetain(t, dir, "executed-original", "go.mod", "decl.go", "original_arm64.s", "main.go", "original")
	t.Logf("actual SDK=%s target=%s/arm64 prefix=%q ELF-or-MachO bytes=%d SHA256=%x\n%s",
		runtime.Version(), goos, runner, len(before), sha256.Sum256(before), output)
	t.Log("source and machine observations only; no compiler-owned transport capability and no benchmark P")
}
