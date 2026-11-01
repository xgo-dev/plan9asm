package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

const arm64ResultTailAuditGo = `package tailaudit

func F(ptr *uint32, val uint32) uint32

func Caller(ptr *uint32, val uint32) uint32 {
	return F(ptr, val)
}
`

// This isolates the unchanged native-width result effect from Or32's separate
// atomic/CPU dispatch. It is not a replacement implementation of Or32.
const arm64ResultTailAuditASM = `TEXT ·F(SB),4,$0-20
	MOVD ptr+0(FP),R0
	MOVW val+8(FP),R1
	MOVD R1,ret+16(FP)
	RET
`

func arm64ResultTailAuditCommand(t *testing.T, goos, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual Go %s/arm64 %v: %v\n%s", goos, args, err, output)
	}
	return output
}

func arm64ResultTailAuditSection(t *testing.T, listing, name string) string {
	t.Helper()
	start := strings.Index(listing, name+" STEXT ")
	if start < 0 || (start > 0 && listing[start-1] != '\n') {
		t.Fatalf("actual compiler has no complete TEXT %s:\n%s", name, listing)
	}
	rest := listing[start:]
	if end := regexp.MustCompile(`\n[^\t\n]`).FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}
	return rest
}

// These are actual compiler observations, not a source-backed permission token.
// In particular a generated wrapper does not close every assembly caller.
func TestARM64ABI0ResultTailCompilerCallerObservation(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			for name, source := range map[string]string{
				"original.go": arm64ResultTailAuditGo,
				// Spell the fixture package explicitly. Historical asm -S keeps
				// the empty package placeholder for ·F despite its -p option;
				// this changes neither instruction operands nor native bytes.
				"original.s": strings.Replace(arm64ResultTailAuditASM, "·F", "tailaudit·F", 1),
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			arm64ResultTailAuditCommand(t, goos, dir, "tool", "asm", "-p", "tailaudit",
				"-gensymabis", "-o", "symabis", "original.s")
			asm := arm64ResultTailAuditCommand(t, goos, dir, "tool", "asm", "-p", "tailaudit",
				"-S", "-o", "original.o", "original.s")
			compiler := arm64ResultTailAuditCommand(t, goos, dir, "tool", "compile", "-p", "tailaudit",
				"-S", "-symabis", "symabis", "-o", "compiler.o", "original.go")

			section := arm64ResultTailAuditSection(t, string(asm), "tailaudit.F")
			var code []byte
			for _, match := range regexp.MustCompile(`(?m)^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`).FindAllStringSubmatch(section, -1) {
				bytes, err := hex.DecodeString(strings.ReplaceAll(match[1], " ", ""))
				if err != nil {
					t.Fatal(err)
				}
				code = append(code, bytes...)
			}
			// STR X1,[SP,#24] writes the complete native result plus four tail
			// bytes. The +8 is ARM64's physical saved-link entry offset.
			if len(code) != 16 || binary.LittleEndian.Uint32(code[8:12]) != 0xf9000fe1 {
				t.Fatalf("original native store was narrowed or has another source frame: %x\n%s", code, asm)
			}
			for _, name := range []string{"tailaudit.F", "tailaudit.Caller"} {
				body := arm64ResultTailAuditSection(t, string(compiler), name)
				frame := regexp.MustCompile(`\tTEXT\t` + regexp.QuoteMeta(name) + `\(SB\),[^\n]*\$([0-9]+)-16\n`).FindStringSubmatch(body)
				if frame == nil {
					t.Fatalf("actual %s has no bound caller TEXT frame:\n%s", name, body)
				}
				bytes, err := strconv.ParseInt(frame[1], 10, 64)
				if err != nil || bytes < 32 || bytes > 4096 ||
					!strings.Contains(body, fmt.Sprintf("\tMOVD.W\tR30, -%d(RSP)\n", bytes)) {
					t.Fatalf("actual %s does not allocate its complete physical outgoing store envelope [24,32):\n%s", name, body)
				}
				for _, instruction := range []string{
					"MOVD\tR0, 8(RSP)", "MOVW\tR1, 16(RSP)",
					"CALL\ttailaudit.F(SB)", "MOVWU\t24(RSP), R0",
				} {
					if !strings.Contains(body, "\t"+instruction+"\n") {
						t.Fatalf("actual %s does not supply the observed ABI0 caller mapping %q:\n%s", name, instruction, body)
					}
				}
				t.Logf("actual %s source-bound listing:\n%s", name, body)
			}
			for _, name := range []string{"original.o", "compiler.o", "symabis"} {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || len(data) == 0 {
					t.Fatalf("missing actual %s: %v", name, err)
				}
				t.Logf("actual %s bytes=%d SHA256=%x", name, len(data), sha256.Sum256(data))
			}
			t.Logf("original native code=%x; declared result [16,20), physical native store [16,24); no frame permission", code)
		})
	}
}

func arm64ResultTailAuditTranslate(t *testing.T, api, target, declaration, source string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "tailaudit", "package tailaudit\n"+declaration)
	resolve := testResolveSym(pkg.Path)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
		})
		if translated != nil && !translated.Module.IsNil() {
			ir := translated.Module.String()
			translated.Module.Dispose()
			return ir, err
		}
		return "", err
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		return Translate(file, options)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		ir := module.String()
		module.Dispose()
		return ir, err
	}
	return "", err
}

func TestARM64ABI0ResultTailAllocationIsNotSlotPermission(t *testing.T) {
	for _, test := range []struct {
		name, declaration, source string
	}{
		{"original Or32 result width", "func F(ptr *uint32,val uint32) uint32\n", arm64ResultTailAuditASM},
		{"aligned TEXT", "func F(ptr *uint32,val uint32) uint32\n", strings.Replace(arm64ResultTailAuditASM, "$0-20", "$0-24", 1)},
		{"beyond aligned end", "func F(ptr *uint32,val uint32) uint32\n", strings.Replace(arm64ResultTailAuditASM, "ret+16", "ret+20", 1)},
		{"result interior gap", "func F() (a uint8,b uint64)\n", "TEXT ·F(SB),4,$0-16\nMOVD $1,R0\nMOVD R0,a+0(FP)\nMOVD R0,b+8(FP)\nRET\n"},
		{"argument gap", "func F(a uint8,b uint64) uint64\n", "TEXT ·F(SB),4,$0-24\nMOVD a+0(FP),R0\nMOVD R0,ret+16(FP)\nRET\n"},
		{"escaped tail address", "func F(ptr *uint32,val uint32) uint32\n", "TEXT ·F(SB),4,$0-20\nMOVD $ret+20(FP),R0\nMOVD R0,ret+16(FP)\nRET\n"},
	} {
		for _, target := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
			"aarch64-pc-windows-msvc", "aarch64-unknown-freebsd",
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%s/%s", test.name, target, api), func(t *testing.T) {
					if _, err := arm64ResultTailAuditTranslate(t, api, target, test.declaration, test.source); err == nil {
						t.Fatal("ABI allocation or a type-only declaration fabricated padding/address permission")
					} else if !strings.Contains(err.Error(), "FP") {
						t.Fatalf("unrelated error does not establish the frame boundary: %v", err)
					} else {
						t.Logf("original boundary remains rejected: %v", err)
					}
				})
			}
		}
	}
}

func TestARM64ABI0ResultTailAdjacentDeclaredResultsAreNotPadding(t *testing.T) {
	const declaration = "func F(ptr *uint32,val uint32) (lo uint32,hi uint32)\n"
	const source = "TEXT ·F(SB),4,$0-24\nMOVD $0x123456789abcdef0,R0\nMOVD R0,lo+16(FP)\nRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-pc-windows-msvc", "aarch64-unknown-freebsd",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target+"/"+api, func(t *testing.T) {
				ir, err := arm64ResultTailAuditTranslate(t, api, target, declaration, source)
				if err != nil {
					t.Fatalf("two actual adjacent uint32 results must retain every native byte: %v", err)
				}
				compileLLVMToObject(t, llc, target, "declared-results.ll", "declared-results.o", ir)
			})
		}
	}
}
