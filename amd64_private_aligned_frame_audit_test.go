package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are source/translation observations, not execution tests. In
// particular, neither missing initialization nor a missing SP restoration
// fixture is executed. A typed ABI0 declaration is not a private-frame proof.
func x86PrivateAlignedFrameAuditFixture(t *testing.T, operation string) (string, FuncSig, GoPackage) {
	t.Helper()
	const goSource = `package frameaudit
func Value(a, b, c, d uint64) uint64
`
	return x86PrivateAlignedFrameAuditTypedFixture(t, operation, goSource)
}

func x86PrivateAlignedFrameAuditTypedFixture(t *testing.T, operation, goSource string) (string, FuncSig, GoPackage) {
	t.Helper()
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "frameaudit.go", goSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check("frameaudit", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	declaration, ok := typed.Scope().Lookup("Value").(*types.Func)
	if !ok {
		t.Fatal("missing actual type-checked first-party declaration")
	}
	sig, err := DeriveGoFuncABI0Signature("frameaudit.Value", declaration, "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`TEXT ·Value(SB),4,$160-40
MOVQ a+0(FP),AX
MOVQ b+8(FP),CX
MOVQ c+16(FP),DX
MOVQ d+24(FP),BX
MOVQ SP,R11
MOVQ $31,R9
NOTQ R9
ANDQ R9,SP
ADDQ $32,SP
MOVQ R11,96(SP)
MOVQ AX,16(SP)
MOVQ CX,24(SP)
MOVQ DX,48(SP)
MOVQ BX,56(SP)
MOVOU 48(SP),X0
%s
MOVQ X0,AX
MOVQ 96(SP),R11
MOVQ R11,SP
MOVQ AX,ret+32(FP)
RET
`, operation)
	return source, sig, GoPackage{Path: "frameaudit", Types: typed, Syntax: []*ast.File{syntax}}
}

func x86PrivateAlignedFrameAuditAPIs(t *testing.T, source string, sig FuncSig, pkg GoPackage, check func(*testing.T, error)) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string {
		return strings.Replace(symbol, "·", "frameaudit.", 1)
	}
	sigs := map[string]FuncSig{sig.Name: sig}
	if declaration, ok := pkg.Types.Scope().Lookup("callee").(*types.Func); ok {
		callee, err := DeriveGoFuncABI0Signature("frameaudit.callee", declaration, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sigs[callee.Name] = callee
	}
	opt := Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: resolve, Sigs: sigs,
	}
	t.Run("Translate", func(t *testing.T) {
		_, err := Translate(file, opt)
		check(t, err)
	})
	t.Run("TranslateModuleInContext", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := TranslateModuleInContext(ctx, file, opt)
		if !module.IsNil() {
			defer module.Dispose()
		}
		check(t, err)
	})
	t.Run("TranslateGoModule", func(t *testing.T) {
		translation, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			ResolveSym: resolve,
		})
		if translation != nil && !translation.Module.IsNil() {
			defer translation.Module.Dispose()
		}
		check(t, err)
	})
}

func TestX86PrivateAlignedFrameAuditOriginalGoM128Source(t *testing.T) {
	// Full legacy opcode membership of the bridges inspected in this audit.
	// The count instructions have their own exact-opcode fault contract; this
	// list does not impose an alignment requirement on them.
	operations := []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0",
		"ADDPS 16(SP),X0", "ADDPD 16(SP),X0", "SUBPS 16(SP),X0", "SUBPD 16(SP),X0",
		"MULPS 16(SP),X0", "MULPD 16(SP),X0", "DIVPS 16(SP),X0", "DIVPD 16(SP),X0",
		"CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
		"PSLLW 16(SP),X0", "PSLLL 16(SP),X0", "PSLLQ 16(SP),X0",
		"PSRLW 16(SP),X0", "PSRLL 16(SP),X0", "PSRLQ 16(SP),X0",
	}
	if len(operations) != 21 {
		t.Fatal("incomplete audited legacy bridge membership")
	}
	for _, operation := range operations {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			source, _, _ := x86PrivateAlignedFrameAuditFixture(t, operation)
			listing := string(x86InsertExtractGoListing(t, "amd64", source))
			for _, required := range []string{
				"locals=0xa8",
				"MOVQ\ta+176(FP), AX", "MOVQ\tb+184(FP), CX",
				"MOVQ\tc+192(FP), DX", "MOVQ\td+200(FP), BX", "MOVQ\tAX, ret+208(FP)",
				"ANDQ\tR9, SP", "ADDQ\t$32, SP", "MOVQ\tR11, SP",
				"RET",
			} {
				if !strings.Contains(listing, required) {
					t.Fatalf("actual Go source frame/prologue/restoration missing %q:\n%s", required, listing)
				}
			}
			var code []byte
			for _, line := range strings.Split(listing, "\n") {
				code = append(code, x86InsertExtractListedBytes(line)...)
			}
			if len(code) == 0 {
				t.Fatal("original Go listing lacks physical instruction bytes")
			}
			// Identify complete observed machine sequences, never a version
			// string or autosize alone. Older Go saves BP in the 160(SP)
			// slot; current Go pushes BP. Both reserve 168 bytes, but their
			// producer and restoration instructions are not interchangeable.
			physicalForm := ""
			for _, form := range []struct {
				name           string
				prefix, suffix []byte
				instructions   []string
			}{
				{
					name:   "pushed_BP",
					prefix: []byte{0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0xa0, 0, 0, 0},
					suffix: []byte{0x48, 0x81, 0xc4, 0xa0, 0, 0, 0, 0x5d, 0xc3},
					instructions: []string{
						"PUSHQ\tBP", "MOVQ\tSP, BP", "SUBQ\t$160, SP", "ADDQ\t$160, SP", "POPQ\tBP",
					},
				},
				{
					name:   "slot_saved_BP",
					prefix: []byte{0x48, 0x81, 0xec, 0xa8, 0, 0, 0, 0x48, 0x89, 0xac, 0x24, 0xa0, 0, 0, 0, 0x48, 0x8d, 0xac, 0x24, 0xa0, 0, 0, 0},
					suffix: []byte{0x48, 0x8b, 0xac, 0x24, 0xa0, 0, 0, 0, 0x48, 0x81, 0xc4, 0xa8, 0, 0, 0, 0xc3},
					instructions: []string{
						"SUBQ\t$168, SP", "MOVQ\tBP, 160(SP)", "LEAQ\t160(SP), BP", "MOVQ\t160(SP), BP", "ADDQ\t$168, SP",
					},
				},
			} {
				if !bytes.HasPrefix(code, form.prefix) || !bytes.HasSuffix(code, form.suffix) {
					continue
				}
				for _, instruction := range form.instructions {
					if !strings.Contains(listing, instruction) {
						t.Fatalf("actual %s object lacks its paired listing instruction %q", form.name, instruction)
					}
				}
				physicalForm = form.name
			}
			if physicalForm == "" {
				t.Fatalf("actual Go physical prologue/epilogue lacks an observed complete pairing: %x", code)
			}
			t.Logf("actual Go original accepted; TEXT160 + savedBP8; physicalForm=%s operation=%s sourceSHA=%x codeSHA=%x code=%x", physicalForm, operation, sha256.Sum256([]byte(source)), sha256.Sum256(code), code)
			if strings.HasPrefix(operation, "PADDB ") {
				t.Logf("independent original Go frame/slot listing:\n%s", listing)
			}
		})
	}
}

func TestX86PrivateAlignedFrameAuditBoundedSourceStillNeedsContract(t *testing.T) {
	for _, operation := range []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
	} {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			source, sig, pkg := x86PrivateAlignedFrameAuditFixture(t, operation)
			x86PrivateAlignedFrameAuditAPIs(t, source, sig, pkg, func(t *testing.T, err error) {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("typed scalar declaration alone granted native private-frame memory: %v", err)
				}
				t.Logf("bounded initialized source remains Context pending its private-frame producer: %v", err)
			})
		})
	}
}

// RED checkpoint: the legacy arithmetic bridge currently admits these
// unproved virtual-SP inputs. This is a missing source contract observation,
// not a claim that any third-party function has been executed incorrectly.
func TestX86PrivateAlignedFrameAuditUnprovedNativeFloatingMemory(t *testing.T) {
	mutations := []struct {
		name     string
		edit     func(string) string
		goSource string
	}{
		{"unaligned source residue", func(source string) string {
			return strings.Replace(source, "ADDQ $32,SP", "ADDQ $33,SP", 1)
		}, ""},
		{"uninitialized source bytes", func(source string) string {
			return strings.Replace(source, "MOVQ CX,24(SP)\n", "", 1)
		}, ""},
		{"source TEXT extent", func(source string) string {
			return strings.Replace(source, "16(SP),X0", "152(SP),X0", 1)
		}, ""},
		{"missing source SP restoration", func(source string) string {
			return strings.Replace(source, "MOVQ R11,SP\n", "", 1)
		}, ""},
		{"unknown alignment mask", func(source string) string {
			return strings.Replace(source, "MOVQ $31,R9\nNOTQ R9", "MOVQ AX,R9", 1)
		}, ""},
		{"private pointer result escape", func(source string) string {
			return strings.Replace(source, "MOVQ AX,ret+32(FP)", "MOVQ R11,ret+32(FP)", 1)
		}, ""},
		{"overwritten saved SP", func(source string) string {
			return strings.Replace(source, "MOVQ R11,96(SP)", "MOVQ $0,96(SP)", 1)
		}, ""},
		{"inconsistent restore join", func(source string) string {
			return strings.Replace(source, "MOVQ R11,SP", "CMPQ AX,$0\nJE afterRestore\nMOVQ R11,SP\nafterRestore:", 1)
		}, ""},
		{"private pointer global escape", func(source string) string {
			return strings.Replace(source, "MOVQ R11,96(SP)", "MOVQ R11,96(SP)\nMOVQ SP,framePointer(SB)", 1) + "GLOBL framePointer(SB),8,$8\n"
		}, ""},
		{"unknown incoming pointer alias", func(source string) string {
			return strings.Replace(source, "MOVQ R11,96(SP)", "MOVQ R11,96(SP)\nMOVQ SP,(BX)", 1)
		}, "package frameaudit\nfunc Value(a, b, c uint64, d *uint64) uint64\n"},
		{"unproved call", func(source string) string {
			return strings.Replace(source, "MOVQ R11,96(SP)", "MOVQ R11,96(SP)\nCALL ·callee(SB)", 1)
		}, "package frameaudit\nfunc Value(a, b, c, d uint64) uint64\nfunc callee()\n"},
		{"raw SP overwrite", func(source string) string {
			// MOVQ AX,SP is encoded explicitly, not described by a forged
			// decoder marker or an assumed neutral raw effect.
			return strings.Replace(source, "MOVQ R11,96(SP)", "MOVQ R11,96(SP)\nBYTE $0x48\nBYTE $0x89\nBYTE $0xc4", 1)
		}, ""},
	}
	for _, op := range []string{"ADDPS", "ADDPD", "SUBPS", "SUBPD", "MULPS", "MULPD", "DIVPS", "DIVPD"} {
		for _, mutation := range mutations {
			t.Run(op+"/"+mutation.name, func(t *testing.T) {
				source, sig, pkg := x86PrivateAlignedFrameAuditFixture(t, op+" 16(SP),X0")
				if mutation.goSource != "" {
					source, sig, pkg = x86PrivateAlignedFrameAuditTypedFixture(t, op+" 16(SP),X0", mutation.goSource)
				}
				source = mutation.edit(source)
				// Object acceptance cannot authorize execution of these negative
				// fixtures or stand in for source-SP/result/no-escape semantics.
				x86InsertExtractGoListing(t, "amd64", source)
				x86PrivateAlignedFrameAuditAPIs(t, source, sig, pkg, func(t *testing.T, err error) {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unproved source private-frame backing admitted by native bridge: %v", err)
					}
				})
			})
		}
	}
}
