package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Independent complete original Go registrations, including ordered encoder
// class, prefix and bytes. Go's yscond admits a register spelling even though
// Intel's pair instructions require memory and raise #UD for ModRM.mod=3.
var x86CMPXCHGOriginalRows = []struct {
	op, registration string
	bits             int
	pair             bool
}{
	{"CMPXCHGB", "{ACMPXCHGB, yrb_mb, Pb, opBytes{0x0f, 0xb0}}", 8, false},
	{"CMPXCHGW", "{ACMPXCHGW, yrl_ml, Pe, opBytes{0x0f, 0xb1}}", 16, false},
	{"CMPXCHGL", "{ACMPXCHGL, yrl_ml, Px, opBytes{0x0f, 0xb1}}", 32, false},
	{"CMPXCHGQ", "{ACMPXCHGQ, yrl_ml, Pw, opBytes{0x0f, 0xb1}}", 64, false},
	{"CMPXCHG8B", "{ACMPXCHG8B, yscond, Pm, opBytes{0xc7, 01}}", 64, true},
	{"CMPXCHG16B", "{ACMPXCHG16B, yscond, Pw, opBytes{0x0f, 0xc7, 01}}", 128, true},
}

func TestX86CMPXCHGByteEncoderViewsCannotInventSourceAliases(t *testing.T) {
	for _, row := range []struct {
		arch, body string
		encoded    []byte
	}{
		{"amd64", "CMPXCHGB AH,R11", []byte{0x41, 0x0f, 0xb0, 0xe3}},
		{"amd64", "CMPXCHGB AH,(R12)", []byte{0x41, 0x0f, 0xb0, 0x24, 0x24}},
		{"amd64", "CMPXCHGB R11,AH", []byte{0x44, 0x0f, 0xb0, 0xdc}},
		{"386", "CMPXCHGB BP,(BX)", []byte{0x95, 0x0f, 0xb0, 0x03, 0x95}},
		{"386", "CMPXCHGB SI,DI", []byte{0x96, 0x87, 0xdf, 0x0f, 0xb0, 0xc3, 0x87, 0xdf, 0x96}},
	} {
		t.Run(row.arch+"/"+row.body, func(t *testing.T) {
			source := x86NamedLockOracleSource(row.arch, row.body)
			if row.arch == "amd64" {
				source = strings.Replace(source, "\t"+row.body, "\tMOVQ $9,R11\n\tMOVQ p+0(FP),R12\n\t"+row.body, 1)
			}
			actual := x86OrderingHintGoBytes(t, row.arch, source)
			if !bytes.HasSuffix(actual, append(append([]byte(nil), row.encoded...), 0xc3)) {
				t.Fatalf("original whole encoder effect changed: %x", actual)
			}
			mode := 64
			if row.arch == "386" {
				mode = 32
			}
			physical, err := x86asm.Decode(row.encoded, mode)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("original first physical opcode=%s; full sequence=%x", x86asm.GoSyntax(physical, 0, nil), row.encoded)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86OrderingHintTranslateAPI(t, api, source,
					"package ordering\nfunc locked(p *[32]byte)\n", row.arch, testTargetTriple("linux", row.arch))
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("Go encoder view/implicit accumulator rewrite acquired a false source effect: %s/%v", api, err)
				}
			}
		})
	}
}

func TestX86CMPXCHGCompleteOriginalOrderedRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := string(data)
	for _, row := range x86CMPXCHGOriginalRows {
		if !strings.Contains(table, row.registration) {
			t.Fatal("original opcode-specific encoding changed", row.registration)
		}
	}
	for _, grammar := range []string{
		"var yrb_mb = []ytab{\n\t{Zr_m, 1, argList{Yrb, Ymb}},\n}",
		"var yrl_ml = []ytab{\n\t{Zr_m, 1, argList{Yrl, Yml}},\n}",
		"var yscond = []ytab{\n\t{Zo_m, 2, argList{Ymb}},\n}",
	} {
		if !strings.Contains(table, grammar) {
			t.Fatal("complete ordered operand class changed", grammar)
		}
	}
}

func x86CMPXCHGOriginalBody(row int, destination string) string {
	op := x86CMPXCHGOriginalRows[row]
	if op.pair {
		return op.op + " " + destination
	}
	source := "CX"
	if op.bits == 8 {
		source = "CL"
	}
	return op.op + " " + source + "," + destination
}

func TestX86CMPXCHGNativeMemoryHasNoInventedLLVMAlignment(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for index, row := range x86CMPXCHGOriginalRows {
			if target.arch == "386" && (row.op == "CMPXCHGQ" || row.bits == 128) {
				continue
			}
			for _, destination := range []string{"1(SI)", "0(FS)", "0(GS)"} {
				for _, locked := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/locked=%t", target.triple, row.op, destination, locked), func(t *testing.T) {
						body := x86CMPXCHGOriginalBody(index, destination)
						if locked {
							body = "LOCK\n\t" + body
						}
						source := x86NamedLockOracleSource(target.arch, body)
						actual := x86OrderingHintGoBytes(t, target.arch, source)
						t.Logf("actual original %s bytes=%x (object only, no unsafe execution)", row.op, actual)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86OrderingHintTranslateAPI(t, api, source,
									"package ordering\nfunc locked(p *[32]byte)\n", target.arch, target.triple)
								if err != nil {
									t.Fatal("Go-accepted complete native memory operation", err)
								}
								if regexp.MustCompile(`(?m)^\s*%[^\n]+ = cmpxchg `).MatchString(ir) {
									t.Fatal("native memory operand acquired an unproved LLVM atomic alignment")
								}
								want := strings.ToLower(row.op)
								if locked {
									want = "lock; " + want
								} else if strings.Contains(ir, "lock; cmpxchg") {
									t.Fatal("unprefixed original instruction acquired a LOCK effect")
								}
								if !strings.Contains(ir, "asm sideeffect \""+want) || !strings.Contains(ir, "=*m") || !strings.Contains(ir, "*m") {
									t.Fatal("full native read/write opcode was not retained", want)
								}
								if destination == "0(FS)" && !strings.Contains(ir, "%fs:") || destination == "0(GS)" && !strings.Contains(ir, "%gs:") {
									t.Fatal("actual original segment override disappeared")
								}
								compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "cmpxchg-native.ll", "cmpxchg-native.o", ir)
							})
						}
					})
				}
			}
		}
	}
}

func TestX86CMPXCHGPairRegisterDoesNotInventSoftwareCAS(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86CMPXCHGOriginalRows[4:] {
			if arch == "386" && row.bits == 128 {
				continue
			}
			for _, register := range []string{"AX", "BX", "SI"} {
				t.Run(arch+"/"+row.op+"/"+register, func(t *testing.T) {
					source := x86NamedLockOracleSource(arch, row.op+" "+register)
					actual := x86OrderingHintGoBytes(t, arch, source)
					t.Logf("Go-accepted pair-register #UD object bytes=%x; not a numerical oracle", actual)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86OrderingHintTranslateAPI(t, api, source,
							"package ordering\nfunc locked(p *[32]byte)\n", arch, testTargetTriple("linux", arch))
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("pair-register #UD became a normal software CAS in %s: %v", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86CMPXCHGDispatchIdentityFailsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		file, err := Parse(ArchAMD64, "TEXT locked(SB),4,$0-0\nCMPXCHGL CX,BX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []Op{"CMPXCHGQ", "MOVL", "CMPXCHGL.BAD"} {
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ctx.goarch = arch
			ins := file.Funcs[0].Instrs[1]
			ins.Op = identity
			before, temporary := out.String(), ctx.tmp
			known, terminated, err := ctx.lowerCompareExchange("CMPXCHGL", ins)
			if !known || terminated || err == nil || before != out.String() || temporary != ctx.tmp {
				t.Fatalf("contradictory dispatched/source opcode changed IR: %s %v", identity, err)
			}
		}
	}
}
