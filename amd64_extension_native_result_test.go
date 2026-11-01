package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Independent Go encoder rows, not the lowerer's extension specification.
var x86ExtensionNativeOracle = []struct {
	op, table, prefix, bytes string
	source, destination      int
	signed, amd64Only        bool
}{
	{"MOVBWSX", "ymb_rl", "Pq", "0xbe", 1, 2, true, false},
	{"MOVBWZX", "ymb_rl", "Pq", "0xb6", 1, 2, false, false},
	{"MOVBLSX", "ymb_rl", "Pm", "0xbe", 1, 4, true, false},
	{"MOVBLZX", "ymb_rl", "Pm", "0xb6", 1, 4, false, false},
	{"MOVBQSX", "ymb_rl", "Pw", "0x0f, 0xbe", 1, 8, true, true},
	{"MOVBQZX", "ymb_rl", "Pw", "0x0f, 0xb6", 1, 8, false, true},
	{"MOVWLSX", "yml_rl", "Pm", "0xbf", 2, 4, true, false},
	{"MOVWLZX", "yml_rl", "Pm", "0xb7", 2, 4, false, false},
	{"MOVWQSX", "yml_rl", "Pw", "0x0f, 0xbf", 2, 8, true, true},
	{"MOVWQZX", "yml_rl", "Pw", "0x0f, 0xb7", 2, 8, false, true},
	{"MOVLQSX", "yml_rl", "Pw", "0x63", 4, 8, true, true},
	{"MOVLQZX", "yml_rl", "Px", "0x8b", 4, 8, false, false},
	{"MOVSWW", "ymb_rl", "Pe", "0x0f, 0xbf", 2, 2, true, false},
	{"MOVZWW", "ymb_rl", "Pe", "0x0f, 0xb7", 2, 2, false, false},
}

func TestX86ExtensionCompleteEncoderAttributes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range x86ExtensionNativeOracle {
		want := fmt.Sprintf("{A%s, %s, %s, opBytes{%s}}", row.op, row.table, row.prefix, row.bytes)
		if !strings.Contains(string(data), want) {
			t.Fatal("original Go encoder attributes changed:", want)
		}
	}
}

func x86ExtensionNativeFixture(name, arch, body string, dead bool) (string, string) {
	word, move, lane, typ, seed := 8, "MOVQ", "Q", "uint64", "0x87654321fedcba98"
	if arch == "386" {
		word, move, lane, typ, seed = 4, "MOVL", "D", "uint32", "0xfedcba98"
	}
	tail := fmt.Sprintf("PINSR%s $0,CX,X1\nPEXTR%s $0,X1,AX\n%s AX,ret+%d(FP)\n", lane, lane, move, word)
	decl := fmt.Sprintf("func %s(p *[4]byte) %s\n", name, typ)
	args := word * 2
	if dead {
		tail = ""
		decl = fmt.Sprintf("func %s(p *[4]byte)\n", name)
		args = word
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DX\nMOVL $1,BX\n%s $%s,CX\n%s\n%sRET\n",
		name, args, move, move, seed, body, tail)
	return source, decl
}

func TestX86ExtensionNativeResultsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86ExtensionNativeOracle {
				if target.arch == "386" && row.amd64Only {
					continue // Independently Go-rejected mode; covered by the existing rejection oracle.
				}
				for _, address := range []string{"(DX)", "-1(DX)(BX*1)"} {
					asm, decl := x86ExtensionNativeFixture(fmt.Sprintf("F%d", count), target.arch, row.op+" "+address+",CX", false)
					source.WriteString(asm)
					declarations.WriteString(decl)
					count++
				}
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("native extension must supply only its continued numerical result:", err)
					}
					if strings.Count(ir, "load volatile i") != count {
						t.Fatal("conditional results lack paired exact native reads")
					}
					compileLLVMToObject(t, llc, target.triple, "extension-native.ll", "extension-native.o", ir)
				})
			}
		})
	}
}

func TestX86ExtensionDeadNativeReadSurvivesOptimization(t *testing.T) {
	for _, row := range x86ExtensionNativeOracle {
		t.Run(row.op, func(t *testing.T) {
			source, declaration := x86ExtensionNativeFixture("F", "amd64", row.op+" (DX),CX", true)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", "Go")
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("load volatile i%d,", row.source*8)
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				if strings.Count(text, want) != 1 {
					t.Fatalf("dead native %s lost its exact %d-byte read", row.op, row.source)
				}
			}
		})
	}
}

func TestX86ExtensionNativeResultsDoNotGrantStandaloneMemory(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86ExtensionNativeOracle {
			if arch == "386" && row.amd64Only {
				continue
			}
			body := fmt.Sprintf("%s p+0(FP),DX\nMOVL $0,CX\n%s (DX),CX\nMOVL CX,ret0+%d(FP)\nRET", move, row.op, word)
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *[4]byte) uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s/%s acquired standalone memory: %v", arch, row.op, err)
				}
			}
		}
	}
}

func TestX86ExtensionNativeResultBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for name, body := range map[string]string{
			"unknown base":                        "MOVBLZX (DI),CX",
			"numeric base":                        "MOVL $42,DX\nMOVBLZX (DX),CX",
			"unknown index":                       "MOVBLZX (DX)(DI*1),CX",
			"pointer index":                       "MOVBLZX (DX)(DX*1),CX",
			"unbound data":                        "MOVBLZX ·external(SB),CX",
			"word high bytes":                     move + " DX,CX\nMOVBWSX (DX),CX",
			"pointer clobbered by partial result": "MOVBWSX (DX),DX\nMOVBLZX (DX),CX",
			"mixed pointer join": "CMPL BX,$0\nJE other\n" + move + " DX,DI\nJMP end\n" +
				"other:\nMOVL $42,DI\nend:\nMOVBLZX (DI),CX",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				source, decl := x86ExtensionNativeFixture("F", arch, body, false)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, decl, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s manufactured numerical or pointer bytes: %v", api, err)
					}
				}
			})
		}
	}
}

func TestX86ExtensionNativeResultEffectsAndOriginBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ExtensionNativeOracle {
			if arch == "386" && row.amd64Only {
				continue
			}
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row.op+" -1(DX)(BX*1),CX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			base, _, _ := x86ResultGP(DX, 4, arch)
			index, _, _ := x86ResultGP(BX, 4, arch)
			destination, _, _ := x86ResultGP(CX, 4, arch)
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.pointerGP[base] = true
			state.gp[index] = 0xff
			before := state.clone()
			accepted, known := x86LoweredScalarExtensionRead(ins, &state, nil, 0, arch)
			want := uint8(0xff)
			if row.destination == 2 {
				want = 3 // W leaves every other byte unknown.
			}
			if !accepted || !known || state.gp[destination] != want || state.flags != before.flags ||
				!state.pointerGP[base] || state.gp[base] != 0 || state.pointerGP[destination] {
				t.Fatalf("%s/%s widened its effect: %+v", arch, row.op, state)
			}
			for _, mutation := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment"} {
				changed, rejected := ins, before.clone()
				switch mutation {
				case "decoded":
					changed.x86Encoded = true
				case "raw":
					changed.x86SourceRaw = new(x86SourceRawInstruction)
				case "raw return":
					changed.x86RawNearReturn = new(x86RawNearReturnForm)
				case "address":
					changed.x86AddressBits = 32
				case "unbound address":
					changed.x86UnboundAddressOverride = true
				case "segment":
					changed.x86SegmentPrefix = 0x64
				}
				if accepted, _ := x86LoweredScalarExtensionRead(changed, &rejected, nil, 0, arch); accepted || rejected.gp != before.gp || rejected.pointerGP != before.pointerGP {
					t.Fatalf("%s/%s granted an unbound %s effect", arch, row.op, mutation)
				}
			}
		}
	}
}
