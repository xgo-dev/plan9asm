package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86NamedPCBranchSymbolAnnotation(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, branch := range []string{
				"JMP annotation+2(PC)",
				"JCS $1, other·symbol <> +(1<<1) ( PC )",
				"LOOP step+2(PC)",
				"LOOPEQ step+2(PC)",
				"LOOPNE step+2(PC)",
				"JCXZL destination+2(PC)",
				"XBEGIN abort+2(PC)",
				"JCS unbound(PC)",
			} {
				name := fmt.Sprintf("Named%d", index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nXORL CX,CX\n%s\nNOP\nRET\n", name, branch)
				fmt.Fprintf(&declarations, "func %s()\n", name)
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			for i, fn := range file.Funcs {
				ins := fn.Instrs[2]
				want := int64(2)
				if i == len(file.Funcs)-1 {
					want = 0
				}
				target := ins.Args[len(ins.Args)-1]
				if target.Kind != OpMem || target.Mem != (MemRef{Base: PC, Off: want}) {
					t.Errorf("%q got %v, want source-relative %d(PC)", ins.Raw, target, want)
				}
			}
			if !t.Failed() {
				x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
			}
		})
	}
}

func TestX86PCBranchRejectsConstructedMemoryAddress(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, branch := range []string{"JCS $1, 2(PC)", "JMP 2(PC)", "XBEGIN 2(PC)"} {
			t.Run(arch+"/"+branch, func(t *testing.T) {
				source := "TEXT Value(SB),4,$0-0\nCLC\n" + branch + "\nNOP\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := &file.Funcs[0].Instrs[2]
				target := &ins.Args[len(ins.Args)-1]
				target.Mem.Index, target.Mem.Scale = AX, 1
				signature := FuncSig{Name: "Value", Ret: Void}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{signature.Name: signature}}
				if _, err := Translate(file, options); err == nil {
					t.Fatalf("%s accepted a PC target with a physical index", ins.Raw)
				}
			})
		}
	}
}

func x86OfficialBackwardBranchProgram() (string, string) {
	var source, declarations strings.Builder
	for _, row := range []struct{ name, body string }{
		{"BelowPC", "label:\nINCL AX\nMOVL AX,DX\nMOVL AX,DX\nCMPL AX,$3\nJB -4(PC)\n"},
		{"BelowLabel", "label:\nINCL AX\nCMPL AX,$3\nJB label\n"},
		{"JumpPC", "label:\nINCL AX\nCMPL AX,$3\nJAE done\nMOVL AX,DX\nJMP -4(PC)\ndone:\n"},
		{"JumpLabel", "label:\nINCL AX\nCMPL AX,$3\nJAE done\nJMP label\ndone:\n"},
		{"CountLoop", "MOVL $3,CX\nloop:\nINCL AX\nLOOP loop\n"},
	} {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nXORL AX,AX\n%sMOVL AX,ret+0(FP)\nRET\n", row.name, row.body)
		fmt.Fprintf(&declarations, "func %s() uint32\n", row.name)
	}
	return source.String(), declarations.String()
}

func TestX86OfficialBackwardBranchObjects(t *testing.T) {
	source, declarations := x86OfficialBackwardBranchProgram()
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			x86RawNumericalFamilyObjects(t, source, declarations, arch, testTargetTriple("linux", arch))
		})
	}
}

const x86Official386ContextSource = `TEXT ·CarryLabel(SB),4,$0-8
MOVL input+0(FP),AX
label:
ADDL $1,AX
JC label
MOVL AX,ret+4(FP)
RET

TEXT ·CarryPC(SB),4,$0-8
MOVL input+0(FP),AX
ADDL $1,AX
JC -1(PC)
MOVL AX,ret+4(FP)
RET

TEXT ·InsertFrameLane(SB),4,$0-12
PXOR X0,X0
PINSRD $2,foo+4(FP),X0
PEXTRD $2,X0,AX
MOVL AX,ret+8(FP)
RET
`

const x86Official386ContextDeclarations = `func CarryLabel(input uint32) uint32
func CarryPC(input uint32) uint32
func InsertFrameLane(prefix, foo uint32) uint32
`

func TestX86Official386CarryAndFrameObjects(t *testing.T) {
	for _, target := range x86AddressMemoryTargets("386") {
		t.Run(target, func(t *testing.T) {
			x86RawNumericalFamilyObjects(t, x86Official386ContextSource, x86Official386ContextDeclarations,
				"386", target)
		})
	}
}

const x86OfficialSymbolJumpSource = `TEXT ·SymbolOffset(SB),4,$0-4
JMP bar<>+4(SB)

TEXT ·SymbolIndex(SB),4,$0-4
MOVQ $5,R11
JMP bar<>+4(SB)(R11*4)

TEXT bar<>(SB),4,$0-0
MOVL $37,AX
MOVL AX,ret+0(FP)
RET
`

const x86OfficialSymbolJumpDeclarations = "func SymbolOffset() uint32\nfunc SymbolIndex() uint32\n"

func TestGoAMD64OfficialSymbolJumpObjects(t *testing.T) {
	x86RawNumericalFamilyObjects(t, x86OfficialSymbolJumpSource, x86OfficialSymbolJumpDeclarations,
		"amd64", testTargetTriple("linux", "amd64"))
}

func x86OfficialPCBranchSource(t *testing.T, arch string) (assembly, declarations string, names, locations []string) {
	t.Helper()
	var source, signatures strings.Builder
	resultOffset := goWordSize(arch)
	for _, path := range x86OfficialAssemblerSourcePaths(t, arch) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, raw := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(raw, "//")
			fields := strings.Fields(code)
			if len(fields) != 2 || fields[0] != "JCS" || fields[1] != "2(PC)" {
				continue
			}
			name := fmt.Sprintf("Carry%d", len(names))
			// The branch skips an observable write on carry and lands on a
			// zero-byte source directive. Keep the exact original spelling.
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOVL a+0(FP),AX\nADDL $1,AX\n"+
				"MOVL $11,DX\n%s\nMOVL $19,DX\nPCDATA $0,$-1\nMOVL DX,ret+%d(FP)\nRET\n",
				name, resultOffset+4, code, resultOffset)
			fmt.Fprintf(&signatures, "func %s(a uint32) uint32\n", name)
			names = append(names, name)
			locations = append(locations, fmt.Sprintf("%s:%d", filepath.Base(path), line+1))
		}
	}
	return source.String(), signatures.String(), names, locations
}

func TestX86OfficialPCBranchObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, mode := range []struct {
		arch, triple string
		want         int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 44},
		{"386", "i386-unknown-linux-gnu", 5},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			source, declarations, names, locations := x86OfficialPCBranchSource(t, mode.arch)
			if len(names) != mode.want {
				t.Fatalf("found %d original JCS occurrences, want %d", len(names), mode.want)
			}
			x86LEAActualTargetGoObject(t, mode.arch, mode.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, mode.arch, mode.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if got := strings.Count(ir, "  br i1 "); got != len(names) {
						t.Fatalf("translated %d of %d source branches", got, len(names))
					}
					object := compileLLVMToObject(t, llc, mode.triple, "pc-branch.ll", "pc-branch.o", ir)
					requireX86ELFTestFunctions(t, mode.arch, object, names, locations)
				})
			}
		})
	}
}
