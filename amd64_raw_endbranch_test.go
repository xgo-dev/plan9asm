package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Intel SDM lists the operand-free F3 0F 1E FA/FB ENDBR64/ENDBR32
// encodings. Go 1.27 names only ENDBR64; either encoding is valid BYTE data.
func TestX86RawEndBranchFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		for _, form := range []struct {
			op   Op
			last byte
		}{
			{"ENDBR64", 0xfa},
			{"ENDBR32", 0xfb},
		} {
			t.Run(string(form.op)+"/"+target.triple, func(t *testing.T) {
				source := fmt.Sprintf(`TEXT endbranch(SB),$0-0
	MOVL $17, AX
	CMPL AX, AX
	BYTE $0xf3; BYTE $0x0f; BYTE $0x1e; BYTE $0x%02x
	SETEQ BL
	ADDL $3, AX
	RET
`, form.last)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := decodeX86RawDirectives(file.Funcs[0], target.arch)
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded.Instrs) != 7 || decoded.Instrs[3].Op != form.op {
					t.Fatalf("wrong instruction boundaries: %+v", decoded.Instrs)
				}
				ir, err := Translate(file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"endbranch": {Name: "endbranch", Ret: I32}},
				})
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("frame-less manual result acquired an ABI return slot", err)
				}
				want := fmt.Sprintf(".byte 0xf3, 0x0f, 0x1e, 0x%02x", form.last)
				for _, result := range []bool{false, true} {
					program, declaration := source, "func endbranch()"
					if result {
						program = strings.Replace(program, "$0-0", "$0-4", 1)
						program = strings.Replace(program, "\tRET", "\tMOVL AX,ret+0(FP)\n\tRET", 1)
						declaration = "func endbranch() uint32"
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, program)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, program, declaration, target.arch, target.triple, api)
						if err != nil || !strings.Contains(ir, want) {
							t.Fatal("source-bound ENDBR program lost its encoding", api, result, err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					}
				}
			})
		}
	}
}

func TestX86RawEndBranchPreservesBoundaries(t *testing.T) {
	// JE targets the second ENDBR after a first four-byte ENDBR and NOP.
	code := []byte{0x74, 5, 0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0xf3, 0x0f, 0x1e, 0xfb, 0xc3}
	for _, mode := range []int{32, 64} {
		instructions, err := decodeX86RawDirectiveGroup(code, mode, 0, "endbranch fixture", map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		var ops []Op
		for _, instruction := range instructions {
			if instruction.Op == "ENDBR32" || instruction.Op == "ENDBR64" {
				ops = append(ops, instruction.Op)
			}
		}
		if len(ops) != 2 || ops[0] != "ENDBR64" || ops[1] != "ENDBR32" {
			t.Fatalf("mode %d: ENDBR instructions = %v", mode, ops)
		}
		for _, incomplete := range [][]byte{{0xf3}, {0xf3, 0x0f}, {0xf3, 0x0f, 0x1e}} {
			if _, err := decodeX86RawDirectiveGroup(incomplete, mode, 0, "truncated ENDBR", map[string]bool{}); err == nil {
				t.Fatalf("accepted truncated encoding %x", incomplete)
			}
		}
	}
}

func TestX86EndBranch32RemainsRawOnly(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, instruction := range []string{"ENDBR32", "ENDBR32 AX", "ENDBR32.Z"} {
			source := "TEXT invalid(SB),$0-0\n" + instruction + "\nRET\n"
			requireX86GoAssemblerResult(t, arch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				continue
			}
			if _, err := Translate(file, Options{
				Goarch: arch,
				Sigs:   map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}},
			}); err == nil {
				t.Fatalf("accepted Go-undefined text form %q on %s", instruction, arch)
			}
		}
	}
}

const x86EndBranchRuntimeSource = `TEXT endbranchstate(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $17, AX
	CMPL AX, AX
	BYTE $0xf3; BYTE $0x0f; BYTE $0x1e; BYTE $0x%02x
	SETEQ 0(DI)
	SETCS 1(DI)
	MOVL AX, 4(DI)
	RET
`

func TestX86RawEndBranchRuntimePreservesState(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution requires amd64; required amd64 CI covers this host-inapplicable test")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	// This checks GP/flags preservation, not operating-system CET enforcement.
	// Both instructions remain executable bytes, even on pre-CET CPUs.
	for _, last := range []byte{0xfa, 0xfb} {
		t.Run(fmt.Sprintf("%02x", last), func(t *testing.T) {
			source := fmt.Sprintf(x86EndBranchRuntimeSource, last)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"endbranchstate": {
						Name: "endbranchstate", Args: []LLVMType{Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			const mainC = `
#include <stdint.h>
struct result { uint8_t zf, cf, padding[2]; uint32_t value; };
extern void endbranchstate(struct result *);
int main(void) {
  struct result out = {0};
  endbranchstate(&out);
  return out.zf != 1 || out.cf != 0 || out.value != 17;
}
`
			compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_endbranch_state", triple, ir, mainC, runPrefix)
		})
	}
}
