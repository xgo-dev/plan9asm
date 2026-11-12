package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

type arm64PrivateStructureCase struct {
	name, instruction string
	kind, count       int // 0 load, 1 store, 2 replicate, 3/4 lane, 5 external store
	bits, lanes, lane int
	post              int
	contiguous        bool // LD1/ST1 concatenate; LD2-4/ST2-4 interleave.
}

// Whole-register cases share the independent Go encoder enumeration. Lane
// cases use its separate independent architectural encoder, not a decoder's
// own output. Only R0/R1/R2/R7/R9/R10 and SIMD registers are touched; these
// first-party fixtures never write R18, g/R28, or an incoming physical frame.
func arm64PrivateStructureCases() []arm64PrivateStructureCase {
	var cases []arm64PrivateStructureCase
	for _, tc := range arm64RawStructureCases() {
		if tc.base != 3 { // One address/register tuple; widths/counts/modes are independent axes.
			continue
		}
		kind := 0
		if !tc.load {
			kind = 1
		} else if tc.replicate {
			kind = 2
		}
		base := "R9"
		if tc.post == 2 {
			base = "R2" // Unknown register writeback is not a private-frame proof.
			if !tc.load {
				base, kind = "R1", 5
			}
		}
		cases = append(cases, arm64PrivateStructureCase{
			instruction: strings.ReplaceAll(tc.syntax, "(R3)", "("+base+")"),
			kind:        kind, count: tc.count, bits: tc.bits, lanes: tc.lanes, lane: -1, post: tc.post,
			contiguous: tc.op == "VLD1" || tc.op == "VST1",
		})
	}
	for _, load := range []bool{false, true} {
		for count := 1; count <= 4; count++ {
			for _, bits := range []int{8, 16, 32, 64} {
				for _, lane := range []int{0, 128/bits - 1} {
					for post := 0; post < 3; post++ {
						base, kind := 9, 4
						if load {
							kind = 3
						}
						mode := arm64RawStructureLanePost(post)
						if post == 2 {
							base = 2
							if !load {
								base, kind = 1, 6
							}
						}
						word := encodeARM64RawStructureLane(load, count, bits, lane, mode, 7, base, 25)
						cases = append(cases, arm64PrivateStructureCase{
							instruction: fmt.Sprintf("WORD $%#08x", word),
							kind:        kind, count: count, bits: bits, lanes: 128 / bits, lane: lane, post: post,
						})
					}
				}
			}
		}
	}
	for index := range cases {
		cases[index].name = fmt.Sprintf("structure_%03d", index)
	}
	return cases
}

func arm64PrivateStructureFixture(t *testing.T) (string, GoPackage, []arm64PrivateStructureCase) {
	t.Helper()
	cases := arm64PrivateStructureCases()
	var source, declarations strings.Builder
	for _, tc := range cases {
		fmt.Fprintf(&declarations, "func %s(*byte,*byte)\n", tc.name)
		fmt.Fprintf(&source, `TEXT ·%s(SB),4,$120-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xd2800024
VLD1 (R0),[V25.B16,V26.B16,V27.B16,V28.B16]
ADD $64,R0,R2
VLD1 (R2),[V16.B16,V17.B16,V18.B16,V19.B16]
ADD $16,RSP,R9
VST1 [V16.B16,V17.B16,V18.B16,V19.B16],(R9)
`, tc.name)
		if tc.post == 2 {
			increment := tc.count * tc.bits / 8
			if tc.lane < 0 && tc.kind != 2 {
				increment *= tc.lanes
			}
			fmt.Fprintf(&source, "MOVD $%d,R7\n", increment)
		}
		source.WriteString(tc.instruction + "\nMOVD $0,R9\n")
		if tc.kind == 1 || tc.kind == 4 {
			source.WriteString(`ADD $16,RSP,R10
VLD1 (R10),[V20.B16,V21.B16,V22.B16,V23.B16]
VST1 [V20.B16,V21.B16,V22.B16,V23.B16],(R1)
MOVD $0,R10
`)
		} else if tc.kind != 5 && tc.kind != 6 {
			fmt.Fprintf(&source, "VST1 %s,(R1)\n", arm64TestVectorList(25, tc.count, "B16"))
		}
		source.WriteString("MOVD 0(RSP),R30\nRET\n")
	}
	pkg := mustGoPackage(t, "structureoracle", "package main\n"+declarations.String())
	return source.String(), pkg, cases
}

func TestARM64PrivateStructureNumericalFamilyObjects(t *testing.T) {
	source, pkg, cases := arm64PrivateStructureFixture(t)
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ctx := llvm.NewContext()
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: testResolveSym("structureoracle"),
		})
		if err != nil {
			ctx.Dispose()
			t.Fatal(err)
		}
		ir := result.Module.String()
		result.Module.Dispose()
		ctx.Dispose()
		compileLLVMToObject(t, llc, target, "structure-family.ll", "structure-family.o", ir)
	}
	t.Logf("%d initialized numerical fixtures; all structure mnemonics, arrangements, counts, post-index modes and first/last raw lanes", len(cases))
}

func TestCrossLinuxRuntimeMatrixARM64PrivateStructureFamily(t *testing.T) {
	source, pkg, cases := arm64PrivateStructureFixture(t)
	arm64RunPrivateStructureFixture(t, source, pkg, cases)
}

func arm64RunPrivateStructureFixture(t *testing.T, source string, pkg GoPackage, cases []arm64PrivateStructureCase) {
	t.Helper()
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var declarations, checks, cDeclarations, cChecks strings.Builder
	for _, tc := range cases {
		fmt.Fprintf(&declarations, "func %s(*byte,*byte)\n", tc.name)
		fmt.Fprintf(&checks, "check(%s,%d,%d,%d,%d,%d,%t)\n", tc.name, tc.kind, tc.count, tc.bits/8, tc.lanes, tc.lane, tc.contiguous)
		fmt.Fprintf(&cDeclarations, "extern void %s(const unsigned char *,unsigned char *);\n", tc.name)
		contiguous := 0
		if tc.contiguous {
			contiguous = 1
		}
		fmt.Fprintf(&cChecks, "if(check(%s,%d,%d,%d,%d,%d,%d)) return 1;\n", tc.name, tc.kind, tc.count, tc.bits/8, tc.lanes, tc.lane, contiguous)
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":         "module structureoracle\n\ngo 1.20\n",
		"main.go":        arm64PrivateStructureGoOracle + declarations.String() + "func main(){\n" + checks.String() + "}\n",
		"oracle_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=2", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go initialized structure oracle: %v\n%s", err, output)
	}
	llvmCtx := llvm.NewContext()
	result, err := translateGoModuleInContext(llvmCtx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string {
			return strings.TrimPrefix(symbol, "·")
		},
	})
	if err != nil {
		llvmCtx.Dispose()
		t.Fatal(err)
	}
	ir := result.Module.String()
	result.Module.Dispose()
	llvmCtx.Dispose()
	cSource := arm64PrivateStructureCOracle + cDeclarations.String() + "int main(void){\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "private_structure", triple, ir, cSource, runner)
	t.Logf("actual Go + LLVM22/independent C: %d fixtures x 32 patterns x 3 unaligned offsets; complete inputs/outputs/canaries, non-roundtrip lane/interleave/replicate reference", len(cases))
}

const arm64PrivateStructureGoOracle = `package main

func check(fn func(*byte, *byte), kind, count, width, lanes, lane int, contiguous bool) {
	var input [192]byte
	var output, want [128]byte
	for trial := 0; trial < 32; trial++ {
		for _, off := range []int{0, 1, 7} {
			for i := range input {
				input[i] = byte(i*71 + trial*53 + 19)
			}
			for i := range output {
				output[i], want[i] = 0xa5, 0xa5
			}
			snapshot := input
			p := want[off:]
			if kind == 1 || kind == 4 {
				copy(p[:64], input[off+64:off+128])
			}
			if kind == 0 || kind == 2 {
				for i := 0; i < count*16; i++ {
					p[i] = 0
				}
			}
			if kind == 3 {
				copy(p[:count*16], input[off:off+count*16])
			}
			for reg := 0; reg < count; reg++ {
				if kind == 3 || kind == 4 || kind == 6 {
					src, dst := 64+reg*width, reg*16+lane*width
					if kind != 3 {
						src, dst = reg*16+lane*width, reg*width
					}
					copy(p[dst:dst+width], input[off+src:off+src+width])
					continue
				}
				for element := 0; element < lanes; element++ {
					interleaved := (element*count + reg) * width
					if contiguous {
						interleaved = (reg*lanes + element) * width
					}
					src, dst := 64+interleaved, reg*16+element*width
					if kind == 2 {
						src = 64 + reg*width
					}
					if kind == 1 || kind == 5 {
						src, dst = reg*16+element*width, interleaved
					}
					copy(p[dst:dst+width], input[off+src:off+src+width])
				}
			}
			fn(&input[off], &output[off])
			if input != snapshot || output != want {
				println(kind, count, width, lanes, lane, trial, off)
				panic("initialized structure layout/canary mismatch")
			}
		}
	}
}
`

const arm64PrivateStructureCOracle = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int check(void (*fn)(const unsigned char *, unsigned char *),
                 unsigned kind, unsigned count, unsigned width,
                 unsigned lanes, int lane, unsigned contiguous) {
  unsigned char input[192], snapshot[192], output[128], want[128];
  const unsigned offsets[] = {0,1,7};
  for (unsigned trial=0;trial<32;trial++) {
    for (unsigned o=0;o<3;o++) {
      unsigned off=offsets[o];
      for (unsigned i=0;i<192;i++) input[i]=(unsigned char)(i*71+trial*53+19);
      memcpy(snapshot,input,192);
      memset(output,0xa5,128);
      memset(want,0xa5,128);
      unsigned char *p=want+off;
      if (kind==1 || kind==4) memcpy(p,input+off+64,64);
      if (kind==0 || kind==2) memset(p,0,count*16);
      if (kind==3) memcpy(p,input+off,count*16);
      for (unsigned reg=0;reg<count;reg++) {
        if (kind==3 || kind==4 || kind==6) {
          unsigned src=64+reg*width,dst=reg*16+lane*width;
          if (kind!=3) {
            src=reg*16+lane*width;
            dst=reg*width;
          }
          memcpy(p+dst,input+off+src,width);
          continue;
        }
        for (unsigned element=0;element<lanes;element++) {
          unsigned interleaved=(element*count+reg)*width;
          if (contiguous) interleaved=(reg*lanes+element)*width;
          unsigned src=64+interleaved,dst=reg*16+element*width;
          if (kind==2) src=64+reg*width;
          if (kind==1 || kind==5) {
            src=reg*16+element*width;
            dst=interleaved;
          }
          memcpy(p+dst,input+off+src,width);
        }
      }
      fn(input+off,output+off);
      if (memcmp(input,snapshot,192) || memcmp(output,want,128)) {
        fprintf(stderr,"structure kind/count/width/lanes/lane/trial/off %u/%u/%u/%u/%d/%u/%u\n",
                kind,count,width,lanes,lane,trial,off);
        return 1;
      }
    }
  }
  return 0;
}
`
