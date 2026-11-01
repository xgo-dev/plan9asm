package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestX86BroadcastPairedNativeMemoryFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	execution := x86FloatCompareExecution{llc: llc, triple: triple,
		compiler: []string{clang, "-target", triple}}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		command := runtimeOracleNativeCCommand(t, ctx, clang, "-target", triple)
		cancel()
		execution.compiler = command.Args
	}
	arch, move, maskMove, originalTriple := "amd64", "MOVQ", "KMOVQ", "x86_64-unknown-linux-gnu"
	if strconv.IntSize == 32 {
		arch, move, maskMove, originalTriple = "386", "MOVL", "KMOVD", "i386-unknown-linux-gnu"
	}
	type kernel struct {
		source, declaration string
		bytes               int
	}
	var kernels []kernel
	for _, spec := range x86BroadcastTestDirectory {
		if spec.source == "K" {
			continue
		}
		add := func(masked bool, mask int64) {
			row := fmt.Sprintf("%s table<>+0(SB),%c2", spec.name, spec.destinations[0])
			if masked {
				row = fmt.Sprintf("%s.Z table<>+0(SB),K3,%c2", spec.name, spec.destinations[0])
			}
			source, declaration := x86BroadcastNativeFixture(arch, row, true)
			source = strings.Replace(source, "3(AX)(DX*2)", "(AX)", 1)
			source = strings.Replace(source, "MOVL $5,CX\nKMOVD CX,K3", fmt.Sprintf("%s $%d,CX\n%s CX,K3", move, mask, maskMove), 1)
			readBytes := spec.bytes
			if masked {
				readBytes = 0
				width := map[byte]int{'X': 16, 'Y': 32, 'Z': 64}[spec.destinations[0]]
				for lane := 0; lane < width/spec.lane; lane++ {
					end := (lane%(spec.bytes/spec.lane) + 1) * spec.lane
					if uint64(mask)&(uint64(1)<<uint(lane)) != 0 && end > readBytes {
						readBytes = end
					}
				}
			}
			kernels = append(kernels, kernel{source, declaration, readBytes})
		}
		add(false, 0)
		if spec.table != "_yvbroadcastf128" {
			width := map[byte]int{'X': 16, 'Y': 32, 'Z': 64}[spec.destinations[0]]
			for _, mask := range []int64{0, 1, 2, -1, 1 << uint(spec.bytes/spec.lane), 1 << uint(width/spec.lane)} {
				add(true, mask)
			}
		}
	}
	if len(kernels) != 114 {
		t.Fatal("incomplete scalar/block fault directory", len(kernels))
	}
	for start := 0; start < len(kernels); start += 64 {
		end := start + 64
		if end > len(kernels) {
			end = len(kernels)
		}
		t.Run(fmt.Sprint("batch-", start/64), func(t *testing.T) {
			var assembly, declarations, callbacks, rows strings.Builder
			var required []bool
			for index, entry := range kernels[start:end] {
				name := fmt.Sprint("Broadcast", index)
				assembly.WriteString(strings.ReplaceAll(entry.source, "Value", name))
				declarations.WriteString(strings.ReplaceAll(entry.declaration, "Value", name) + "\n")
				fmt.Fprintf(&callbacks, "extern uint32_t %s(const uint8_t*);\n", name)
				fmt.Fprintf(&callbacks, "static int run%d(const uint8_t *p) { return %s(p)==7 ? 0 : 91; }\n", index, name)
				accessible := entry.bytes - 1
				if accessible < 0 {
					accessible = 0
				}
				fmt.Fprintf(&rows, "{run%d,%d,%d},\n", index, entry.bytes, accessible)
				required = append(required, entry.bytes != 0)
			}
			x86LEAActualTargetGoObject(t, arch, originalTriple, assembly.String())
			ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, execution.triple, "Go")
			if err != nil {
				t.Fatal(err)
			}
			driver := x86MemoryFaultDriver(callbacks.String(), rows.String())
			for _, passes := range []string{"default", "O2"} {
				text := ir
				if passes == "O2" {
					text = x86DwordProductIROptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(passes+level, func(t *testing.T) {
						executable := execution.compileLLVM(t, "broadcast-fault", text, driver, level)
						x86CheckMemoryAccessMatrix(t, execution, executable, required)
					})
				}
			}
		})
	}
	t.Log("114 scalar/block kernels; actual-host portable LLVM memory faults, not original AVX512 execution")
}
