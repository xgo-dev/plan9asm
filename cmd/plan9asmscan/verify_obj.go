package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/diffreport"
)

type objProbeItem struct {
	form string
	ins  plan9asm.Instr
}

func llcTripleForGoarch(goarch string) string {
	switch goarch {
	case "386":
		return "i386-unknown-linux-gnu"
	case "amd64":
		return "x86_64-unknown-linux-gnu"
	case "arm":
		return "armv7-unknown-linux-gnueabihf"
	case "arm64":
		return "aarch64-unknown-linux-gnu"
	case "wasm":
		return "wasm32-unknown-unknown"
	default:
		return ""
	}
}

func llcArgsForGoarch(goarch, outPath string) []string {
	triple := llcTripleForGoarch(goarch)
	args := []string{"-mtriple=" + triple, "-filetype=obj", "-o", outPath, "-"}
	if goarch == "amd64" || goarch == "386" {
		args = append(args, "-mattr=+aes,+ssse3,+sse4.1,+sse4.2,+pclmul,+avx,+avx2,+avx512f,+avx512bw,+avx512cd,+avx512dq,+avx512vl,+avx512vbmi,+avx512vbmi2,+avx512vnni,+avx512bitalg,+avx512vpopcntdq,+gfni,+vaes,+vpclmulqdq,+sha,+popcnt,+adx,+bmi,+bmi2,+f16c,+fma,+fsgsbase,+rdpid,+rdrnd,+rdseed,+movbe,+clflushopt,+clwb,+cldemote")
	}
	return args
}

// findLLCTool locates an LLVM 22 llc binary and validates its reported version.
// Unversioned or non-22 llc binaries are explicitly rejected so -verify-obj
// always matches the LLVM 22 toolchain contract.
func findLLCTool() (string, string, error) {
	var candidates []string
	if llvmConfig := strings.TrimSpace(os.Getenv("LLVM_CONFIG")); llvmConfig != "" {
		verOut, err := exec.Command(llvmConfig, "--version").Output()
		if err != nil {
			return "", "", fmt.Errorf("LLVM_CONFIG=%q --version failed: %w", llvmConfig, err)
		}
		verStr := strings.TrimSpace(string(verOut))
		if !strings.HasPrefix(verStr, "22.") && verStr != "22" {
			return "", "", fmt.Errorf("LLVM_CONFIG=%q reports LLVM %s, require LLVM 22 for -verify-obj", llvmConfig, verStr)
		}
		binOut, err := exec.Command(llvmConfig, "--bindir").Output()
		if err != nil {
			return "", "", fmt.Errorf("LLVM_CONFIG=%q --bindir failed: %w", llvmConfig, err)
		}
		candidates = append(candidates, filepath.Join(strings.TrimSpace(string(binOut)), "llc"))
	} else {
		candidates = append(candidates, "llc-22", "llc")
	}
	var rejected []string
	for _, candidate := range candidates {
		p, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		out, err := exec.Command(p, "--version").CombinedOutput()
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%s (--version failed: %v)", p, err))
			continue
		}
		if version := diffreport.LLVM22(string(out)); version != "" {
			return p, version, nil
		}
		firstLine := strings.TrimSpace(strings.Split(string(out), "\n")[0])
		rejected = append(rejected, fmt.Sprintf("%s (%s)", p, firstLine))
	}
	if len(rejected) > 0 {
		return "", "", fmt.Errorf("LLVM 22 llc not found (required by -verify-obj); rejected non-22 binaries: %s", strings.Join(rejected, "; "))
	}
	return "", "", fmt.Errorf("LLVM 22 llc not found in PATH (required by -verify-obj)")
}

var translateMu sync.Mutex

func buildBatchIR(arch plan9asm.Arch, goarch string, items []objProbeItem) (string, error) {
	triple := llcTripleForGoarch(goarch)
	wasmABI := plan9asm.WASMABIDirect
	if arch == plan9asm.ArchWASM {
		wasmABI = plan9asm.WASMABIGo
	}
	funcs := make([]plan9asm.Func, 0, len(items))
	sigs := make(map[string]plan9asm.FuncSig, len(items))
	globlSeen := map[string]bool{}
	var globls []plan9asm.GloblStmt
	addGlobl := func(raw string) {
		s := strings.TrimSpace(raw)
		if !strings.HasSuffix(s, "(SB)") {
			return
		}
		s = strings.TrimSuffix(s, "(SB)")
		if plus := strings.IndexByte(s, '+'); plus >= 0 {
			s = s[:plus]
		}
		if s == "" || globlSeen[s] {
			return
		}
		globlSeen[s] = true
		globls = append(globls, plan9asm.GloblStmt{Sym: s, Size: 64})
	}
	for i, it := range items {
		fnName := fmt.Sprintf("plan9asm_obj_%d", i)
		fn := plan9asm.Func{Sym: fnName, Instrs: []plan9asm.Instr{it.ins}}
		labels := map[string]struct{}{}
		for _, arg := range it.ins.Args {
			if arg.Kind == plan9asm.OpLabel {
				labels[arg.Sym] = struct{}{}
			}
			opUpper := strings.ToUpper(string(it.ins.Op))
			if arg.Kind == plan9asm.OpSym && (opUpper == "CALL" || opUpper == "JMP" || opUpper == "RET" || opUpper == "CALLNORESUME") {
				name := strings.TrimSuffix(arg.Sym, "(SB)")
				if plus := strings.IndexByte(name, '+'); plus >= 0 {
					name = name[:plus]
				}
				if name != "" && !strings.HasPrefix(name, "*") {
					sigs[name] = plan9asm.FuncSig{Name: name, Ret: plan9asm.Void}
				}
			} else if arg.Kind == plan9asm.OpSym {
				addGlobl(arg.Sym)
			} else if arg.Kind == plan9asm.OpMem && arg.Mem.Sym != "" {
				addGlobl(arg.Mem.Sym)
			}
		}
		for label := range labels {
			fn.Instrs = append(fn.Instrs, plan9asm.Instr{
				Op:   plan9asm.OpLABEL,
				Args: []plan9asm.Operand{{Kind: plan9asm.OpLabel, Sym: label}},
				Raw:  label + ":",
			})
		}
		if arch == plan9asm.ArchWASM {
			// Match probeWASMInstructionWith stack-depth seeding by translating
			// wasm forms individually rather than batching raw stack ops.
			return "", fmt.Errorf("wasm uses per-form probe IR")
		}
		fn.Instrs = append(fn.Instrs, plan9asm.Instr{Op: plan9asm.OpRET, Raw: "RET"})
		funcs = append(funcs, fn)
		sigs[fnName] = plan9asm.FuncSig{Name: fnName, Ret: plan9asm.Void}
	}
	translateMu.Lock()
	ir, err := plan9asm.Translate(&plan9asm.File{Arch: arch, Funcs: funcs, Globl: globls}, plan9asm.Options{
		Goarch:       goarch,
		TargetTriple: triple,
		Sigs:         sigs,
		WASMABI:      wasmABI,
	})
	translateMu.Unlock()
	return ir, err
}

// runLLCOnIR compiles LLVM IR to a real target object file (-filetype=obj) in
// tmpDir and verifies a non-empty object file was actually written.
func runLLCOnIR(llcPath, goarch, tmpDir, ir string) error {
	f, err := os.CreateTemp(tmpDir, "plan9asm-*.o")
	if err != nil {
		return fmt.Errorf("create temp object file: %w", err)
	}
	objPath := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(objPath)
		return fmt.Errorf("close temp object file: %w", err)
	}
	defer os.Remove(objPath)

	cmd := exec.Command(llcPath, llcArgsForGoarch(goarch, objPath)...)
	cmd.Stdin = strings.NewReader(ir)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 240 {
			msg = msg[:240]
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	fi, err := os.Stat(objPath)
	if err != nil {
		return fmt.Errorf("object file not emitted: %w", err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("object file emitted empty (0 bytes)")
	}
	return nil
}

func verifyObjChunk(llcPath, goarch, tmpDir string, arch plan9asm.Arch, items []objProbeItem, compiled map[string]bool, failed map[string]string, mu *sync.Mutex) {
	if len(items) == 0 {
		return
	}
	ir, err := buildBatchIR(arch, goarch, items)
	if err == nil {
		if llcErr := runLLCOnIR(llcPath, goarch, tmpDir, ir); llcErr == nil {
			mu.Lock()
			for _, it := range items {
				compiled[it.form] = true
			}
			mu.Unlock()
			return
		} else if len(items) == 1 {
			mu.Lock()
			failed[items[0].form] = llcErr.Error()
			mu.Unlock()
			return
		}
	} else if len(items) == 1 {
		mu.Lock()
		failed[items[0].form] = err.Error()
		mu.Unlock()
		return
	}
	mid := len(items) / 2
	verifyObjChunk(llcPath, goarch, tmpDir, arch, items[:mid], compiled, failed, mu)
	verifyObjChunk(llcPath, goarch, tmpDir, arch, items[mid:], compiled, failed, mu)
}

func verifyObjectCompilation(arch plan9asm.Arch, goarch string, forms map[string]*formStat) (map[string]bool, map[string]string, string, error) {
	llcPath, llvmVer, err := findLLCTool()
	if err != nil {
		return nil, nil, "", err
	}
	tmpDir, err := os.MkdirTemp("", "plan9asm-verify-obj-*")
	if err != nil {
		return nil, nil, "", fmt.Errorf("create temp dir for -verify-obj: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	items := make([]objProbeItem, 0, len(forms))
	for _, st := range forms {
		if st.UnsupportedCount > 0 || (st.ContextCount > 0 && st.SupportedCount == 0) {
			continue
		}
		if !st.HasSample {
			continue
		}
		items = append(items, objProbeItem{form: st.Descriptor.Form, ins: st.SampleInstr})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].form < items[j].form })

	compiled := make(map[string]bool, len(items))
	failed := make(map[string]string)

	// Wasm stack instructions require stack-seed wrappers (handled by ProbeInstruction),
	// so verify wasm individually via minimal seeded wrappers when needed.
	if arch == plan9asm.ArchWASM {
		var mu sync.Mutex
		workers := runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
		if workers > 8 {
			workers = 8
		}
		ch := make(chan objProbeItem, len(items))
		for _, it := range items {
			ch <- it
		}
		close(ch)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for it := range ch {
					ir, ok := translateWASMSampleForObj(it.ins)
					if !ok {
						mu.Lock()
						failed[it.form] = "failed to synthesize wasm probe IR"
						mu.Unlock()
						continue
					}
					if err := runLLCOnIR(llcPath, goarch, tmpDir, ir); err != nil {
						mu.Lock()
						failed[it.form] = err.Error()
						mu.Unlock()
					} else {
						mu.Lock()
						compiled[it.form] = true
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		return compiled, failed, llvmVer, nil
	}

	const batchSize = 128
	var chunks [][]objProbeItem
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}

	var mu sync.Mutex
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	ch := make(chan []objProbeItem, len(chunks))
	for _, chunk := range chunks {
		ch <- chunk
	}
	close(ch)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range ch {
				verifyObjChunk(llcPath, goarch, tmpDir, arch, chunk, compiled, failed, &mu)
			}
		}()
	}
	wg.Wait()
	return compiled, failed, llvmVer, nil
}

func translateWASMSampleForObj(ins plan9asm.Instr) (string, bool) {
	seedOps := [][]plan9asm.Instr{
		nil,
		{{Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 1}}}, {Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 2}}}},
		{{Op: "I64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "I64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 1}}}, {Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 1}}}},
		{{Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "I64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 1}}}},
		{{Op: "F32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "F32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}},
		{{Op: "F64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "F64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}},
		{{Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "F32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}},
		{{Op: "I32Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}, {Op: "F64Const", Args: []plan9asm.Operand{{Kind: plan9asm.OpImm, Imm: 0}}}},
	}
	for _, seeds := range seedOps {
		instrs := append([]plan9asm.Instr(nil), seeds...)
		instrs = append(instrs, ins, plan9asm.Instr{Op: plan9asm.OpRET, Raw: "RET"})
		file := &plan9asm.File{
			Arch:  plan9asm.ArchWASM,
			Funcs: []plan9asm.Func{{Sym: "plan9asm_wasm_obj", Instrs: instrs}},
		}
		translateMu.Lock()
		ir, err := plan9asm.Translate(file, plan9asm.Options{
			Goarch:       "wasm",
			TargetTriple: "wasm32-unknown-unknown",
			Sigs:         map[string]plan9asm.FuncSig{"plan9asm_wasm_obj": {Name: "plan9asm_wasm_obj", Ret: plan9asm.Void}},
			WASMABI:      plan9asm.WASMABIGo,
		})
		translateMu.Unlock()
		if err == nil {
			return ir, true
		}
	}
	return "", false
}
