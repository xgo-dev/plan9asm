package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStdlibInternalBytealg_ARM64_Compile(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc not found")
	}

	goroot := runtime.GOROOT()
	if goroot == "" {
		t.Fatal("GOROOT not available")
	}

	sfiles := stdlibBytealgARM64Sigs(goroot)
	if len(sfiles) == 0 {
		t.Fatal("internal/bytealg arm64 asm files not present in this GOROOT")
	}

	resolve := func(sym string) string {
		sym = goStripABISuffix(sym)
		if strings.HasPrefix(sym, "runtime·") {
			sym = strings.ReplaceAll(sym, "∕", "/")
			return strings.ReplaceAll(sym, "·", ".")
		}
		if strings.HasPrefix(sym, "·") {
			return "internal/bytealg." + strings.TrimPrefix(sym, "·")
		}
		if !strings.Contains(sym, "·") && !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
			return "internal/bytealg." + sym
		}
		sym = strings.ReplaceAll(sym, "∕", "/")
		return strings.ReplaceAll(sym, "·", ".")
	}

	triple := "aarch64-unknown-linux-gnu"
	compiled := 0
	for path, sigs := range sfiles {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := Parse(ArchARM64, string(src))
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			ResolveSym:   resolve,
			Sigs:         sigs,
			Goarch:       "arm64",
		})
		if err != nil {
			t.Fatalf("translate %s: %v", path, err)
		}

		tmp := t.TempDir()
		llPath := filepath.Join(tmp, filepath.Base(path)+".ll")
		objPath := filepath.Join(tmp, filepath.Base(path)+".o")
		if err := os.WriteFile(llPath, []byte(ll), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=obj", llPath, "-o", objPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			s := string(out)
			if strings.Contains(s, "No available targets") ||
				strings.Contains(s, "no targets are registered") ||
				strings.Contains(s, "unknown target triple") ||
				strings.Contains(s, "unknown target") ||
				strings.Contains(s, "is not a registered target") {
				t.Fatalf("llc does not support triple %q: %s", triple, strings.TrimSpace(s))
			}
			t.Fatalf("llc failed for %s: %v\n%s", path, err, s)
		}
		compiled++
	}
	if compiled == 0 {
		t.Fatalf("expected at least one successful llc compilation")
	}
}

func stdlibBytealgARM64Sigs(goroot string) map[string]map[string]FuncSig {
	sfiles := map[string]map[string]FuncSig{
		filepath.Join(goroot, "src", "internal", "bytealg", "compare_arm64.s"): {
			"internal/bytealg.Compare": sigWithClassicFrame("internal/bytealg.Compare", []LLVMType{"{ ptr, i64, i64 }", "{ ptr, i64, i64 }"}, I64),
			"runtime.cmpstring":        sigWithClassicFrame("runtime.cmpstring", []LLVMType{"{ ptr, i64 }", "{ ptr, i64 }"}, I64),
			"internal/bytealg.cmpbody": sigWithClassicFrame("internal/bytealg.cmpbody", []LLVMType{Ptr, I64, Ptr, I64}, I64),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "count_arm64.s"): {
			"internal/bytealg.Count":       sigWithClassicFrame("internal/bytealg.Count", []LLVMType{"{ ptr, i64, i64 }", "i8"}, I64),
			"internal/bytealg.CountString": sigWithClassicFrame("internal/bytealg.CountString", []LLVMType{"{ ptr, i64 }", "i8"}, I64),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "index_arm64.s"): {
			"internal/bytealg.Index":       sigWithClassicFrame("internal/bytealg.Index", []LLVMType{"{ ptr, i64, i64 }", "{ ptr, i64, i64 }"}, I64),
			"internal/bytealg.IndexString": sigWithClassicFrame("internal/bytealg.IndexString", []LLVMType{"{ ptr, i64 }", "{ ptr, i64 }"}, I64),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "indexbyte_arm64.s"): {
			"internal/bytealg.IndexByte":       sigWithClassicFrame("internal/bytealg.IndexByte", []LLVMType{"{ ptr, i64, i64 }", "i8"}, I64),
			"internal/bytealg.IndexByteString": sigWithClassicFrame("internal/bytealg.IndexByteString", []LLVMType{"{ ptr, i64 }", "i8"}, I64),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "equal_arm64.s"): {
			"runtime.memequal_varlen": sigWithClassicFrame("runtime.memequal_varlen", []LLVMType{Ptr, Ptr}, I1),
			"runtime.memequal":        sigWithClassicFrame("runtime.memequal", []LLVMType{Ptr, Ptr, I64}, I1),
		},
	}

	addIfPresent := func(path, sym string, sig FuncSig) {
		src, err := os.ReadFile(path)
		if err != nil || len(src) == 0 || !containsTextSymbol(string(src), sym) {
			return
		}
		resolved := goStripABISuffix(sym)
		resolved = strings.TrimPrefix(resolved, "·")
		if strings.HasPrefix(resolved, "runtime·") {
			resolved = strings.ReplaceAll(strings.TrimPrefix(resolved, "runtime·"), "∕", "/")
			resolved = "runtime." + strings.ReplaceAll(resolved, "·", ".")
		} else {
			resolved = "internal/bytealg." + strings.ReplaceAll(resolved, "·", ".")
		}
		sig.Name = resolved
		sfiles[path][resolved] = sig
	}

	addIfPresent(
		filepath.Join(goroot, "src", "internal", "bytealg", "equal_arm64.s"),
		"memeqbody<>",
		sigWithClassicFrame("internal/bytealg.memeqbody", []LLVMType{Ptr, Ptr, I64}, I1),
	)
	addIfPresent(
		filepath.Join(goroot, "src", "internal", "bytealg", "index_arm64.s"),
		"indexbody<>",
		withArgRegs(sigWithClassicFrame("internal/bytealg.indexbody", []LLVMType{Ptr, I64, Ptr, I64, Ptr}, Void), []Reg{"R0", "R1", "R2", "R3", "R9"}),
	)
	addIfPresent(
		filepath.Join(goroot, "src", "internal", "bytealg", "indexbyte_arm64.s"),
		"indexbytebody<>",
		withArgRegs(sigWithClassicFrame("internal/bytealg.indexbytebody", []LLVMType{Ptr, "i8", I64, Ptr}, Void), []Reg{"R0", "R1", "R2", "R8"}),
	)
	addIfPresent(
		filepath.Join(goroot, "src", "internal", "bytealg", "count_arm64.s"),
		"countbytebody<>",
		withArgRegs(sigWithClassicFrame("internal/bytealg.countbytebody", []LLVMType{Ptr, I64, "i8", Ptr}, Void), []Reg{"R0", "R2", "R1", "R8"}),
	)

	for path := range sfiles {
		if _, err := os.Stat(path); err != nil {
			delete(sfiles, path)
		}
	}
	return sfiles
}

func withArgRegs(sig FuncSig, regs []Reg) FuncSig {
	sig.ArgRegs = regs
	return sig
}

func sigWithClassicFrame(name string, args []LLVMType, ret LLVMType) FuncSig {
	sig := FuncSig{Name: name, Args: args, Ret: ret}
	var off int64
	for i, arg := range args {
		off = goAlignOff(off, typeAlign(arg))
		for _, slot := range frameSlotsForType(arg, off, i, false) {
			sig.Frame.Params = append(sig.Frame.Params, slot)
		}
		off += typeSize(arg)
	}
	if ret != Void {
		off = goAlignOff(off, typeAlign(ret))
		for _, slot := range frameSlotsForType(ret, off, 0, true) {
			sig.Frame.Results = append(sig.Frame.Results, slot)
		}
	}
	return sig
}

func frameSlotsForType(ty LLVMType, off int64, index int, result bool) []FrameSlot {
	fieldIndex := func(v int) int {
		if result {
			return -1
		}
		return v
	}
	switch ty {
	case "{ ptr, i64 }":
		return []FrameSlot{
			{Offset: off + 0, Type: Ptr, Index: index, Field: fieldIndex(0)},
			{Offset: off + 8, Type: I64, Index: index, Field: fieldIndex(1)},
		}
	case "{ ptr, i64, i64 }":
		return []FrameSlot{
			{Offset: off + 0, Type: Ptr, Index: index, Field: fieldIndex(0)},
			{Offset: off + 8, Type: I64, Index: index, Field: fieldIndex(1)},
			{Offset: off + 16, Type: I64, Index: index, Field: fieldIndex(2)},
		}
	default:
		return []FrameSlot{{Offset: off, Type: ty, Index: index, Field: -1}}
	}
}

func typeSize(ty LLVMType) int64 {
	switch ty {
	case I1, "i8":
		return 1
	case "i16":
		return 2
	case I32, "float":
		return 4
	case I64, Ptr, "double":
		return 8
	case "{ ptr, i64 }":
		return 16
	case "{ ptr, i64, i64 }":
		return 24
	default:
		panic("unsupported test llvm type size: " + string(ty))
	}
}

func typeAlign(ty LLVMType) int64 {
	switch ty {
	case I1, "i8":
		return 1
	case "i16":
		return 2
	case I32, "float":
		return 4
	default:
		return 8
	}
}

func containsTextSymbol(src, sym string) bool {
	return strings.Contains(src, "TEXT "+sym+"(SB)") ||
		strings.Contains(src, "TEXT "+sym+",") ||
		strings.Contains(src, "\nTEXT "+sym+"(SB)")
}
