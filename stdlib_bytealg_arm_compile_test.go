package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStdlibInternalBytealg_ARM_Compile(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc not found")
	}
	goroot := runtime.GOROOT()
	if goroot == "" {
		t.Fatal("GOROOT not available")
	}
	sfiles := stdlibBytealgARMSigs(goroot)
	if len(sfiles) == 0 {
		t.Fatal("internal/bytealg arm asm files not present in this GOROOT")
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

	triple := "armv7-unknown-linux-gnueabihf"
	compiled := 0
	for path, sigs := range sfiles {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := Parse(ArchARM, string(src))
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			ResolveSym:   resolve,
			Sigs:         sigs,
			Goarch:       "arm",
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

func stdlibBytealgARMSigs(goroot string) map[string]map[string]FuncSig {
	sfiles := map[string]map[string]FuncSig{
		filepath.Join(goroot, "src", "internal", "bytealg", "compare_arm.s"): {
			"internal/bytealg.Compare": sigWithClassicFrame32("internal/bytealg.Compare", []LLVMType{"{ ptr, i32, i32 }", "{ ptr, i32, i32 }"}, I32),
			"runtime.cmpstring":        sigWithClassicFrame32("runtime.cmpstring", []LLVMType{"{ ptr, i32 }", "{ ptr, i32 }"}, I32),
			"internal/bytealg.cmpbody": withArgRegs(sigWithClassicFrame32("internal/bytealg.cmpbody", []LLVMType{Ptr, I32, Ptr, I32, Ptr}, Void), []Reg{"R2", "R0", "R3", "R1", "R7"}),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "equal_arm.s"): {
			"runtime.memequal":           sigWithClassicFrame32("runtime.memequal", []LLVMType{Ptr, Ptr, I32}, I1),
			"runtime.memequal_varlen":    sigWithClassicFrame32("runtime.memequal_varlen", []LLVMType{Ptr, Ptr}, I1),
			"internal/bytealg.memeqbody": withArgRegs(sigWithClassicFrame32("internal/bytealg.memeqbody", []LLVMType{Ptr, Ptr, I32, Ptr}, Void), []Reg{"R0", "R2", "R1", "R7"}),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "count_arm.s"): {
			"internal/bytealg.Count":         sigWithClassicFrame32("internal/bytealg.Count", []LLVMType{"{ ptr, i32, i32 }", I8}, I32),
			"internal/bytealg.CountString":   sigWithClassicFrame32("internal/bytealg.CountString", []LLVMType{"{ ptr, i32 }", I8}, I32),
			"internal/bytealg.countbytebody": withArgRegs(sigWithClassicFrame32("internal/bytealg.countbytebody", []LLVMType{Ptr, I32, I8, Ptr}, Void), []Reg{"R0", "R1", "R2", "R7"}),
		},
		filepath.Join(goroot, "src", "internal", "bytealg", "indexbyte_arm.s"): {
			"internal/bytealg.IndexByte":       sigWithClassicFrame32("internal/bytealg.IndexByte", []LLVMType{"{ ptr, i32, i32 }", I8}, I32),
			"internal/bytealg.IndexByteString": sigWithClassicFrame32("internal/bytealg.IndexByteString", []LLVMType{"{ ptr, i32 }", I8}, I32),
			"internal/bytealg.indexbytebody":   withArgRegs(sigWithClassicFrame32("internal/bytealg.indexbytebody", []LLVMType{Ptr, I32, I8, Ptr}, Void), []Reg{"R0", "R1", "R2", "R5"}),
		},
	}
	for path := range sfiles {
		if _, err := os.Stat(path); err != nil {
			delete(sfiles, path)
		}
	}
	return sfiles
}

func sigWithClassicFrame32(name string, args []LLVMType, ret LLVMType) FuncSig {
	sig := FuncSig{Name: name, Args: args, Ret: ret}
	var off int64
	for i, arg := range args {
		off = alignOff32(off, typeAlign32(arg))
		for _, slot := range frameSlotsForType32(arg, off, i, false) {
			sig.Frame.Params = append(sig.Frame.Params, slot)
		}
		off += typeSize32(arg)
	}
	if ret != Void {
		off = alignOff32(off, typeAlign32(ret))
		for _, slot := range frameSlotsForType32(ret, off, 0, true) {
			sig.Frame.Results = append(sig.Frame.Results, slot)
		}
	}
	return sig
}

func frameSlotsForType32(ty LLVMType, off int64, index int, result bool) []FrameSlot {
	fieldIndex := func(v int) int {
		if result {
			return -1
		}
		return v
	}
	switch ty {
	case "{ ptr, i32 }":
		return []FrameSlot{
			{Offset: off + 0, Type: Ptr, Index: index, Field: fieldIndex(0)},
			{Offset: off + 4, Type: I32, Index: index, Field: fieldIndex(1)},
		}
	case "{ ptr, i32, i32 }":
		return []FrameSlot{
			{Offset: off + 0, Type: Ptr, Index: index, Field: fieldIndex(0)},
			{Offset: off + 4, Type: I32, Index: index, Field: fieldIndex(1)},
			{Offset: off + 8, Type: I32, Index: index, Field: fieldIndex(2)},
		}
	default:
		return []FrameSlot{{Offset: off, Type: ty, Index: index, Field: -1}}
	}
}

func typeSize32(ty LLVMType) int64 {
	switch ty {
	case I1, I8:
		return 1
	case I16:
		return 2
	case I32, Ptr:
		return 4
	case I64:
		return 8
	case "{ ptr, i32 }":
		return 8
	case "{ ptr, i32, i32 }":
		return 12
	default:
		return 4
	}
}

func typeAlign32(ty LLVMType) int64 {
	switch ty {
	case I64:
		return 4
	case "{ ptr, i32 }", "{ ptr, i32, i32 }", I32, Ptr:
		return 4
	case I16:
		return 2
	default:
		return 1
	}
}

func alignOff32(off, align int64) int64 {
	if align <= 1 {
		return off
	}
	m := off % align
	if m == 0 {
		return off
	}
	return off + (align - m)
}
