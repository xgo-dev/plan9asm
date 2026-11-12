package plan9asm

import (
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func requireX86DemandDeclarations(t *testing.T, ir string, want ...string) {
	t.Helper()
	var got []string
	ordinary := make(map[string]bool)
	for _, line := range strings.Split(ir, "\n") {
		if !strings.HasPrefix(line, "declare ") {
			continue
		}
		for name := range llvmTextGlobalNames(line) {
			if strings.HasPrefix(name, "llvm.") {
				got = append(got, name)
			} else {
				ordinary[name] = true
			}
		}
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("LLVM declarations = %v, want only actual uses %v (IR: %d bytes)", got, want, len(ir))
	}
	if len(ordinary) != 6 {
		t.Errorf("ordinary declarations = %v, want the six original external declarations", ordinary)
	}
	for _, name := range []string{"syscall", "cliteErrno", "atan2", "fmod", "remainder", "tan"} {
		if !ordinary[name] {
			t.Errorf("lost original ordinary declaration %s", name)
		}
	}
}

func TestX86DemandPreludeContainsOnlyUsedDeclarations(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			name, body string
			want       []string
		}{
			{name: "scalar", body: "MOVL $7,AX\nRET"},
			{name: "annotated-comment", body: "MOVL $7,AX // @llvm.bswap.i64( is only a comment\nRET"},
			{name: "scalar-intrinsic", body: "MOVL $7,AX\nPOPCNTL AX,BX\nRET", want: []string{"llvm.ctpop.i32"}},
			{name: "vector-intrinsic", body: "PXOR X0,X0\nPXOR X1,X1\nPSHUFB X0,X1\nRET", want: []string{"llvm.x86.ssse3.pshuf.b.128"}},
			{name: "source-sha", body: "PXOR X1,X1\nSHA1MSG1 X1,X1\nRET", want: []string{"llvm.x86.sha1msg1"}},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, testTargetTriple("linux", arch), targetBackendCase{
						arch: ArchAMD64, goarch: arch, body: row.body,
					})
					if err != nil {
						t.Fatal("initialized source must translate before checking declaration demand", err)
					}
					requireX86DemandDeclarations(t, ir, row.want...)
				})
			}
		}
	}
}

func TestX86DemandPreludeRetainsSourceHelperClosure(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, api := range []string{"text", "module", "Go"} {
			for _, row := range []struct {
				kind, bits string
			}{{"SS", "32"}, {"SD", "64"}} {
				t.Run(arch+"/rounded-fma"+row.bits+"/"+api, func(t *testing.T) {
					// The emitted software helper itself references both intrinsics,
					// even when a matching native entry uses exact inline assembly.
					ir, err := targetBackendRequest(t, api, testTargetTriple("linux", arch), targetBackendCase{
						arch: ArchAMD64, goarch: arch,
						body: "PXOR X0,X0\nPXOR X1,X1\nPXOR X2,X2\nVFMADD132" + row.kind + ".RD_SAE X0,X1,X2\nRET",
					})
					if err != nil {
						t.Fatal("initialized FMA source must translate before checking helper closure", err)
					}
					helper := x86StringMemoryFunction(t, ir, "__plan9asm_fma3_round_f"+row.bits)
					for _, call := range []string{"@llvm.fma.f" + row.bits + "(", "@llvm.ctlz.i128("} {
						if !strings.Contains(helper, call) {
							t.Fatal("source-dependent FMA helper lost its intrinsic reference", call)
						}
					}
					requireX86DemandDeclarations(t, ir, "llvm.fma.f"+row.bits, "llvm.ctlz.i128")
					compileLLVMToObject(t, llc, testTargetTriple("linux", arch), "demand-fma.ll", "demand-fma.o", ir)
				})
			}
			t.Run(arch+"/string-helper/"+api, func(t *testing.T) {
				// Reuse the initialized native-pointer source owner; selecting
				// declarations must not rebuild its memory or runtime matrix.
				source, declarations := x86StringRepeatCFGFixture(
					x86StringMemoryRow{op: "MOVSB", kind: "movs", width: 1, reads: 1, writes: 1},
					arch, "REP", "adjacent")
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, testTargetTriple("linux", arch), api)
				if err != nil {
					t.Fatal("original string source must translate before checking helper preservation", err)
				}
				helper := x86StringMemoryFunction(t, ir, "__plan9asm_movsb")
				if err := x86StringMemoryIRAccessError(helper, 1, 1, 1); err != nil {
					t.Fatal(err)
				}
				requireX86DemandDeclarations(t, ir)
				compileLLVMToObject(t, llc, testTargetTriple("linux", arch), "demand-string.ll", "demand-string.o", ir)
			})
		}
	}
}

func TestX86DemandPreludeLeavesDirectModuleIndependent(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT scalar(SB),4,$0-0\nMOVL $7,AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"scalar": {Name: "scalar", Ret: Void}}}
	for _, translate := range []func(llvm.Context, *File, Options) (llvm.Module, error){
		translateModuleDirectInContext, TranslateModuleInContext,
	} {
		module, err := translate(ctx, file, options)
		if err != nil || module.IsNil() {
			if !module.IsNil() {
				module.Dispose()
			}
			t.Fatal("ordinary direct-module source must remain independent of textual prelude", err)
		}
		ir := module.String()
		module.Dispose()
		if strings.Contains(ir, "declare ") {
			t.Fatal("ordinary direct-module source acquired textual prelude declarations")
		}
	}
}
