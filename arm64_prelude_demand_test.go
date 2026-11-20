package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestLLVMTextGlobalNames(t *testing.T) {
	const text = `; @not.a.use()
@"global;name" = constant [14 x i8] c"@not.a.use()\00"
define void @body() {
  %x = call i32 @llvm.ctlz.i32(i32 7, i1 false)
  %y = call i64 @"llvm.bitreverse\2Ei64"(i64 7)
  call void @prefix.longer()
  ret void ; @also.not.a.use
}
`
	want := map[string]bool{
		"global;name": true, "body": true, "llvm.ctlz.i32": true,
		"llvm.bitreverse.i64": true, "prefix.longer": true,
	}
	if got := llvmTextGlobalNames(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("LLVM global names = %v, want %v", got, want)
	}
}

func TestARM64PreludeContainsOnlyUsedDeclarations(t *testing.T) {
	for _, row := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "scalar",
			body: "MOVD $7, R0\nMOVD R0, ret+0(FP)\nRET",
		},
		{
			name: "annotated-comment",
			body: "MOVD $7, R0 // @llvm.bitreverse.i64( is only a comment\nMOVD R0, ret+0(FP)\nRET",
		},
		{
			name: "scalar-intrinsics",
			body: "MOVD $7, R0\nRBIT R0, R1\nCLZW R1, R0\nMOVD R0, ret+0(FP)\nRET",
			want: []string{"llvm.bitreverse.i64", "llvm.ctlz.i32"},
		},
		{
			name: "scalable-intrinsic",
			body: "CNTB R0\nMOVD R0, ret+0(FP)\nRET",
			want: []string{"llvm.aarch64.sve.cntb"},
		},
		{
			name: "raw-scalable-intrinsic",
			body: "WORD $0x0420e3ea\nMOVD R10, ret+0(FP)\nRET",
			want: []string{"llvm.aarch64.sve.cntb"},
		},
	} {
		// The current entry lowerer reads the incoming LR through this
		// intrinsic even for an ordinary scalar leaf. It is an actual use,
		// unlike the other 2,220 declarations formerly emitted unconditionally.
		row.want = append(row.want, "llvm.returnaddress")
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", targetBackendCase{
					arch: ArchARM64, goarch: "arm64", body: row.body, result: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				var declarations []string
				for _, line := range strings.Split(ir, "\n") {
					if strings.HasPrefix(line, "declare ") {
						declarations = append(declarations, line)
					}
				}
				if len(declarations) != len(row.want) {
					t.Fatalf("generated %d declarations, want only %d used declarations (IR: %d bytes)",
						len(declarations), len(row.want), len(ir))
				}
				t.Logf("%d bytes of IR, %d used declarations", len(ir), len(declarations))
				for _, name := range row.want {
					found := false
					for _, declaration := range declarations {
						found = found || strings.Contains(declaration, "@"+name+"(")
					}
					if !found {
						t.Errorf("missing used declaration %s", name)
					}
				}
			})
		}
	}
}

func TestARM64DemandPreludeLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	row := targetBackendCase{
		arch: ArchARM64, goarch: "arm64", result: true,
		body: "CNTB R0\nRBIT R0, R1\nCLZW R1, R0\nMOVD R0, ret+0(FP)\nRET",
	}
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, triple, row)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "demand.ll", "demand.o", ir)
			})
		}
	}
}
