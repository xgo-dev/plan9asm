package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ImmediatePackedCompareCompleteGoRowsAndAttributes(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	actual := strings.Join(strings.Fields(string(source)), "")
	rows := []string{
		"{zcase:Zevex_i_rm_v_r,zoffset:0,args:argList{Yu8,YxmEvex,YxrEvex,Yk}}",
		"{zcase:Zevex_i_rm_v_k_r,zoffset:3,args:argList{Yu8,YxmEvex,YxrEvex,Yknot0,Yk}}",
		"{zcase:Zevex_i_rm_v_r,zoffset:0,args:argList{Yu8,YymEvex,YyrEvex,Yk}}",
		"{zcase:Zevex_i_rm_v_k_r,zoffset:3,args:argList{Yu8,YymEvex,YyrEvex,Yknot0,Yk}}",
		"{zcase:Zevex_i_rm_v_r,zoffset:0,args:argList{Yu8,Yzm,Yzr,Yk}}",
		"{zcase:Zevex_i_rm_v_k_r,zoffset:3,args:argList{Yu8,Yzm,Yzr,Yknot0,Yk}}",
	}
	if !strings.Contains(actual, "var_yvpcmpb=[]ytab{"+strings.Join(rows, ",")+",}") {
		t.Fatal("actual SDK complete ordered immediate comparison rows changed")
	}
	seen := map[string]bool{}
	for _, match := range regexp.MustCompile(`\{as:A(VPCMPU?[BWDQ]),ytab:_yvpcmpb,`).FindAllStringSubmatch(actual, -1) {
		if seen[match[1]] {
			t.Fatal("duplicate actual SDK immediate comparison member", match[1])
		}
		seen[match[1]] = true
	}
	if len(seen) != 8 || len(amd64ImmediatePackedCompareSpecs) != 8 {
		t.Fatal("complete immediate comparison family changed", seen)
	}
	for _, op := range x86ImmediateCompareResultMembers {
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		unsigned := strings.HasPrefix(op, "VPCMPU")
		w, broadcast := "W0", ""
		if bits == 16 || bits == 64 {
			w = "W1"
		}
		if bits >= 32 {
			broadcast = fmt.Sprintf("|evexBcstN%d", bits/8)
		}
		opcode := 0x3f
		if bits >= 32 {
			opcode = 0x1f
		}
		if unsigned {
			opcode--
		}
		var attributes strings.Builder
		for _, width := range []int{128, 256, 512} {
			fmt.Fprintf(&attributes, "avxEscape|evex%d|evex66|evex0F3A|evex%s,evexN%d%s,0x%X,", width, w, width/8, broadcast, opcode)
		}
		if !strings.Contains(actual, "{as:A"+op+",ytab:_yvpcmpb,prefix:Pavx,op:opBytes{"+attributes.String()+"}},") {
			t.Fatal("actual SDK immediate comparison encoding attributes changed", op)
		}
		spec, present := amd64ImmediatePackedCompareSpecs[op]
		if !seen[op] || !present || spec.laneBits != bits || spec.unsigned != unsigned {
			t.Fatal("typed spec differs from complete independent Go member", op, spec)
		}
	}
}
