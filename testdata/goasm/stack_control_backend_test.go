// Copied only into an added, owned SDK test overlay. This file never changes
// Go's encoder, existing tests, tables or source classification.
package x86

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"encoding/json"
	"testing"
)

func TestPlan9asmOriginalDuffSource(t *testing.T) {
	for _, mode := range []struct {
		name string
		arch *obj.LinkArch
	}{{"amd64", &Linkamd64}, {"386", &Link386}} {
		for _, operation := range []struct {
			op           obj.As
			name, symbol string
		}{{obj.ADUFFCOPY, "DUFFCOPY", "runtime.duffcopy"}, {obj.ADUFFZERO, "DUFFZERO", "runtime.duffzero"}} {
			ctxt := obj.Linknew(mode.arch)
			ctxt.Headtype = objabi.Hlinux
			ctxt.IsAsm = true
			ctxt.DiagFunc = func(format string, args ...interface{}) { t.Fatalf(format, args...) }
			instinit(ctxt)
			instruction := obj.Prog{Ctxt: ctxt, As: operation.op, Pc: 13,
				To: obj.Addr{Type: obj.TYPE_ADDR, Sym: ctxt.Lookup(operation.symbol), Offset: 37}}
			owner := &obj.LSym{Name: "plan9asm.original.duff"}
			var buffer AsmBuf
			buffer.asmins(ctxt, owner, &instruction)
			if len(owner.R) != 1 || owner.R[0].Sym == nil {
				t.Fatal("actual DUFF encoder did not preserve its symbol relocation", owner.R)
			}
			relocation := owner.R[0]
			displacement := int(relocation.Off) - int(instruction.Pc)
			if relocation.Type != objabi.R_CALL || displacement < 1 || displacement+4 > buffer.Len() ||
				buffer.Bytes()[displacement-1] != 0xe8 || relocation.Siz != 4 ||
				relocation.Sym.Name != operation.symbol || relocation.Add != 37 {
				t.Fatal("actual original DUFF PC/symbol/addend changed", relocation)
			}
			record := struct {
				Arch, Opcode, Origin string
				PC                   int64
				Encoding             []byte
				Offset, Size, Kind   int
				Symbol               string
				Add                  int64
			}{mode.name, operation.name, "stock-backend", instruction.Pc,
				append([]byte(nil), buffer.Bytes()...), int(relocation.Off), int(relocation.Siz),
				int(relocation.Type), relocation.Sym.Name, relocation.Add}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("PLAN9ASM_SOURCE_DUFF %s", encoded)
		}
	}
}
