// Added only through an owned Go test overlay; no SDK source is replaced.
package x86

import (
	"bytes"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"encoding/json"
	"testing"
)

func TestPlan9asmOriginalStateSystemBackend(t *testing.T) {
	for _, mode := range []struct {
		name string
		arch *obj.LinkArch
	}{{"amd64", &Linkamd64}, {"386", &Link386}} {
		for _, operation := range []struct {
			name string
			op   obj.As
		}{{"FLDENV", AFLDENV}, {"XBEGIN", AXBEGIN}} {
			t.Run(mode.name+"/"+operation.name, func(t *testing.T) {
				ctxt := obj.Linknew(mode.arch)
				ctxt.Headtype, ctxt.IsAsm = objabi.Hlinux, true
				ctxt.DiagFunc = func(format string, args ...interface{}) { t.Fatalf(format, args...) }
				instinit(ctxt)
				instruction := obj.Prog{Ctxt: ctxt, As: operation.op, Pc: 13}
				expected := []byte{0xd9, 0x26}
				if operation.op == AFLDENV {
					// The original Zm_o consumes From. Stock asm's unaryDst
					// frontend places this same single operand in To instead.
					instruction.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SI}
				} else {
					instruction.To = obj.Addr{Type: obj.TYPE_BRANCH, Sym: ctxt.Lookup("plan9asm.backend.target")}
					expected = []byte{0xc7, 0xf8, 0, 0, 0, 0}
				}
				owner := &obj.LSym{Name: "plan9asm.original.state"}
				var buffer AsmBuf
				buffer.asmins(ctxt, owner, &instruction)
				if !bytes.Equal(buffer.Bytes(), expected) {
					t.Fatal("original Go backend bytes differ", buffer.Bytes(), expected)
				}
				record := struct {
					Arch, Opcode, Origin string
					PC                   int64
					Encoding             []byte
					Offset, Size, Kind   int
					KindName             string
					Symbol               string
					Add                  int64
				}{Arch: mode.name, Opcode: operation.name, Origin: "stock-backend",
					PC: instruction.Pc, Encoding: append([]byte(nil), buffer.Bytes()...)}
				if operation.op == AFLDENV {
					if len(owner.R) != 0 {
						t.Fatal("original FLDENV acquired a relocation", owner.R)
					}
				} else {
					if len(owner.R) != 1 || owner.R[0].Sym == nil {
						t.Fatal("original XBEGIN lost its unique external relocation", owner.R)
					}
					relocation := owner.R[0]
					if relocation.Type != objabi.R_CALL || relocation.Off != 15 || relocation.Siz != 4 ||
						relocation.Sym.Name != "plan9asm.backend.target" || relocation.Add != 0 {
						t.Fatal("original XBEGIN PC/width/type/symbol/addend differ", relocation)
					}
					record.Offset, record.Size, record.Kind = int(relocation.Off), int(relocation.Siz), int(relocation.Type)
					record.KindName = relocation.Type.String()
					record.Symbol, record.Add = relocation.Sym.Name, relocation.Add
				}
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("PLAN9ASM_STATE_SYSTEM_BACKEND %s", encoded)
			})
		}
	}
}
