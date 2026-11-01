package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) emitAMD64GoArguments() error {
	entry := c.sig.amd64GoArguments
	if entry != nil && entry.virtual != nil {
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	if entry == nil || !entry.valid(c.fpScalarSource, c.sig, c.goarch) || !c.fpScalarChecked || c.fpScalarCheckErr != nil {
		return amd64GoArgumentContext("entry emission lacks its complete live source-byte proof")
	}
	for _, argument := range entry.plan.Arguments {
		for _, carrier := range argument.Carriers {
			value := fmt.Sprintf("%%arg%d", argument.Index)
			if len(carrier.Path) != 0 {
				var path []string
				for _, field := range carrier.Path {
					path = append(path, fmt.Sprint(field))
				}
				temporary := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %s\n", temporary, c.sig.Args[argument.Index], value, strings.Join(path, ", "))
				value = "%" + temporary
			}
			if carrier.Kind != amd64GoArgumentFloating {
				slot, used := c.regSlot[carrier.Register]
				if !used {
					continue
				}
				integer, valid, err := amd64ValueAsI64(c, carrier.Type, value)
				if err != nil || !valid {
					return amd64GoArgumentContext("declared GP carrier lost its LLVM scalar transport")
				}
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s\n", integer, slot)
				continue
			}
			index, valid := amd64ParseXReg(carrier.Register)
			if !valid {
				return amd64GoArgumentContext("invalid declared FP carrier")
			}
			if _, used := c.xRegSlot[index]; !used {
				continue
			}
			bits := carrier.Width * 8
			integer, lane, bytes := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", integer, carrier.Type, value, bits)
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %%%s, i32 0\n", lane, 128/bits, bits, bits, integer)
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, 128/bits, bits, lane)
			if err := c.storeX(carrier.Register, "%"+bytes); err != nil {
				return err
			}
		}
	}
	// The virtual slots use a deterministic representative for unused bytes.
	// The complete source proof initialized only each declared scalar width,
	// never the representative upper GP/X bytes or the native ABI spill homes.
	return nil
}
