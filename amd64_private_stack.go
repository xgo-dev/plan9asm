package plan9asm

import "fmt"

const x86PrivateStackWords = 64
const amd64PrivateStackSize = x86PrivateStackWords * 8

func (c *amd64Ctx) emitPrivateAMD64Stack() {
	c.vstackSlot, c.vspSlot = "%virt_stack", "%virt_sp"
	fmt.Fprintf(c.b, "  %s = alloca [%d x i8]\n", c.vstackSlot, amd64PrivateStackSize)
	fmt.Fprintf(c.b, "  store [%d x i8] zeroinitializer, ptr %s\n", amd64PrivateStackSize, c.vstackSlot)
	fmt.Fprintf(c.b, "  %s = alloca i64\n", c.vspSlot)
	// Keep the legacy synthetic entry word outside the proved private span.
	fmt.Fprintf(c.b, "  store i64 %d, ptr %s\n", amd64PrivateStackSize-8, c.vspSlot)
}

// The result proof independently bounds live accesses. Clamp here to keep
// legacy paths without that proof inside the alloca, including entry POPQ.
func (c *amd64Ctx) privateAMD64StackAddress(width int, push bool) string {
	sp, outOfBounds, index, next, pointer := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", sp, c.vspSlot)
	if push {
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %d\n", outOfBounds, sp, width)
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %d\n", next, sp, width)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %%%s\n", index, outOfBounds, next)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", index, c.vspSlot)
	} else {
		limit := amd64PrivateStackSize - width
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i64 %%%s, %d\n", outOfBounds, sp, limit)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %d, i64 %%%s\n", index, outOfBounds, limit, sp)
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %d\n", next, index, width)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s\n", next, c.vspSlot)
	}
	fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [%d x i8], ptr %s, i64 0, i64 %%%s\n",
		pointer, amd64PrivateStackSize, c.vstackSlot, index)
	return "%" + pointer
}
