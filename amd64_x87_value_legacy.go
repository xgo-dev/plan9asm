package plan9asm

// These adapters isolate the pre-existing binary64 numerical implementation
// while the portable provider is migrated. Native value lowering must never
// enter them. They are not an extended-precision arithmetic implementation.
func (c *amd64Ctx) x87LegacyF64(value x87Value) string {
	if c.x87NativeValues {
		panic("native x87 value entered the temporary binary64 adapter")
	}
	result, err := c.x87PortableToFloat(value, 64, "895")
	if err != nil {
		panic(err) // The private adapter always requests the supported width.
	}
	return result
}

func (c *amd64Ctx) x87LegacyF64Value(value string) x87Value {
	if c.x87NativeValues {
		panic("native x87 value entered the temporary binary64 adapter")
	}
	result, err := c.x87PortableFromFloat(value, 64)
	if err != nil {
		panic(err)
	}
	return result
}
