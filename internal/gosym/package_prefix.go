// Package gosym describes Go's native symbol spelling, not source permissions
// or the LLVM logical namespace.
package gosym

import "strings"

// PackagePrefix implements objabi.PathToPrefix's byte grammar. Only periods
// after the final slash are escaped; UTF-8 is escaped one byte at a time.
func PackagePrefix(packagePath string) string {
	lastSlash := strings.LastIndexByte(packagePath, '/')
	escaped := func(index int) bool {
		value := packagePath[index]
		return value <= ' ' || value == '.' && index > lastSlash ||
			value == '%' || value == '"' || value >= 0x7f
	}
	count := 0
	for index := 0; index < len(packagePath); index++ {
		if escaped(index) {
			count++
		}
	}
	if count == 0 {
		return packagePath
	}
	const hex = "0123456789abcdef"
	var prefix strings.Builder
	prefix.Grow(len(packagePath) + 2*count)
	for index := 0; index < len(packagePath); index++ {
		value := packagePath[index]
		if escaped(index) {
			prefix.WriteByte('%')
			prefix.WriteByte(hex[value>>4])
			prefix.WriteByte(hex[value&0xf])
		} else {
			prefix.WriteByte(value)
		}
	}
	return prefix.String()
}
