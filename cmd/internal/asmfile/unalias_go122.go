//go:build go1.22

package asmfile

import "go/types"

func unaliasType(t types.Type) types.Type {
	return types.Unalias(t)
}
