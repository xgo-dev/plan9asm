package plan9asm

import (
	"errors"
	"go/token"
	"go/types"
	"testing"
)

type amd64ArgumentCallbackType struct{ calls *int }

func (typ *amd64ArgumentCallbackType) Underlying() types.Type {
	*typ.calls++
	return types.Typ[types.Uint64]
}
func (typ *amd64ArgumentCallbackType) String() string                   { *typ.calls++; return "uint64" }
func (typ *amd64ArgumentCallbackType) TypeParams() *types.TypeParamList { *typ.calls++; return nil }

func TestAMD64GoArgumentEntryRejectsCallerTypeCallbacksBeforeSampling(t *testing.T) {
	calls := 0
	typ := &amd64ArgumentCallbackType{&calls}
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "x", typ)), nil, false)
	defer func() {
		if failure := recover(); failure != nil {
			t.Errorf("caller-controlled type reached compiler layout/panicked: %v (callbacks=%d)", failure, calls)
		}
	}()
	plan, err := planAMD64GoArguments(sig)
	if plan != nil || !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
		t.Fatalf("non-source go/types implementation reached callback under a future owner lock: %#v, %v, calls=%d", plan, err, calls)
	}
}
