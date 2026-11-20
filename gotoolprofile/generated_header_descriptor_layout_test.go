package gotoolprofile

import (
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

const nativeHeaderDescriptorSource = `package header
type Record struct {
    Word uintptr
    Pointer *byte
    Slice []uint16
    Text string
    Map map[uint8]uint16
    Channel chan uint64
    Send chan<- uint64
    Receive <-chan uint64
    Function func(uintptr) uintptr
    Empty interface{}
    NonEmpty interface { Read([]byte) (int, error) }
    Tail [0]byte
}
type Alias = Record
type Recursive struct {
    Next *Recursive
    Children map[string]*Recursive
    Siblings []*Recursive
}
type Array struct { Elements [2]Record; Marker byte }
type Zero struct { Function func(); Tail [0]*byte }
`

func TestGeneratedHeaderDescriptorLayoutsMatchActualNativeObjects(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target, nativeHeaderDescriptorSource)
			replayed, err := ReplayNativeGeneratedHeader("example.invalid/header", target, "go1.20",
				map[string]string{"header.go": nativeHeaderDescriptorSource})
			if err != nil || !reflect.DeepEqual(actual, replayed) {
				t.Fatalf("complete native descriptor header differs from original source replay:\nactual=%v\nreplayed=%v\nerror=%v", actual, replayed, err)
			}
			word := 8
			if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
				word = 4
			}
			for name, words := range map[string]int{
				"Record__size": 17, "Record_Pointer": 1, "Record_Slice": 2, "Record_Text": 5,
				"Record_Map": 7, "Record_Channel": 8, "Record_Send": 9, "Record_Receive": 10,
				"Record_Function": 11, "Record_Empty": 12, "Record_NonEmpty": 14, "Record_Tail": 16,
				"Recursive__size": 5, "Recursive_Next": 0, "Recursive_Children": 1, "Recursive_Siblings": 2,
				"Array__size": 35, "Array_Marker": 34, "Zero__size": 2, "Zero_Tail": 1,
			} {
				if actual[name] != fmt.Sprint(words*word) {
					t.Fatalf("native word layout/tail padding changed: %s=%s, want %d", name, actual[name], words*word)
				}
			}
		})
	}
}

func TestGeneratedHeaderUnsafePointerPropertyMatchesActualNativeObjects(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target,
				"package header\nimport \"unsafe\"\ntype Record struct { Value unsafe.Pointer }\n")
			word := int64(8)
			if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
				word = 4
			}
			sizes := &nativeHeaderGCSizes{word: word, cache: make(map[types.Type]nativeHeaderLayout), active: make(map[types.Type]bool)}
			layout, err := sizes.layout(types.Typ[types.UnsafePointer], 0)
			if err != nil || layout.size != word || layout.align != word || actual["Record__size"] != fmt.Sprint(layout.size) {
				t.Fatalf("unsafe pointer property differs from native object: %+v %v actual=%v", layout, err, actual)
			}
		})
	}
}
