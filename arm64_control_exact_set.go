package plan9asm

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
)

// A control value owns immutable exact token/bool entries. Only the lazy
// projections are mutable, and each is published once under its own guard.
// There is no global interner or cache, and no source/permission memoization.
type arm64ControlValue = *arm64ControlSet

type arm64ControlSet struct {
	root        *arm64ControlNode
	labelsOnce  sync.Once
	labels      arm64ControlValue
	addressOnce sync.Once
	address     arm64ControlValue
}

type arm64ControlEntry struct {
	token   string
	present bool
}

// A compressed binary trie branches at one hash bit. Hash collisions remain
// sorted full-string entries in a leaf; a hash never establishes equality.
type arm64ControlNode struct {
	hash                uint64
	split               uint64
	left, right         *arm64ControlNode
	entries             []arm64ControlEntry
	count, falseEntries int
	frames, labels      int
	nonUnknown          int
}

func arm64ControlHash(token string) uint64 {
	const prime = uint64(1099511628211)
	hash := uint64(14695981039346656037)
	for index := 0; index < len(token); index++ {
		hash = (hash ^ uint64(token[index])) * prime
	}
	return hash
}

func arm64ControlFrameToken(token string) bool {
	return strings.HasPrefix(token, "sp:") || strings.HasPrefix(token, "fp:")
}

func arm64ControlLeaf(hash uint64, entries []arm64ControlEntry) *arm64ControlNode {
	if len(entries) == 0 {
		return nil
	}
	node := &arm64ControlNode{hash: hash, entries: append([]arm64ControlEntry(nil), entries...), count: len(entries)}
	for _, entry := range entries {
		if !entry.present {
			node.falseEntries++
		}
		if arm64ControlFrameToken(entry.token) {
			node.frames++
		}
		if strings.HasPrefix(entry.token, "label:") || entry.token == "code-derived:" {
			node.labels++
		}
		if entry.token != "" {
			node.nonUnknown++
		}
	}
	return node
}

func arm64ControlBranch(split uint64, left, right *arm64ControlNode) *arm64ControlNode {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return &arm64ControlNode{
		hash: left.hash, split: split, left: left, right: right,
		count: left.count + right.count, falseEntries: left.falseEntries + right.falseEntries,
		frames: left.frames + right.frames, labels: left.labels + right.labels,
		nonUnknown: left.nonUnknown + right.nonUnknown,
	}
}

func arm64ControlSplit(left, right uint64) uint64 {
	if difference := left ^ right; difference != 0 {
		return uint64(1) << (63 - bits.LeadingZeros64(difference))
	}
	return 0
}

func arm64ControlInsert(node *arm64ControlNode, hash uint64, token string, present bool) *arm64ControlNode {
	if node == nil {
		return arm64ControlLeaf(hash, []arm64ControlEntry{{token, present}})
	}
	if split := arm64ControlSplit(node.hash, hash); split > node.split {
		leaf := arm64ControlLeaf(hash, []arm64ControlEntry{{token, present}})
		if hash&split == 0 {
			return arm64ControlBranch(split, leaf, node)
		}
		return arm64ControlBranch(split, node, leaf)
	}
	if node.split != 0 {
		if hash&node.split == 0 {
			left := arm64ControlInsert(node.left, hash, token, present)
			if left == node.left {
				return node
			}
			return arm64ControlBranch(node.split, left, node.right)
		}
		right := arm64ControlInsert(node.right, hash, token, present)
		if right == node.right {
			return node
		}
		return arm64ControlBranch(node.split, node.left, right)
	}
	index := sort.Search(len(node.entries), func(index int) bool { return node.entries[index].token >= token })
	if index < len(node.entries) && node.entries[index].token == token && node.entries[index].present == present {
		return node
	}
	entries := append([]arm64ControlEntry(nil), node.entries...)
	if index < len(entries) && entries[index].token == token {
		entries[index].present = present
	} else {
		entries = append(entries, arm64ControlEntry{})
		copy(entries[index+1:], entries[index:])
		entries[index] = arm64ControlEntry{token, present}
	}
	return arm64ControlLeaf(hash, entries)
}

func arm64ControlLookup(node *arm64ControlNode, hash uint64, token string) bool {
	for node != nil && node.split != 0 {
		if hash&node.split == 0 {
			node = node.left
		} else {
			node = node.right
		}
	}
	if node == nil || node.hash != hash {
		return false
	}
	index := sort.Search(len(node.entries), func(index int) bool { return node.entries[index].token >= token })
	return index < len(node.entries) && node.entries[index].token == token && node.entries[index].present
}

func arm64ControlVisitNode(node *arm64ControlNode, visit func(uint64, string, bool) bool) bool {
	if node == nil {
		return true
	}
	if node.split != 0 {
		return arm64ControlVisitNode(node.left, visit) && arm64ControlVisitNode(node.right, visit)
	}
	for _, entry := range node.entries {
		if !visit(node.hash, entry.token, entry.present) {
			return false
		}
	}
	return true
}

func arm64ControlCount(value arm64ControlValue) int {
	if value == nil || value.root == nil {
		return 0
	}
	return value.root.count
}

func arm64ControlHas(value arm64ControlValue, token string) bool {
	return value != nil && arm64ControlLookup(value.root, arm64ControlHash(token), token)
}

func arm64ControlKeys(value arm64ControlValue) []string {
	keys := make([]string, 0, arm64ControlCount(value))
	if value != nil {
		arm64ControlVisitNode(value.root, func(_ uint64, token string, _ bool) bool {
			keys = append(keys, token)
			return true
		})
	}
	return keys
}

func arm64ControlFromMap(entries map[string]bool) arm64ControlValue {
	if entries == nil {
		return nil
	}
	value := &arm64ControlSet{}
	for token, present := range entries {
		value.root = arm64ControlInsert(value.root, arm64ControlHash(token), token, present)
	}
	return value
}

func arm64ControlMap(value arm64ControlValue) map[string]bool {
	if value == nil {
		return nil
	}
	entries := make(map[string]bool, arm64ControlCount(value))
	arm64ControlVisitNode(value.root, func(_ uint64, token string, present bool) bool {
		entries[token] = present
		return true
	})
	return entries
}

func (value *arm64ControlSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(arm64ControlMap(value))
}

func (value *arm64ControlSet) String() string {
	return fmt.Sprint(arm64ControlMap(value))
}

func arm64ControlCanonical(value arm64ControlValue) bool {
	return value != nil && (value.root == nil || value.root.falseEntries == 0 && value.root.frames <= 1)
}

func arm64ControlSubsetNodes(subset, superset *arm64ControlNode) bool {
	if subset == nil {
		return true
	}
	if superset == nil || subset.count > superset.count {
		return false
	}
	if subset == superset {
		return superset.falseEntries == 0
	}
	if subset.split == superset.split && arm64ControlSplit(subset.hash, superset.hash) <= subset.split && subset.split != 0 {
		return arm64ControlSubsetNodes(subset.left, superset.left) && arm64ControlSubsetNodes(subset.right, superset.right)
	}
	if superset.split > subset.split && arm64ControlSplit(subset.hash, superset.hash) <= superset.split {
		if subset.hash&superset.split == 0 {
			return arm64ControlSubsetNodes(subset, superset.left)
		}
		return arm64ControlSubsetNodes(subset, superset.right)
	}
	return arm64ControlVisitNode(subset, func(hash uint64, token string, _ bool) bool {
		return arm64ControlLookup(superset, hash, token)
	})
}

func arm64ControlSubset(subset, superset arm64ControlValue) bool {
	var left, right *arm64ControlNode
	if subset != nil {
		left = subset.root
	}
	if superset != nil {
		right = superset.root
	}
	return arm64ControlSubsetNodes(left, right)
}

func arm64ControlEqual(left, right arm64ControlValue) bool {
	return arm64ControlCount(left) == arm64ControlCount(right) && arm64ControlSubset(left, right)
}

type arm64ControlProjection uint8

const (
	arm64ControlAllTokens arm64ControlProjection = iota
	arm64ControlLabelTokens
	arm64ControlAddressTokens
	arm64ControlNonFrameTokens
)

func arm64ControlProject(node *arm64ControlNode, kind arm64ControlProjection) *arm64ControlNode {
	if node == nil {
		return nil
	}
	selected := node.count
	switch kind {
	case arm64ControlLabelTokens:
		selected = node.labels
	case arm64ControlAddressTokens:
		selected = node.nonUnknown
	case arm64ControlNonFrameTokens:
		selected -= node.frames
	}
	if selected == 0 {
		return nil
	}
	if selected == node.count && node.falseEntries == 0 {
		return node
	}
	if node.split != 0 {
		return arm64ControlBranch(node.split, arm64ControlProject(node.left, kind), arm64ControlProject(node.right, kind))
	}
	entries := make([]arm64ControlEntry, 0, selected)
	for _, entry := range node.entries {
		keep := true
		switch kind {
		case arm64ControlLabelTokens:
			keep = strings.HasPrefix(entry.token, "label:") || entry.token == "code-derived:"
		case arm64ControlAddressTokens:
			keep = entry.token != ""
		case arm64ControlNonFrameTokens:
			keep = !arm64ControlFrameToken(entry.token)
		}
		if keep {
			entries = append(entries, arm64ControlEntry{entry.token, true})
		}
	}
	return arm64ControlLeaf(node.hash, entries)
}

func arm64ControlUnionNodes(left, right *arm64ControlNode) *arm64ControlNode {
	if left == nil {
		return arm64ControlProject(right, arm64ControlAllTokens)
	}
	if right == nil || left == right {
		return arm64ControlProject(left, arm64ControlAllTokens)
	}
	if split := arm64ControlSplit(left.hash, right.hash); split > left.split && split > right.split {
		left, right = arm64ControlProject(left, arm64ControlAllTokens), arm64ControlProject(right, arm64ControlAllTokens)
		if left.hash&split == 0 {
			return arm64ControlBranch(split, left, right)
		}
		return arm64ControlBranch(split, right, left)
	}
	if left.split != 0 && left.split >= right.split {
		if left.split == right.split {
			return arm64ControlBranch(left.split, arm64ControlUnionNodes(left.left, right.left), arm64ControlUnionNodes(left.right, right.right))
		}
		if right.hash&left.split == 0 {
			return arm64ControlBranch(left.split, arm64ControlUnionNodes(left.left, right), arm64ControlProject(left.right, arm64ControlAllTokens))
		}
		return arm64ControlBranch(left.split, arm64ControlProject(left.left, arm64ControlAllTokens), arm64ControlUnionNodes(left.right, right))
	}
	if right.split != 0 {
		return arm64ControlUnionNodes(right, left)
	}
	root := arm64ControlProject(left, arm64ControlAllTokens)
	for _, entry := range right.entries {
		root = arm64ControlInsert(root, right.hash, entry.token, true)
	}
	return root
}

func arm64ControlUnion(left, right arm64ControlValue) arm64ControlValue {
	if arm64ControlCount(left) >= arm64ControlCount(right) && arm64ControlCanonical(left) && arm64ControlSubset(right, left) {
		return left
	}
	if arm64ControlCount(right) >= arm64ControlCount(left) && arm64ControlCanonical(right) && arm64ControlSubset(left, right) {
		return right
	}
	var a, b *arm64ControlNode
	if left != nil {
		a = left.root
	}
	if right != nil {
		b = right.root
	}
	root := arm64ControlUnionNodes(a, b)
	if root != nil && root.frames > 1 {
		root = arm64ControlProject(root, arm64ControlNonFrameTokens)
		root = arm64ControlInsert(root, arm64ControlHash(""), "", true)
	}
	return &arm64ControlSet{root: root}
}

func arm64ControlWithToken(value arm64ControlValue, token string) arm64ControlValue {
	if arm64ControlHas(value, token) {
		return value
	}
	var root *arm64ControlNode
	if value != nil {
		root = value.root
	}
	return &arm64ControlSet{root: arm64ControlInsert(root, arm64ControlHash(token), token, true)}
}

func arm64ControlSetToken(value arm64ControlValue, token string, present bool) arm64ControlValue {
	var root *arm64ControlNode
	if value != nil {
		root = value.root
	}
	return &arm64ControlSet{root: arm64ControlInsert(root, arm64ControlHash(token), token, present)}
}

func arm64ControlLabels(value arm64ControlValue) arm64ControlValue {
	if value == nil {
		return &arm64ControlSet{}
	}
	value.labelsOnce.Do(func() {
		value.labels = &arm64ControlSet{root: arm64ControlProject(value.root, arm64ControlLabelTokens)}
	})
	return value.labels
}

func arm64ControlAddressTaint(value arm64ControlValue) arm64ControlValue {
	if value == nil {
		return &arm64ControlSet{}
	}
	value.addressOnce.Do(func() {
		value.address = &arm64ControlSet{root: arm64ControlProject(value.root, arm64ControlAddressTokens)}
	})
	return value.address
}
